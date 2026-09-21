//! Nginx `stub_status` inspection, for correlating web-tier pressure with PHP-FPM.

use std::time::Duration;

use mdoctor_core::{HttpTarget, NginxStatus, ProbeOutcome};

use crate::http_probe::{http_probe, HttpProbeRequest};

/// Reads Nginx `stub_status` counters from a local or remote web node.
pub async fn inspect_nginx(status_url: &HttpTarget, timeout: Duration) -> NginxStatus {
    let request = HttpProbeRequest::get(&status_url.host, status_url.port, &status_url.path, timeout);

    match http_probe(request).await {
        Ok(resp) if resp.is_success() => {
            let mut status = parse_stub_status(&resp.body);
            status.endpoint = Some(status_url.to_string());
            if !status.is_detected {
                status.probe = ProbeOutcome::failed("response is not an Nginx stub_status page");
            }
            status
        }
        Ok(resp) => NginxStatus {
            endpoint: Some(status_url.to_string()),
            probe: ProbeOutcome::failed(format!("HTTP {}", resp.status)),
            ..Default::default()
        },
        Err(e) => NginxStatus {
            endpoint: Some(status_url.to_string()),
            probe: ProbeOutcome::failed(e.to_string()),
            ..Default::default()
        },
    }
}

/// Parses the seven counters emitted by `ngx_http_stub_status_module`.
pub fn parse_stub_status(body: &str) -> NginxStatus {
    let mut status = NginxStatus::default();

    for line in body.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("Active connections:") {
            status.active_connections = rest.trim().parse().ok();
            continue;
        }

        if trimmed.starts_with("Reading:") {
            // "Reading: 0 Writing: 3 Waiting: 117"
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            for pair in tokens.chunks(2) {
                let (Some(label), Some(value)) = (pair.first(), pair.get(1)) else {
                    continue;
                };
                let parsed = value.parse().ok();
                match label.trim_end_matches(':') {
                    "Reading" => status.reading = parsed,
                    "Writing" => status.writing = parsed,
                    "Waiting" => status.waiting = parsed,
                    _ => {}
                }
            }
            continue;
        }

        // The accepts/handled/requests triple sits on its own unlabelled line.
        let numbers: Vec<u64> = trimmed
            .split_whitespace()
            .filter_map(|t| t.parse::<u64>().ok())
            .collect();
        if numbers.len() == 3 && trimmed.chars().all(|c| c.is_ascii_digit() || c.is_whitespace()) {
            status.accepted = Some(numbers[0]);
            status.handled = Some(numbers[1]);
            status.requests = Some(numbers[2]);
        }
    }

    status.is_detected = status.active_connections.is_some() && status.requests.is_some();
    if status.is_detected {
        status.probe = ProbeOutcome::Succeeded;
        status.dropped = match (status.accepted, status.handled) {
            (Some(a), Some(h)) => Some(a.saturating_sub(h)),
            _ => None,
        };
    }

    status
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Active connections: 291
server accepts handled requests
 16630948 16630948 31070465
Reading: 6 Writing: 179 Waiting: 106
";

    #[test]
    fn test_parse_stub_status() {
        let status = parse_stub_status(SAMPLE);
        assert!(status.is_detected);
        assert_eq!(status.active_connections, Some(291));
        assert_eq!(status.accepted, Some(16630948));
        assert_eq!(status.handled, Some(16630948));
        assert_eq!(status.requests, Some(31070465));
        assert_eq!(status.reading, Some(6));
        assert_eq!(status.writing, Some(179));
        assert_eq!(status.waiting, Some(106));
        assert_eq!(status.dropped, Some(0));
    }

    #[test]
    fn test_parse_stub_status_detects_dropped_connections() {
        let status = parse_stub_status(
            "Active connections: 10\nserver accepts handled requests\n 500 490 1200\nReading: 0 Writing: 1 Waiting: 9\n",
        );
        assert_eq!(status.dropped, Some(10));
    }

    #[test]
    fn test_parse_stub_status_rejects_unrelated_body() {
        let status = parse_stub_status("<html><body>Welcome to nginx!</body></html>");
        assert!(!status.is_detected);
        assert_eq!(status.active_connections, None);
    }

    #[tokio::test]
    async fn test_inspect_nginx_over_http() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut discard = [0u8; 1024];
            let _ = sock.read(&mut discard).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                SAMPLE.len(),
                SAMPLE
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let target = HttpTarget::parse(&format!("http://127.0.0.1:{}/nginx_status", port), 80).unwrap();
        let status = inspect_nginx(&target, Duration::from_secs(2)).await;

        assert!(status.is_detected);
        assert!(status.probe.is_success());
        assert_eq!(status.active_connections, Some(291));
    }
}
