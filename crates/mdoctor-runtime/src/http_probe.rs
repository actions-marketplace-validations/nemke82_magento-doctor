//! Minimal async HTTP/1.1 client for status-page probes.
//!
//! Deliberately tiny: the services we probe (OpenSearch, Varnish, PHP-FPM status,
//! Nginx stub_status) all speak plain HTTP on an internal network. What matters is
//! that we read the *whole* response under one overall deadline and surface the
//! status code, so a slow or authenticated endpoint is reported as "probe failed"
//! rather than silently mistaken for an unhealthy service.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Hard ceiling on a response body, so a pathological endpoint cannot exhaust memory.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Why an HTTP probe did not produce a usable response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpProbeError {
    #[error("connection to {addr} failed: {reason}")]
    Connect { addr: String, reason: String },
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    #[error("connection closed before a complete response was received")]
    Incomplete,
    #[error("malformed HTTP response")]
    Malformed,
    #[error("i/o error: {0}")]
    Io(String),
}

/// A parsed HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    /// Header names are lowercased for case-insensitive lookup.
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl HttpResponse {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }

    /// True for a 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Options for a single probe.
#[derive(Debug, Clone)]
pub struct HttpProbeRequest<'a> {
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub method: &'a str,
    /// Extra request headers as `(name, value)`.
    pub headers: Vec<(String, String)>,
    /// `user:password` for HTTP Basic auth.
    pub basic_auth: Option<&'a str>,
    /// Overall deadline covering connect, write, and the full body read.
    pub timeout: Duration,
}

impl<'a> HttpProbeRequest<'a> {
    /// A GET request with a sensible default timeout.
    pub fn get(host: &'a str, port: u16, path: &'a str, timeout: Duration) -> Self {
        Self {
            host,
            port,
            path,
            method: "GET",
            headers: Vec::new(),
            basic_auth: None,
            timeout,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn with_basic_auth(mut self, credentials: Option<&'a str>) -> Self {
        self.basic_auth = credentials;
        self
    }
}

/// Performs one HTTP request and returns the complete response.
///
/// The supplied timeout is an overall deadline: unlike a per-read timeout, a server
/// that trickles bytes cannot be mistaken for one that closed the connection.
pub async fn http_probe(req: HttpProbeRequest<'_>) -> Result<HttpResponse, HttpProbeError> {
    let deadline = Instant::now() + req.timeout;
    let addr = if req.host.contains(':') {
        format!("[{}]:{}", req.host, req.port)
    } else {
        format!("{}:{}", req.host, req.port)
    };

    let mut stream = match tokio::time::timeout_at(deadline.into(), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(HttpProbeError::Connect {
                addr,
                reason: e.to_string(),
            })
        }
        Err(_) => return Err(HttpProbeError::Timeout(req.timeout)),
    };

    let mut request = format!("{} {} HTTP/1.1\r\n", req.method, req.path);
    let host_header = if req.host.contains(':') {
        format!("[{}]:{}", req.host, req.port)
    } else {
        format!("{}:{}", req.host, req.port)
    };
    request.push_str(&format!("Host: {}\r\n", host_header));
    request.push_str("User-Agent: mdoctor\r\n");
    request.push_str("Accept: */*\r\n");
    // Ask the server to close, so a body with neither Content-Length nor chunked
    // framing still terminates.
    request.push_str("Connection: close\r\n");
    if let Some(creds) = req.basic_auth {
        request.push_str(&format!("Authorization: Basic {}\r\n", base64_encode(creds.as_bytes())));
    }
    for (name, value) in &req.headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    request.push_str("\r\n");

    match tokio::time::timeout_at(deadline.into(), stream.write_all(request.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(HttpProbeError::Io(e.to_string())),
        Err(_) => return Err(HttpProbeError::Timeout(req.timeout)),
    }

    let mut raw = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout_at(deadline.into(), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_BODY_BYTES {
                    break;
                }
                // Stop as soon as the framing says the body is complete, rather than
                // waiting for a server that keeps the socket open anyway.
                if response_is_complete(&raw) {
                    break;
                }
            }
            Ok(Err(e)) => return Err(HttpProbeError::Io(e.to_string())),
            // A timeout with a complete response already buffered is still a success.
            Err(_) => {
                if response_is_complete(&raw) {
                    break;
                }
                return Err(HttpProbeError::Timeout(req.timeout));
            }
        }
    }

    parse_response(&raw)
}

/// Splits headers from body, returning the byte offset just past the blank line.
fn header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// True once the buffered bytes contain a complete response per its own framing.
fn response_is_complete(raw: &[u8]) -> bool {
    let Some(body_start) = header_end(raw) else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..body_start]);
    let headers = parse_headers(&head);

    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        // The terminating zero-length chunk ends the body.
        return raw[body_start..].windows(5).any(|w| w == b"0\r\n\r\n");
    }
    if let Some(len) = headers.get("content-length").and_then(|v| v.trim().parse::<usize>().ok()) {
        return raw.len() >= body_start + len;
    }
    false
}

/// Parses header lines out of a response head, lowercasing names.
fn parse_headers(head: &str) -> HashMap<String, String> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse, HttpProbeError> {
    if raw.is_empty() {
        return Err(HttpProbeError::Incomplete);
    }
    let body_start = header_end(raw).ok_or(HttpProbeError::Malformed)?;
    let head = String::from_utf8_lossy(&raw[..body_start]);

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(HttpProbeError::Malformed)?;

    let headers = parse_headers(&head);
    let raw_body = &raw[body_start..];

    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        decode_chunked(raw_body)
    } else {
        String::from_utf8_lossy(raw_body).to_string()
    };

    Ok(HttpResponse { status, headers, body })
}

/// Decodes an HTTP/1.1 chunked body, stopping at the terminating zero chunk.
///
/// OpenSearch and Nginx both use chunked framing for some status endpoints, so a
/// naive reader would hand JSON parsing a body still carrying chunk-size lines.
fn decode_chunked(mut raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());

    while let Some(line_end) = raw.windows(2).position(|w| w == b"\r\n") {
        let size_line = String::from_utf8_lossy(&raw[..line_end]);
        // A chunk-size line may carry trailing extensions after ';'.
        let size_token = size_line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_token, 16) else {
            break;
        };
        if size == 0 {
            break;
        }

        let chunk_start = line_end + 2;
        let chunk_end = chunk_start.saturating_add(size).min(raw.len());
        out.extend_from_slice(&raw[chunk_start..chunk_end]);

        // Skip the chunk and its trailing CRLF.
        let next = (chunk_end + 2).min(raw.len());
        raw = &raw[next..];
    }

    String::from_utf8_lossy(&out).to_string()
}

/// Standard base64, used only for the Authorization header.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);

    for group in input.chunks(3) {
        let b0 = group[0] as u32;
        let b1 = *group.get(1).unwrap_or(&0) as u32;
        let b2 = *group.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(TABLE[(triple >> 18) as usize & 0x3F] as char);
        out.push(TABLE[(triple >> 12) as usize & 0x3F] as char);
        out.push(if group.len() > 1 {
            TABLE[(triple >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if group.len() > 2 {
            TABLE[triple as usize & 0x3F] as char
        } else {
            '='
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response_with_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"status\":\"g\"}";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
        assert_eq!(resp.header("content-type"), Some("application/json"));
        assert_eq!(resp.header("Content-Type"), Some("application/json"), "lookup is case-insensitive");
        assert!(resp.body.starts_with("{\"status\""));
    }

    #[test]
    fn test_parse_response_surfaces_auth_failure() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 401);
        assert!(!resp.is_success(), "a secured endpoint must not look like a healthy one");
    }

    #[test]
    fn test_decode_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1a\r\n{\"cluster_name\":\"prod-os\"}\r\n0\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.body, "{\"cluster_name\":\"prod-os\"}");
        let parsed: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(parsed["cluster_name"], "prod-os");
    }

    #[test]
    fn test_response_is_complete_respects_framing() {
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort";
        assert!(!response_is_complete(partial));

        let full = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfull!";
        assert!(response_is_complete(full));

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfull!\r\n0\r\n\r\n";
        assert!(response_is_complete(chunked));
    }

    #[test]
    fn test_parse_response_rejects_garbage() {
        assert!(parse_response(b"").is_err());
        assert!(parse_response(b"not http at all").is_err());
        // Headers present but no status code.
        assert!(parse_response(b"GARBAGE\r\n\r\nbody").is_err());
    }

    #[test]
    fn test_base64_encode_matches_known_vectors() {
        assert_eq!(base64_encode(b"admin:admin"), "YWRtaW46YWRtaW4=");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[tokio::test]
    async fn test_probe_reports_connection_refused() {
        // Port 1 on loopback is reserved and never listening in CI.
        let err = http_probe(HttpProbeRequest::get("127.0.0.1", 1, "/", Duration::from_millis(500)))
            .await
            .unwrap_err();
        assert!(matches!(err, HttpProbeError::Connect { .. } | HttpProbeError::Timeout(_)));
    }

    #[tokio::test]
    async fn test_probe_reads_full_response_from_local_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut discard = [0u8; 1024];
            let _ = sock.read(&mut discard).await;
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nVia: 1.1 varnish (Varnish/7.4)\r\nContent-Length: 2\r\n\r\nhi",
            )
            .await
            .unwrap();
        });

        let resp = http_probe(HttpProbeRequest::get(
            "127.0.0.1",
            addr.port(),
            "/",
            Duration::from_secs(2),
        ))
        .await
        .unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "hi");
        assert!(resp.header("via").unwrap().contains("varnish"));
    }

    #[tokio::test]
    async fn test_probe_times_out_on_silent_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept but never reply: the old per-read logic treated this as a clean EOF.
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        });

        let err = http_probe(HttpProbeRequest::get(
            "127.0.0.1",
            addr.port(),
            "/",
            Duration::from_millis(300),
        ))
        .await
        .unwrap_err();

        assert!(matches!(err, HttpProbeError::Timeout(_)), "got {:?}", err);
    }
}
