//! Full Page Cache (FPC), Varnish, and layout puncture evaluation.

use std::time::Duration;

use mdoctor_core::{
    Endpoint, FpcEngine, FpcProbeStatus, HttpTarget, ProbeOutcome, SanitizedEnvConfig,
    UncacheableBlock, VarnishProbeResult,
};

use crate::http_probe::{http_probe, HttpProbeRequest};

/// Varnish's conventional listen port for a Magento install.
pub const DEFAULT_VARNISH_PORT: u16 = 6081;

/// Probes an endpoint over HTTP and reports whether it is really a Varnish tier.
///
/// An open TCP port proves nothing: on a Magento host, port 80 is nginx or Apache.
/// Varnish is identified only from response headers it actually emits — `Via:` (which
/// carries "varnish"), `X-Varnish`, or `Server: Varnish`.
pub async fn probe_varnish(endpoint: &Endpoint, timeout: Duration) -> VarnishProbeResult {
    let mut result = VarnishProbeResult {
        endpoint: Some(endpoint.to_string()),
        ..Default::default()
    };

    if endpoint.is_unix_socket {
        result.outcome = ProbeOutcome::failed("unix socket endpoints cannot be probed over HTTP");
        return result;
    }

    let request = HttpProbeRequest::get(&endpoint.host, endpoint.port, "/", timeout)
        .with_header("X-Magento-Cache-Debug", "1");

    match http_probe(request).await {
        Ok(resp) => {
            result.outcome = ProbeOutcome::Succeeded;
            result.http_status = Some(resp.status);
            result.via_header = resp.header("via").map(str::to_string);
            result.x_varnish_header = resp.header("x-varnish").map(str::to_string);
            result.age_header = resp.header("age").map(str::to_string);
            result.x_magento_cache_debug = resp.header("x-magento-cache-debug").map(str::to_string);
            result.server_header = resp.header("server").map(str::to_string);
            result.identified_as_varnish = identifies_varnish(
                result.via_header.as_deref(),
                result.x_varnish_header.as_deref(),
                result.server_header.as_deref(),
            );
        }
        Err(e) => result.outcome = ProbeOutcome::failed(e.to_string()),
    }

    result
}

/// Probes the storefront URL instead of a Varnish port directly.
///
/// On a cluster the operator may only be able to reach the public storefront; its
/// response headers still reveal whether a Varnish tier fronts the store.
pub async fn probe_storefront_cache(target: &HttpTarget, timeout: Duration) -> VarnishProbeResult {
    let mut result = VarnishProbeResult {
        endpoint: Some(target.to_string()),
        ..Default::default()
    };

    let request = HttpProbeRequest::get(&target.host, target.port, &target.path, timeout)
        .with_header("X-Magento-Cache-Debug", "1");

    match http_probe(request).await {
        Ok(resp) => {
            result.outcome = ProbeOutcome::Succeeded;
            result.http_status = Some(resp.status);
            result.via_header = resp.header("via").map(str::to_string);
            result.x_varnish_header = resp.header("x-varnish").map(str::to_string);
            result.age_header = resp.header("age").map(str::to_string);
            result.x_magento_cache_debug = resp.header("x-magento-cache-debug").map(str::to_string);
            result.server_header = resp.header("server").map(str::to_string);
            result.identified_as_varnish = identifies_varnish(
                result.via_header.as_deref(),
                result.x_varnish_header.as_deref(),
                result.server_header.as_deref(),
            );
        }
        Err(e) => result.outcome = ProbeOutcome::failed(e.to_string()),
    }

    result
}

/// True when a response header positively names Varnish.
fn identifies_varnish(via: Option<&str>, x_varnish: Option<&str>, server: Option<&str>) -> bool {
    // X-Varnish is set by Varnish on every response and by nothing else.
    if x_varnish.is_some_and(|v| !v.trim().is_empty()) {
        return true;
    }
    let names_varnish = |h: Option<&str>| h.is_some_and(|v| v.to_ascii_lowercase().contains("varnish"));
    names_varnish(via) || names_varnish(server)
}

/// Evaluates FPC configuration and layout punctures.
///
/// "Configured" comes from env.php `http_cache_hosts`; "reachable" comes from a probe
/// that identified Varnish. They are reported separately because a store configured
/// for Varnish with an unreachable tier and a store on built-in FPC with Varnish
/// running next to it are different problems.
pub fn evaluate_fpc(
    env_config: &SanitizedEnvConfig,
    uncacheable_blocks: Vec<UncacheableBlock>,
    varnish_probe: VarnishProbeResult,
) -> FpcProbeStatus {
    let is_varnish_configured = !env_config.http_cache_hosts.is_empty();
    let is_varnish_reachable = varnish_probe.identified_as_varnish;

    // Prefer what the store is configured to use; a reachable Varnish only decides
    // the engine when env.php says nothing either way.
    let engine = if is_varnish_configured || is_varnish_reachable {
        FpcEngine::Varnish
    } else if env_config.redis_page_cache_host.is_some() {
        FpcEngine::BuiltIn
    } else {
        FpcEngine::Unknown
    };

    let (varnish_host, varnish_port) = match &varnish_probe.endpoint {
        Some(ep) => match Endpoint::parse(ep, DEFAULT_VARNISH_PORT) {
            Ok(parsed) => (Some(parsed.host), Some(parsed.port)),
            Err(_) => (None, None),
        },
        None => (None, None),
    };

    FpcProbeStatus {
        engine,
        is_varnish_configured,
        is_varnish_reachable,
        varnish_host,
        varnish_port,
        varnish_probe,
        uncacheable_blocks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_fpc_builtin_redis() {
        let env = SanitizedEnvConfig {
            redis_page_cache_host: Some("127.0.0.1:6379".to_string()),
            ..Default::default()
        };

        let status = evaluate_fpc(&env, Vec::new(), VarnishProbeResult::default());
        assert_eq!(status.engine, FpcEngine::BuiltIn);
        assert!(!status.is_varnish_reachable);
        assert!(!status.is_varnish_configured);
    }

    #[test]
    fn test_varnish_configured_comes_from_env_not_from_probe() {
        let env = SanitizedEnvConfig {
            http_cache_hosts: vec!["varnish-1.internal:6081".to_string()],
            ..Default::default()
        };

        // Configured for Varnish, but the tier did not answer.
        let status = evaluate_fpc(
            &env,
            Vec::new(),
            VarnishProbeResult {
                outcome: ProbeOutcome::failed("connection refused"),
                ..Default::default()
            },
        );

        assert!(status.is_varnish_configured, "env.php http_cache_hosts means configured");
        assert!(!status.is_varnish_reachable, "a failed probe is not reachable");
        assert_eq!(status.engine, FpcEngine::Varnish);
    }

    #[test]
    fn test_plain_web_server_is_not_reported_as_varnish() {
        // The old probe treated any accepted TCP connection as Varnish. A 200 from
        // nginx with no Varnish headers must not identify as Varnish.
        let probe = VarnishProbeResult {
            endpoint: Some("127.0.0.1:80".to_string()),
            outcome: ProbeOutcome::Succeeded,
            http_status: Some(200),
            server_header: Some("nginx/1.24.0".to_string()),
            identified_as_varnish: identifies_varnish(None, None, Some("nginx/1.24.0")),
            ..Default::default()
        };

        assert!(!probe.identified_as_varnish);

        let status = evaluate_fpc(&SanitizedEnvConfig::default(), Vec::new(), probe);
        assert!(!status.is_varnish_reachable);
        assert!(!status.is_varnish_configured);
        assert_eq!(status.engine, FpcEngine::Unknown);
    }

    #[test]
    fn test_identifies_varnish_from_headers() {
        assert!(identifies_varnish(Some("1.1 varnish (Varnish/7.4)"), None, None));
        assert!(identifies_varnish(None, Some("12345 67890"), None));
        assert!(identifies_varnish(None, None, Some("Varnish")));

        assert!(!identifies_varnish(None, None, Some("nginx/1.24.0")));
        assert!(!identifies_varnish(Some("1.1 squid"), None, Some("Apache/2.4")));
        assert!(!identifies_varnish(None, Some("   "), None), "blank X-Varnish proves nothing");
        assert!(!identifies_varnish(None, None, None));
    }

    #[tokio::test]
    async fn test_probe_varnish_reads_headers_from_real_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut discard = [0u8; 1024];
            let _ = sock.read(&mut discard).await;
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nVia: 1.1 varnish (Varnish/7.4)\r\nX-Varnish: 98765\r\nAge: 42\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        });

        let endpoint = Endpoint::parse(&format!("127.0.0.1:{}", port), DEFAULT_VARNISH_PORT).unwrap();
        let probe = probe_varnish(&endpoint, Duration::from_secs(2)).await;

        assert!(probe.outcome.is_success());
        assert!(probe.identified_as_varnish);
        assert_eq!(probe.age_header.as_deref(), Some("42"));
        assert_eq!(probe.x_varnish_header.as_deref(), Some("98765"));
    }

    #[tokio::test]
    async fn test_probe_varnish_on_silent_tcp_port_does_not_identify() {
        // A socket that accepts but speaks no HTTP: exactly the case the old
        // TcpStream::connect probe mistook for a live Varnish.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        });

        let endpoint = Endpoint::parse(&format!("127.0.0.1:{}", port), DEFAULT_VARNISH_PORT).unwrap();
        let probe = probe_varnish(&endpoint, Duration::from_millis(300)).await;

        assert!(!probe.identified_as_varnish);
        assert!(matches!(probe.outcome, ProbeOutcome::Failed { .. }));
    }
}
