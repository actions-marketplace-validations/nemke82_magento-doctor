//! Full Page Cache (FPC), Varnish, and layout puncture evaluation.

use std::time::Duration;
use tokio::net::TcpStream;
use mdoctor_core::{FpcEngine, FpcProbeStatus, SanitizedEnvConfig, UncacheableBlock};

/// Probes whether a Varnish reverse proxy daemon is active and accepting connections.
pub async fn probe_varnish(host: &str, port: u16, timeout_secs: u64) -> bool {
    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_secs(timeout_secs.clamp(1, 3));

    tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Evaluates FPC configuration and layout punctures.
pub fn evaluate_fpc(
    env_config: &SanitizedEnvConfig,
    uncacheable_blocks: Vec<UncacheableBlock>,
    is_varnish_live: bool,
) -> FpcProbeStatus {
    let mut engine = FpcEngine::Unknown;

    if is_varnish_live {
        engine = FpcEngine::Varnish;
    } else if env_config.redis_page_cache_host.is_some() {
        engine = FpcEngine::BuiltIn;
    }

    FpcProbeStatus {
        engine,
        is_varnish_configured: is_varnish_live,
        is_varnish_reachable: is_varnish_live,
        varnish_host: None,
        varnish_port: None,
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

        let status = evaluate_fpc(&env, Vec::new(), false);
        assert_eq!(status.engine, FpcEngine::BuiltIn);
        assert!(!status.is_varnish_reachable);
    }
}
