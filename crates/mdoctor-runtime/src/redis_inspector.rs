//! Live Redis and Valkey deep internals probe using lightweight RESP protocol.

use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use mdoctor_core::RedisStatus;

/// Connects to a live Redis or Valkey server and collects memory, fragmentation, eviction, and hit metrics.
pub async fn inspect_redis(
    host: &str,
    port: u16,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<RedisStatus, Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_secs(timeout_secs.clamp(1, 5));

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await??;

    // 1. Authenticate if password provided
    if let Some(pass) = password {
        if !pass.trim().is_empty() {
            let auth_cmd = format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n", pass.len(), pass);
            tokio::time::timeout(timeout, stream.write_all(auth_cmd.as_bytes())).await??;

            let mut auth_buf = [0u8; 128];
            let n = tokio::time::timeout(timeout, stream.read(&mut auth_buf)).await??;
            let resp = String::from_utf8_lossy(&auth_buf[..n]);
            if !resp.starts_with("+OK") {
                return Err(format!("Redis AUTH failed: {}", resp.trim()).into());
            }
        }
    }

    // 2. Request INFO
    let info_cmd = "*1\r\n$4\r\nINFO\r\n";
    tokio::time::timeout(timeout, stream.write_all(info_cmd.as_bytes())).await??;

    let mut response_buf = Vec::with_capacity(8192);
    let mut temp = [0u8; 2048];
    loop {
        match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut temp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                response_buf.extend_from_slice(&temp[..n]);
                if response_buf.len() > 65536 {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }

    let info_str = String::from_utf8_lossy(&response_buf);
    let mut status = parse_redis_info(&info_str);
    status.is_configured = true;
    status.is_reachable = true;

    Ok(status)
}

/// Parses raw Redis INFO output into a structured RedisStatus model.
pub fn parse_redis_info(info: &str) -> RedisStatus {
    let mut map = HashMap::new();

    for line in info.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    let version = map.get("redis_version").cloned();
    let used_memory_bytes = map.get("used_memory").and_then(|v| v.parse().ok());
    let used_memory_peak_bytes = map.get("used_memory_peak").and_then(|v| v.parse().ok());
    let maxmemory_bytes = map.get("maxmemory").and_then(|v| v.parse().ok());
    let maxmemory_policy = map.get("maxmemory_policy").cloned();
    let mem_fragmentation_ratio = map.get("mem_fragmentation_ratio").and_then(|v| v.parse().ok());
    let evicted_keys = map.get("evicted_keys").and_then(|v| v.parse().ok());
    let connected_clients = map.get("connected_clients").and_then(|v| v.parse().ok());
    let blocked_clients = map.get("blocked_clients").and_then(|v| v.parse().ok());
    let keyspace_hits = map.get("keyspace_hits").and_then(|v| v.parse().ok());
    let keyspace_misses = map.get("keyspace_misses").and_then(|v| v.parse().ok());
    let ops_per_sec = map.get("instantaneous_ops_per_sec").and_then(|v| v.parse().ok());

    let hit_ratio = match (keyspace_hits, keyspace_misses) {
        (Some(h), Some(m)) if (h + m) > 0 => Some((h as f64) / ((h + m) as f64)),
        _ => None,
    };

    RedisStatus {
        is_configured: true,
        is_reachable: true,
        version,
        used_memory_bytes,
        used_memory_peak_bytes,
        maxmemory_bytes,
        maxmemory_policy,
        mem_fragmentation_ratio,
        evicted_keys,
        connected_clients,
        blocked_clients,
        keyspace_hits,
        keyspace_misses,
        hit_ratio,
        ops_per_sec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_redis_info_sample() {
        let sample = r#"
# Server
redis_version:7.2.4
redis_mode:standalone

# Clients
connected_clients:42
blocked_clients:1

# Memory
used_memory:268435456
used_memory_peak:314572800
maxmemory:536870912
maxmemory_policy:volatile-lru
mem_fragmentation_ratio:1.45

# Stats
total_connections_received:12000
instantaneous_ops_per_sec:850
keyspace_hits:90000
keyspace_misses:10000
evicted_keys:15
"#;

        let status = parse_redis_info(sample);
        assert_eq!(status.version.as_deref(), Some("7.2.4"));
        assert_eq!(status.used_memory_bytes, Some(268435456));
        assert_eq!(status.maxmemory_bytes, Some(536870912));
        assert_eq!(status.maxmemory_policy.as_deref(), Some("volatile-lru"));
        assert_eq!(status.mem_fragmentation_ratio, Some(1.45));
        assert_eq!(status.evicted_keys, Some(15));
        assert_eq!(status.connected_clients, Some(42));
        assert_eq!(status.blocked_clients, Some(1));
        assert_eq!(status.ops_per_sec, Some(850));
        assert_eq!(status.hit_ratio, Some(0.9)); // 90000 / 100000
    }
}
