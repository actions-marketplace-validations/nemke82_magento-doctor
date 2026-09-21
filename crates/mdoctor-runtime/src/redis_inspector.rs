//! Live Redis and Valkey deep internals probe using lightweight RESP protocol.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mdoctor_core::{Endpoint, ProbeOutcome, RedisStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Default Redis/Valkey port.
pub const DEFAULT_REDIS_PORT: u16 = 6379;

/// Ceiling on an INFO reply, which is a few KB in practice.
const MAX_REPLY_BYTES: usize = 256 * 1024;

/// Connects to a live Redis or Valkey server and collects memory, fragmentation,
/// eviction, and hit metrics.
///
/// Returns a [`RedisStatus`] whose `probe` field explains any failure, so an
/// authenticated or unreachable instance is never mistaken for a healthy one.
pub async fn inspect_redis(
    endpoint: &Endpoint,
    password: Option<&str>,
    timeout: Duration,
) -> RedisStatus {
    let mut status = RedisStatus {
        is_configured: true,
        endpoint: Some(endpoint.to_string()),
        ..Default::default()
    };

    if endpoint.is_unix_socket {
        status.probe = ProbeOutcome::failed("unix socket endpoints are not supported over TCP");
        return status;
    }

    match probe_redis_inner(endpoint, password, timeout).await {
        Ok((info, config)) => {
            let mut parsed = parse_redis_info(&info);
            // CONFIG GET is authoritative for maxmemory-policy: INFO reflects the
            // running value, but a instance where CONFIG differs is worth trusting
            // from CONFIG, and on some builds INFO omits the field entirely.
            if let Some(policy) = config.get("maxmemory-policy") {
                parsed.maxmemory_policy = Some(policy.clone());
            }
            if let Some(max) = config.get("maxmemory").and_then(|v| v.parse::<u64>().ok()) {
                parsed.maxmemory_bytes = Some(max);
            }
            parsed.is_configured = true;
            parsed.is_reachable = true;
            parsed.endpoint = Some(endpoint.to_string());
            parsed.probe = ProbeOutcome::Succeeded;
            parsed
        }
        Err(reason) => {
            status.probe = ProbeOutcome::failed(reason);
            status
        }
    }
}

/// Runs AUTH, INFO and CONFIG GET against one instance under a single deadline.
async fn probe_redis_inner(
    endpoint: &Endpoint,
    password: Option<&str>,
    timeout: Duration,
) -> Result<(String, HashMap<String, String>), String> {
    let deadline = Instant::now() + timeout;
    let addr = if endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };

    let mut stream = match tokio::time::timeout_at(deadline.into(), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("connection to {} failed: {}", addr, e)),
        Err(_) => return Err(format!("connection to {} timed out", addr)),
    };

    if let Some(pass) = password.map(str::trim).filter(|p| !p.is_empty()) {
        let reply = redis_command(&mut stream, &["AUTH", pass], deadline).await?;
        if !reply.starts_with("+OK") {
            // Redis echoes no secret in its error, but be explicit rather than paste it.
            return Err("AUTH rejected: check the password supplied for this instance".to_string());
        }
    }

    let info_reply = redis_command(&mut stream, &["INFO"], deadline).await?;
    if info_reply.starts_with("-NOAUTH") || info_reply.starts_with("-ERR operation not permitted") {
        return Err("instance requires a password (pass --redis-password)".to_string());
    }
    if info_reply.starts_with('-') {
        return Err(format!("INFO rejected: {}", info_reply.trim().trim_start_matches('-')));
    }
    let info = strip_bulk_header(&info_reply);

    // CONFIG GET may be disabled or renamed on hardened instances; that is not fatal.
    let config = match redis_command(&mut stream, &["CONFIG", "GET", "maxmemory*"], deadline).await {
        Ok(reply) if !reply.starts_with('-') => parse_config_get(&reply),
        _ => HashMap::new(),
    };

    Ok((info, config))
}

/// Sends one command as a RESP array and reads the reply.
async fn redis_command(
    stream: &mut TcpStream,
    args: &[&str],
    deadline: Instant,
) -> Result<String, String> {
    let mut cmd = format!("*{}\r\n", args.len());
    for arg in args {
        cmd.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
    }

    match tokio::time::timeout_at(deadline.into(), stream.write_all(cmd.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("write failed: {}", e)),
        Err(_) => return Err("timed out sending command".to_string()),
    }

    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout_at(deadline.into(), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_REPLY_BYTES || resp_reply_is_complete(&buf) {
                    break;
                }
            }
            Ok(Err(e)) => return Err(format!("read failed: {}", e)),
            Err(_) => {
                if resp_reply_is_complete(&buf) {
                    break;
                }
                return Err("timed out reading reply".to_string());
            }
        }
    }

    if buf.is_empty() {
        return Err("no reply from server".to_string());
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// True once a buffered RESP reply is complete, so we stop reading promptly.
fn resp_reply_is_complete(buf: &[u8]) -> bool {
    let text = String::from_utf8_lossy(buf);
    match buf.first() {
        // Simple string, error and integer replies are one CRLF-terminated line.
        Some(b'+') | Some(b'-') | Some(b':') => text.contains("\r\n"),
        Some(b'$') => {
            let Some((header, rest)) = text.split_once("\r\n") else {
                return false;
            };
            match header[1..].parse::<i64>() {
                Ok(-1) => true,
                Ok(len) => rest.len() >= len as usize + 2,
                Err(_) => false,
            }
        }
        Some(b'*') => {
            // Count CRLF-terminated payload lines against the declared arity. Every
            // element of a CONFIG GET reply is a bulk string, i.e. two lines each.
            let Some((header, rest)) = text.split_once("\r\n") else {
                return false;
            };
            match header[1..].parse::<i64>() {
                Ok(n) if n <= 0 => true,
                Ok(n) => rest.matches("\r\n").count() >= (n as usize) * 2,
                Err(_) => false,
            }
        }
        _ => false,
    }
}

/// Strips the `$<len>\r\n` bulk-string header from an INFO reply.
fn strip_bulk_header(reply: &str) -> String {
    if let Some(rest) = reply.strip_prefix('$') {
        if let Some((_, body)) = rest.split_once("\r\n") {
            return body.to_string();
        }
    }
    reply.to_string()
}

/// Parses a RESP array reply from `CONFIG GET` into key/value pairs.
pub fn parse_config_get(reply: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // Skip the array header, then take alternating bulk-string payload lines.
    let payload: Vec<&str> = reply
        .split("\r\n")
        .skip(1)
        .filter(|line| !line.is_empty() && !line.starts_with('$'))
        .collect();

    for pair in payload.chunks(2) {
        if let (Some(k), Some(v)) = (pair.first(), pair.get(1)) {
            map.insert(k.to_string(), v.to_string());
        }
    }

    map
}

/// Reads and parses one INFO field.
fn info_field<T: std::str::FromStr>(map: &HashMap<String, String>, key: &str) -> Option<T> {
    map.get(key).and_then(|v| v.parse().ok())
}

/// Parses raw Redis INFO output into a structured RedisStatus model.
///
/// Reachability is *not* set here: a parse of arbitrary text says nothing about
/// whether a server answered. Callers that actually connected set it.
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

    let keyspace_hits: Option<u64> = info_field(&map, "keyspace_hits");
    let keyspace_misses: Option<u64> = info_field(&map, "keyspace_misses");
    let hit_ratio = match (keyspace_hits, keyspace_misses) {
        (Some(h), Some(m)) if (h + m) > 0 => Some((h as f64) / ((h + m) as f64)),
        _ => None,
    };

    RedisStatus {
        is_configured: false,
        is_reachable: false,
        endpoint: None,
        probe: ProbeOutcome::NotAttempted,
        version: map.get("redis_version").cloned(),
        used_memory_bytes: info_field(&map, "used_memory"),
        used_memory_peak_bytes: info_field(&map, "used_memory_peak"),
        maxmemory_bytes: info_field(&map, "maxmemory"),
        maxmemory_policy: map.get("maxmemory_policy").cloned(),
        mem_fragmentation_ratio: info_field(&map, "mem_fragmentation_ratio"),
        evicted_keys: info_field(&map, "evicted_keys"),
        connected_clients: info_field(&map, "connected_clients"),
        blocked_clients: info_field(&map, "blocked_clients"),
        keyspace_hits,
        keyspace_misses,
        hit_ratio,
        ops_per_sec: info_field(&map, "instantaneous_ops_per_sec"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_INFO: &str = r#"
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

    #[test]
    fn test_parse_redis_info_sample() {
        let status = parse_redis_info(SAMPLE_INFO);
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

    #[test]
    fn test_parse_redis_info_does_not_claim_reachability() {
        // Parsing text is not evidence that a server answered.
        let status = parse_redis_info("garbage without any colons");
        assert!(!status.is_reachable);
        assert!(!status.is_configured);
        assert_eq!(status.probe, ProbeOutcome::NotAttempted);
    }

    #[test]
    fn test_parse_config_get() {
        let reply = "*4\r\n$9\r\nmaxmemory\r\n$10\r\n2147483648\r\n$16\r\nmaxmemory-policy\r\n$12\r\nvolatile-lru\r\n";
        let config = parse_config_get(reply);
        assert_eq!(config.get("maxmemory").map(String::as_str), Some("2147483648"));
        assert_eq!(config.get("maxmemory-policy").map(String::as_str), Some("volatile-lru"));
    }

    #[test]
    fn test_strip_bulk_header() {
        assert_eq!(strip_bulk_header("$12\r\nhello world\r\n"), "hello world\r\n");
        assert_eq!(strip_bulk_header("+OK\r\n"), "+OK\r\n");
    }

    #[test]
    fn test_resp_reply_is_complete() {
        assert!(resp_reply_is_complete(b"+OK\r\n"));
        assert!(resp_reply_is_complete(b"-NOAUTH Authentication required.\r\n"));
        assert!(!resp_reply_is_complete(b"+OK"));
        assert!(resp_reply_is_complete(b"$5\r\nhello\r\n"));
        assert!(!resp_reply_is_complete(b"$50\r\nhello\r\n"));
        assert!(resp_reply_is_complete(b"*2\r\n$1\r\na\r\n$1\r\nb\r\n"));
        assert!(!resp_reply_is_complete(b"*2\r\n$1\r\na\r\n"));
    }

    #[tokio::test]
    async fn test_inspect_redis_authenticates_and_reads_info() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];

            // AUTH
            let n = sock.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains("AUTH"));
            sock.write_all(b"+OK\r\n").await.unwrap();

            // INFO
            let n = sock.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains("INFO"));
            let payload = SAMPLE_INFO.replace('\n', "\r\n");
            sock.write_all(format!("${}\r\n{}\r\n", payload.len(), payload).as_bytes())
                .await
                .unwrap();

            // CONFIG GET maxmemory*
            let n = sock.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains("CONFIG"));
            sock.write_all(
                b"*4\r\n$9\r\nmaxmemory\r\n$10\r\n2147483648\r\n$16\r\nmaxmemory-policy\r\n$11\r\nallkeys-lru\r\n",
            )
            .await
            .unwrap();
        });

        let endpoint = Endpoint::parse(&format!("127.0.0.1:{}", port), DEFAULT_REDIS_PORT).unwrap();
        let status = inspect_redis(&endpoint, Some("hunter2"), Duration::from_secs(3)).await;

        assert!(status.is_reachable, "probe failed: {}", status.probe);
        assert!(status.probe.is_success());
        assert_eq!(status.version.as_deref(), Some("7.2.4"));
        assert_eq!(
            status.maxmemory_policy.as_deref(),
            Some("allkeys-lru"),
            "CONFIG GET must win over INFO"
        );
        assert_eq!(status.maxmemory_bytes, Some(2147483648));
        assert_eq!(status.endpoint.as_deref(), Some(format!("127.0.0.1:{}", port).as_str()));
    }

    #[tokio::test]
    async fn test_inspect_redis_reports_missing_password() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            sock.write_all(b"-NOAUTH Authentication required.\r\n").await.unwrap();
        });

        let endpoint = Endpoint::parse(&format!("127.0.0.1:{}", port), DEFAULT_REDIS_PORT).unwrap();
        let status = inspect_redis(&endpoint, None, Duration::from_secs(2)).await;

        assert!(!status.is_reachable);
        match status.probe {
            ProbeOutcome::Failed { ref reason } => {
                assert!(reason.contains("password"), "unhelpful reason: {}", reason)
            }
            other => panic!("expected a failure, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_inspect_redis_reports_rejected_password() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            sock.write_all(b"-WRONGPASS invalid username-password pair\r\n").await.unwrap();
        });

        let endpoint = Endpoint::parse(&format!("127.0.0.1:{}", port), DEFAULT_REDIS_PORT).unwrap();
        let status = inspect_redis(&endpoint, Some("wrong"), Duration::from_secs(2)).await;

        assert!(!status.is_reachable);
        let ProbeOutcome::Failed { reason } = status.probe else {
            panic!("expected failure");
        };
        assert!(!reason.contains("wrong"), "the password must not be echoed back: {}", reason);
    }

    #[tokio::test]
    async fn test_inspect_redis_unreachable() {
        let endpoint = Endpoint::parse("127.0.0.1:1", DEFAULT_REDIS_PORT).unwrap();
        let status = inspect_redis(&endpoint, None, Duration::from_millis(400)).await;

        assert!(!status.is_reachable);
        assert!(status.is_configured, "we knew where to look, so it is configured");
        assert!(status.probe.is_inconclusive());
    }
}
