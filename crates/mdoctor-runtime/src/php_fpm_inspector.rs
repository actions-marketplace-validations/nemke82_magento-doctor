//! PHP-FPM pool status, worker pressure, and memory sizing forensics.
//!
//! Three sources, in descending order of trust:
//!
//! 1. **FPM status page** (`pm.status_path`) — the only source with a true active
//!    worker count, listen queue depth and `max children reached` counter. Works
//!    against a remote node, which is what a clustered or jump-host run needs.
//! 2. **`/proc` scan** — counts worker processes and measures real RSS, but its
//!    "active" figure undercounts: a worker blocked on MySQL or an outbound HTTP call
//!    is sleeping, not running, and that is exactly the saturation worth alerting on.
//! 3. **Pool config only** — sizing limits with no live data.
//!
//! Nothing is invented. When a value was not measured it stays `None`, and the
//! [`WorkerMetricSource`] travels with the metrics so rules can refuse to alert on
//! numbers that cannot support the alert.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mdoctor_core::{HttpTarget, PhpWorkerMetrics, WorkerMetricSource};

use crate::http_probe::{http_probe, HttpProbeRequest};

/// Documented average Magento 2 worker footprint, used only when real RSS is
/// unavailable and always reported as an estimate.
const ESTIMATED_WORKER_MEMORY_MB: f64 = 150.0;

/// Common standard Linux PHP-FPM pool locations.
const POOL_CONF_CANDIDATES: &[&str] = &[
    "/etc/php/8.4/fpm/pool.d/www.conf",
    "/etc/php/8.3/fpm/pool.d/www.conf",
    "/etc/php/8.2/fpm/pool.d/www.conf",
    "/etc/php/8.1/fpm/pool.d/www.conf",
    "/etc/php-fpm.d/www.conf",
    "/usr/local/etc/php-fpm.d/www.conf",
    "/opt/remi/php83/root/etc/php-fpm.d/www.conf",
];

/// Inspects PHP-FPM from a remote status page, falling back to local discovery.
///
/// `status_url` should point at a pool's `pm.status_path`; `?json` is appended when
/// the caller did not ask for a specific format.
pub async fn inspect_php_fpm_remote(
    status_url: &HttpTarget,
    timeout: Duration,
) -> PhpWorkerMetrics {
    let path = if status_url.path.contains("json") {
        status_url.path.clone()
    } else if status_url.path.contains('?') {
        format!("{}&json", status_url.path)
    } else {
        format!("{}?json", status_url.path)
    };

    let request = HttpProbeRequest::get(&status_url.host, status_url.port, &path, timeout);
    match http_probe(request).await {
        Ok(resp) if resp.is_success() => {
            let mut metrics = parse_fpm_status(&resp.body);
            metrics.origin = Some(status_url.to_string());
            if !metrics.is_detected {
                // A 200 that we could not parse is a misconfigured status path, not a
                // healthy pool: leave it undetected rather than invent numbers.
                metrics.origin = Some(format!("{} (unparseable status response)", status_url));
            }
            metrics
        }
        Ok(resp) => PhpWorkerMetrics {
            origin: Some(format!("{} (HTTP {})", status_url, resp.status)),
            ..Default::default()
        },
        Err(e) => PhpWorkerMetrics {
            origin: Some(format!("{} ({})", status_url, e)),
            ..Default::default()
        },
    }
}

/// Inspects PHP-FPM on the local host from pool config plus a `/proc` scan.
pub fn inspect_php_fpm(custom_conf: Option<&Path>) -> PhpWorkerMetrics {
    let discovered = discover_fpm_conf(custom_conf);
    let conf_map = discovered
        .as_ref()
        .map(|(_, map)| map.clone())
        .unwrap_or_default();

    let max_children = conf_map
        .get("pm.max_children")
        .and_then(|v| v.parse::<usize>().ok());
    let process_manager = conf_map.get("pm").cloned();
    let pool_name = discovered
        .as_ref()
        .and_then(|(path, _)| path.file_stem().map(|s| s.to_string_lossy().to_string()));

    let scan = scan_php_fpm_processes();
    let host_total_memory_mb = read_host_total_memory_mb();

    // PHP-FPM is "detected" only on real evidence: a pool config on disk or a live
    // worker process. A default max_children is not evidence.
    let source = if scan.workers > 0 {
        WorkerMetricSource::ProcScan
    } else if discovered.is_some() {
        WorkerMetricSource::ConfigOnly
    } else {
        WorkerMetricSource::NotDetected
    };

    if source == WorkerMetricSource::NotDetected {
        return PhpWorkerMetrics::default();
    }

    let (worker_memory_mb, worker_memory_measured) = match scan.average_rss_mb() {
        Some(measured) => (Some(measured), true),
        None => (Some(ESTIMATED_WORKER_MEMORY_MB), false),
    };

    let total_pool_memory_mb = match (max_children, worker_memory_mb) {
        (Some(mc), Some(mem)) => Some(mc as f64 * mem),
        _ => None,
    };

    // OOM risk needs a configured ceiling and a real host memory figure; guessing
    // either one produces a critical alert out of thin air.
    let oom_risk = match (total_pool_memory_mb, host_total_memory_mb) {
        (Some(pool), Some(host)) if host > 0.0 => pool > host * 0.80,
        _ => false,
    };

    // Saturation from a /proc scan is reported for context but flagged approximate by
    // `source`; rules must not alert on it.
    let saturation_pct = match (scan.running, max_children) {
        (running, Some(mc)) if mc > 0 => Some((running as f64 / mc as f64) * 100.0),
        _ => None,
    };

    PhpWorkerMetrics {
        is_detected: true,
        source,
        origin: discovered
            .as_ref()
            .map(|(path, _)| path.display().to_string())
            .or_else(|| Some("/proc scan".to_string())),
        pool_name,
        process_manager,
        active_workers: (scan.workers > 0).then_some(scan.running),
        idle_workers: (scan.workers > 0).then(|| scan.workers.saturating_sub(scan.running)),
        total_workers: (scan.workers > 0).then_some(scan.workers),
        max_children,
        listen_queue: None,
        listen_queue_len: None,
        max_children_reached: None,
        slow_requests: None,
        saturation_pct,
        worker_memory_mb,
        worker_memory_measured,
        total_pool_memory_mb,
        host_total_memory_mb,
        oom_risk,
    }
}

/// Parses a PHP-FPM status page, in either `?json` or plain-text format.
pub fn parse_fpm_status(body: &str) -> PhpWorkerMetrics {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            return metrics_from_status_fields(&json_status_fields(&v));
        }
    }
    metrics_from_status_fields(&text_status_fields(body))
}

/// PHP-FPM's JSON status uses the same key names as its text form, hyphenated.
fn json_status_fields(v: &serde_json::Value) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            let value = match val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                _ => continue,
            };
            fields.insert(k.to_ascii_lowercase(), value);
        }
    }
    fields
}

fn text_status_fields(body: &str) -> HashMap<String, String> {
    body.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

fn metrics_from_status_fields(fields: &HashMap<String, String>) -> PhpWorkerMetrics {
    let num = |key: &str| -> Option<u64> { fields.get(key).and_then(|v| v.trim().parse().ok()) };
    let size = |key: &str| -> Option<usize> { num(key).map(|n| n as usize) };

    let active = size("active processes");
    let idle = size("idle processes");
    let total = size("total processes").or_else(|| match (active, idle) {
        (Some(a), Some(i)) => Some(a + i),
        _ => None,
    });

    // A status body without an active-process count is not a status page.
    if active.is_none() && total.is_none() {
        return PhpWorkerMetrics::default();
    }

    // FPM reports the configured ceiling as "max active processes" (high-water mark)
    // and, for dynamic pools, "max children reached". The true ceiling comes from
    // pm.max_children, which the status page does not expose; the high-water mark is
    // the closest honest stand-in, so prefer it only when nothing better exists.
    let max_children = size("max children").or_else(|| size("max active processes"));

    let saturation_pct = match (active, max_children) {
        (Some(a), Some(mc)) if mc > 0 => Some((a as f64 / mc as f64) * 100.0),
        _ => None,
    };

    PhpWorkerMetrics {
        is_detected: true,
        source: WorkerMetricSource::FpmStatus,
        origin: None,
        pool_name: fields.get("pool").cloned(),
        process_manager: fields.get("process manager").cloned(),
        active_workers: active,
        idle_workers: idle,
        total_workers: total,
        max_children,
        listen_queue: size("listen queue"),
        listen_queue_len: size("listen queue len"),
        max_children_reached: num("max children reached"),
        slow_requests: num("slow requests"),
        saturation_pct,
        worker_memory_mb: None,
        worker_memory_measured: false,
        total_pool_memory_mb: None,
        host_total_memory_mb: None,
        oom_risk: false,
    }
}

/// Combines a status-page reading with local pool config and host memory.
///
/// The status page knows the live numbers; the pool config knows `pm.max_children`
/// and the host knows its RAM. When mdoctor can see both, merge them so saturation
/// and OOM risk are computed from real values on both sides.
pub fn merge_local_sizing(mut remote: PhpWorkerMetrics, local: &PhpWorkerMetrics) -> PhpWorkerMetrics {
    if !remote.is_detected {
        return remote;
    }

    if let Some(mc) = local.max_children {
        remote.max_children = Some(mc);
        if let Some(active) = remote.active_workers {
            if mc > 0 {
                remote.saturation_pct = Some((active as f64 / mc as f64) * 100.0);
            }
        }
    }
    if remote.process_manager.is_none() {
        remote.process_manager = local.process_manager.clone();
    }
    if remote.worker_memory_mb.is_none() {
        remote.worker_memory_mb = local.worker_memory_mb;
        remote.worker_memory_measured = local.worker_memory_measured;
    }
    remote.host_total_memory_mb = local.host_total_memory_mb;

    remote.total_pool_memory_mb = match (remote.max_children, remote.worker_memory_mb) {
        (Some(mc), Some(mem)) => Some(mc as f64 * mem),
        _ => None,
    };
    remote.oom_risk = match (remote.total_pool_memory_mb, remote.host_total_memory_mb) {
        (Some(pool), Some(host)) if host > 0.0 => pool > host * 0.80,
        _ => false,
    };

    remote
}

/// Parses a PHP-FPM INI-style pool configuration file.
///
/// Only the first `[pool]` section is returned: merging every pool into one map
/// silently mixes `pm.max_children` values from unrelated pools.
pub fn parse_php_fpm_conf(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut seen_section = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            if seen_section {
                break;
            }
            seen_section = true;
            if let Some(name) = trimmed.trim_start_matches('[').split(']').next() {
                map.insert("pool".to_string(), name.trim().to_string());
            }
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            // Strip inline comments, or `pm.max_children = 50 ; peak` fails to parse.
            let value = v
                .split([';', '#'])
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string();
            map.insert(k.trim().to_string(), value);
        }
    }

    map
}

/// Finds a pool config, returning its path alongside the parsed values.
fn discover_fpm_conf(custom_path: Option<&Path>) -> Option<(PathBuf, HashMap<String, String>)> {
    if let Some(p) = custom_path {
        // An explicitly supplied path that cannot be read is worth failing on rather
        // than silently falling back to an unrelated pool.
        let content = std::fs::read_to_string(p).ok()?;
        return Some((p.to_path_buf(), parse_php_fpm_conf(&content)));
    }

    POOL_CONF_CANDIDATES.iter().find_map(|path| {
        std::fs::read_to_string(path)
            .ok()
            .map(|c| (PathBuf::from(path), parse_php_fpm_conf(&c)))
    })
}

/// What a `/proc` sweep found for php-fpm.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FpmProcessScan {
    /// Worker processes, excluding the master.
    pub workers: usize,
    /// Workers in R (running) or D (uninterruptible) state.
    pub running: usize,
    /// Summed worker RSS in KiB.
    pub total_rss_kb: u64,
}

impl FpmProcessScan {
    /// Mean worker RSS in MB, when any worker was seen.
    pub fn average_rss_mb(&self) -> Option<f64> {
        if self.workers == 0 || self.total_rss_kb == 0 {
            return None;
        }
        Some((self.total_rss_kb as f64 / self.workers as f64) / 1024.0)
    }
}

/// Scans `/proc` for php-fpm workers, measuring real resident memory.
fn scan_php_fpm_processes() -> FpmProcessScan {
    let mut scan = FpmProcessScan::default();

    let Ok(entries) = std::fs::read_dir(Path::new("/proc")) else {
        return scan;
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str.is_empty() || !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let proc_path = entry.path();
        let Ok(comm) = std::fs::read_to_string(proc_path.join("comm")) else {
            continue;
        };
        if !comm.trim().contains("php-fpm") {
            continue;
        }

        // The master process is not a worker and must not inflate the pool count.
        // Its cmdline reads "php-fpm: master process (...)".
        if let Ok(cmdline) = std::fs::read_to_string(proc_path.join("cmdline")) {
            if cmdline.contains("master process") {
                continue;
            }
        }

        scan.workers += 1;

        if let Some(state) = read_proc_state(&proc_path) {
            // R = running, D = uninterruptible sleep (usually disk I/O).
            if state == 'R' || state == 'D' {
                scan.running += 1;
            }
        }
        if let Some(rss_kb) = read_proc_rss_kb(&proc_path) {
            scan.total_rss_kb += rss_kb;
        }
    }

    scan
}

/// Reads a process state letter from `/proc/<pid>/stat`.
///
/// The comm field is parenthesised and may itself contain spaces or brackets, so the
/// state is taken from just after the final ')' rather than by splitting on spaces.
fn read_proc_state(proc_path: &Path) -> Option<char> {
    let stat = std::fs::read_to_string(proc_path.join("stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_whitespace().next()?.chars().next()
}

/// Reads resident set size in KiB from `/proc/<pid>/statm`.
fn read_proc_rss_kb(proc_path: &Path) -> Option<u64> {
    let statm = std::fs::read_to_string(proc_path.join("statm")).ok()?;
    let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // statm counts pages; 4 KiB is the page size on every platform we target.
    Some(rss_pages * 4)
}

/// Reads MemTotal from `/proc/meminfo` in MB.
fn read_host_total_memory_mb() -> Option<f64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: f64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024.0);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_php_fpm_conf() {
        let conf = r#"
[www]
pm = dynamic
pm.max_children = 50
pm.start_servers = 10
pm.max_requests = 1000
"#;
        let map = parse_php_fpm_conf(conf);
        assert_eq!(map.get("pm").map(String::as_str), Some("dynamic"));
        assert_eq!(map.get("pm.max_children").map(String::as_str), Some("50"));
        assert_eq!(map.get("pool").map(String::as_str), Some("www"));
    }

    #[test]
    fn test_parse_php_fpm_conf_strips_inline_comments() {
        let map = parse_php_fpm_conf("[www]\npm.max_children = 50 ; sized for 8GB\n");
        assert_eq!(map.get("pm.max_children").map(String::as_str), Some("50"));
    }

    #[test]
    fn test_parse_php_fpm_conf_stops_at_second_pool() {
        // Merging pools would let an admin pool's limits masquerade as the web pool's.
        let conf = "[www]\npm.max_children = 50\n\n[admin]\npm.max_children = 5\n";
        let map = parse_php_fpm_conf(conf);
        assert_eq!(map.get("pm.max_children").map(String::as_str), Some("50"));
        assert_eq!(map.get("pool").map(String::as_str), Some("www"));
    }

    #[test]
    fn test_no_fpm_anywhere_reports_not_detected() {
        // The previous implementation defaulted max_children to 20 and so always
        // reported a pool, inventing a whole PHP-FPM install on hosts without one.
        let metrics = inspect_php_fpm(Some(Path::new("/nonexistent/mdoctor-test/www.conf")));

        if metrics.is_detected {
            // CI hosts may genuinely run php-fpm; then it must come from real evidence.
            assert_ne!(metrics.source, WorkerMetricSource::NotDetected);
            assert!(metrics.total_workers.is_some_and(|w| w > 0) || metrics.max_children.is_some());
        } else {
            assert_eq!(metrics.source, WorkerMetricSource::NotDetected);
            assert_eq!(metrics.max_children, None, "no config means no ceiling");
            assert_eq!(metrics.pool_name, None);
            assert!(!metrics.oom_risk, "OOM risk cannot be asserted without real inputs");
            assert_eq!(metrics.total_pool_memory_mb, None);
        }
    }

    #[test]
    fn test_parse_fpm_status_text() {
        let body = "pool:                 www
process manager:      dynamic
start time:           01/Jan/2026:00:00:00 +0000
accepted conn:        120451
listen queue:         7
max listen queue:     31
listen queue len:     128
idle processes:       2
active processes:     48
total processes:      50
max active processes: 50
max children reached: 4
slow requests:        12
";
        let m = parse_fpm_status(body);
        assert!(m.is_detected);
        assert_eq!(m.source, WorkerMetricSource::FpmStatus);
        assert_eq!(m.pool_name.as_deref(), Some("www"));
        assert_eq!(m.active_workers, Some(48));
        assert_eq!(m.idle_workers, Some(2));
        assert_eq!(m.total_workers, Some(50));
        assert_eq!(m.listen_queue, Some(7));
        assert_eq!(m.listen_queue_len, Some(128));
        assert_eq!(m.max_children_reached, Some(4));
        assert_eq!(m.slow_requests, Some(12));
        assert!(m.source.has_reliable_saturation());
    }

    #[test]
    fn test_parse_fpm_status_json() {
        let body = r#"{"pool":"www","process manager":"dynamic","listen queue":3,
            "idle processes":5,"active processes":45,"total processes":50,
            "max active processes":50,"max children reached":2,"slow requests":0}"#;
        let m = parse_fpm_status(body);
        assert_eq!(m.source, WorkerMetricSource::FpmStatus);
        assert_eq!(m.active_workers, Some(45));
        assert_eq!(m.listen_queue, Some(3));
        assert_eq!(m.saturation_pct, Some(90.0));
    }

    #[test]
    fn test_parse_fpm_status_rejects_unrelated_body() {
        // A 200 from the storefront instead of the status path must not be believed.
        let m = parse_fpm_status("<html><body>Welcome to nginx!</body></html>");
        assert!(!m.is_detected);
        assert_eq!(m.source, WorkerMetricSource::NotDetected);
    }

    #[test]
    fn test_merge_local_sizing_uses_real_max_children_and_ram() {
        let remote = parse_fpm_status("active processes: 40\nidle processes: 0\ntotal processes: 40\n");
        let local = PhpWorkerMetrics {
            is_detected: true,
            source: WorkerMetricSource::ConfigOnly,
            max_children: Some(100),
            worker_memory_mb: Some(160.0),
            worker_memory_measured: true,
            host_total_memory_mb: Some(8192.0),
            ..Default::default()
        };

        let merged = merge_local_sizing(remote, &local);
        assert_eq!(merged.max_children, Some(100));
        assert_eq!(merged.saturation_pct, Some(40.0));
        assert_eq!(merged.total_pool_memory_mb, Some(16000.0));
        assert!(merged.oom_risk, "16GB pool on an 8GB host is a real OOM risk");
        assert!(merged.worker_memory_measured);
    }

    #[test]
    fn test_merge_local_sizing_without_host_memory_makes_no_oom_claim() {
        let remote = parse_fpm_status("active processes: 10\ntotal processes: 10\n");
        let local = PhpWorkerMetrics {
            is_detected: true,
            max_children: Some(500),
            worker_memory_mb: Some(150.0),
            host_total_memory_mb: None,
            ..Default::default()
        };

        let merged = merge_local_sizing(remote, &local);
        assert!(!merged.oom_risk, "no host RAM figure means no OOM verdict");
    }

    #[test]
    fn test_process_scan_average_rss() {
        let scan = FpmProcessScan { workers: 4, running: 1, total_rss_kb: 4 * 160 * 1024 };
        assert_eq!(scan.average_rss_mb(), Some(160.0));

        assert_eq!(FpmProcessScan::default().average_rss_mb(), None);
    }

    #[tokio::test]
    async fn test_inspect_remote_status_page() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.contains("json"), "status probe should request JSON: {}", req);

            let body = r#"{"pool":"www","active processes":48,"idle processes":2,"total processes":50,"max active processes":50,"listen queue":9,"max children reached":3}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let target = HttpTarget::parse(&format!("http://127.0.0.1:{}/status", port), 80).unwrap();
        let metrics = inspect_php_fpm_remote(&target, Duration::from_secs(2)).await;

        assert!(metrics.is_detected);
        assert_eq!(metrics.source, WorkerMetricSource::FpmStatus);
        assert_eq!(metrics.active_workers, Some(48));
        assert_eq!(metrics.listen_queue, Some(9));
        assert!(metrics.origin.is_some_and(|o| o.contains("127.0.0.1")));
    }

    #[tokio::test]
    async fn test_inspect_remote_status_page_http_error_is_not_detected() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut discard = [0u8; 1024];
            let _ = sock.read(&mut discard).await;
            sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let target = HttpTarget::parse(&format!("http://127.0.0.1:{}/status", port), 80).unwrap();
        let metrics = inspect_php_fpm_remote(&target, Duration::from_secs(2)).await;

        assert!(!metrics.is_detected);
        assert!(metrics.origin.is_some_and(|o| o.contains("404")), "the reason must reach the operator");
    }
}
