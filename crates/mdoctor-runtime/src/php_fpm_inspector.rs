//! PHP-FPM pool status, worker pressure, and memory sizing forensics.

use std::collections::HashMap;
use std::path::Path;
use mdoctor_core::PhpWorkerMetrics;

/// Inspects PHP-FPM worker saturation and configuration risks.
pub fn inspect_php_fpm(custom_conf: Option<&Path>) -> PhpWorkerMetrics {
    let conf_map = discover_and_parse_fpm_conf(custom_conf);

    let pm = conf_map
        .get("pm")
        .cloned()
        .unwrap_or_else(|| "dynamic".to_string());
    let max_children = conf_map
        .get("pm.max_children")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(20);

    // Discover active and total php-fpm processes on host
    let (active_workers, total_workers) = count_php_fpm_processes();
    let sys_total_mem_mb = get_system_total_memory_mb().unwrap_or(8192.0);

    calculate_pool_metrics(
        "www",
        &pm,
        max_children,
        active_workers,
        total_workers,
        0, // listen queue default
        sys_total_mem_mb,
    )
}

/// Calculates derived pool metrics, saturation percentage, and OOM risk.
pub fn calculate_pool_metrics(
    pool_name: &str,
    pm: &str,
    max_children: usize,
    active_workers: usize,
    total_workers: usize,
    listen_queue: usize,
    sys_total_mem_mb: f64,
) -> PhpWorkerMetrics {
    let idle_workers = total_workers.saturating_sub(active_workers);
    let max_ch = max_children.max(1);
    let saturation_pct = ((active_workers as f64) / (max_ch as f64)) * 100.0;

    // Standard Magento 2 worker footprint averages ~150MB with OPcache and core extensions
    let estimated_worker_memory_mb = 150.0;
    let total_pool_memory_mb = (max_ch as f64) * estimated_worker_memory_mb;

    // High risk if pool can consume > 80% of total host RAM
    let oom_risk = total_pool_memory_mb > (sys_total_mem_mb * 0.80);

    PhpWorkerMetrics {
        is_detected: total_workers > 0 || max_children > 0,
        pool_name: pool_name.to_string(),
        process_manager: pm.to_string(),
        active_workers,
        idle_workers,
        total_workers,
        max_children: max_ch,
        listen_queue,
        max_children_reached: if active_workers >= max_ch { 1 } else { 0 },
        saturation_pct,
        estimated_worker_memory_mb,
        total_pool_memory_mb,
        oom_risk,
    }
}

/// Parses a PHP-FPM INI-style pool configuration file.
pub fn parse_php_fpm_conf(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(';') || trimmed.starts_with('#') || trimmed.starts_with('[') || trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    map
}

fn discover_and_parse_fpm_conf(custom_path: Option<&Path>) -> HashMap<String, String> {
    if let Some(p) = custom_path {
        if let Ok(c) = std::fs::read_to_string(p) {
            return parse_php_fpm_conf(&c);
        }
    }

    // Common standard Linux PHP-FPM pool locations
    let candidates = [
        "/etc/php/8.3/fpm/pool.d/www.conf",
        "/etc/php/8.2/fpm/pool.d/www.conf",
        "/etc/php/8.1/fpm/pool.d/www.conf",
        "/etc/php-fpm.d/www.conf",
        "/usr/local/etc/php-fpm.d/www.conf",
    ];

    for path in &candidates {
        if let Ok(c) = std::fs::read_to_string(path) {
            return parse_php_fpm_conf(&c);
        }
    }

    HashMap::new()
}

fn count_php_fpm_processes() -> (usize, usize) {
    let mut total = 0;
    let mut active = 0;

    let proc_dir = Path::new("/proc");
    if !proc_dir.exists() {
        return (0, 0);
    }

    if let Ok(entries) = std::fs::read_dir(proc_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if name_str.chars().all(|c| c.is_ascii_digit()) {
                let comm_path = entry.path().join("comm");
                if let Ok(comm) = std::fs::read_to_string(comm_path) {
                    if comm.trim().contains("php-fpm") {
                        total += 1;
                        let stat_path = entry.path().join("stat");
                        if let Ok(stat) = std::fs::read_to_string(stat_path) {
                            // State 'R' means Running (Active)
                            if stat.contains(") R ") {
                                active += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    (active, total)
}

fn get_system_total_memory_mb() -> Option<f64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let kb: f64 = parts[1].parse().ok()?;
                return Some(kb / 1024.0);
            }
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
pm.min_spare_servers = 5
pm.max_spare_servers = 20
pm.max_requests = 1000
"#;
        let map = parse_php_fpm_conf(conf);
        assert_eq!(map.get("pm").map(|s| s.as_str()), Some("dynamic"));
        assert_eq!(map.get("pm.max_children").map(|s| s.as_str()), Some("50"));
    }

    #[test]
    fn test_calculate_pool_metrics_oom_detection() {
        // 100 max_children * 150MB = 15,000MB pool. Host has only 8,192MB -> OOM Risk!
        let metrics = calculate_pool_metrics("www", "dynamic", 100, 85, 90, 4, 8192.0);
        assert!(metrics.oom_risk);
        assert_eq!(metrics.active_workers, 85);
        assert_eq!(metrics.saturation_pct, 85.0);
        assert_eq!(metrics.listen_queue, 4);
    }
}
