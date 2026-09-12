//! Runtime forensics rules for MySQL digests, Redis internals, PHP workers, FPC, and OpenSearch.

use mdoctor_core::{Category, Confidence, Finding, MagentoInstallation, Severity};
use mdoctor_db::correlate_query;

/// Evaluates all runtime forensics rules across MySQL, Redis, PHP-FPM, FPC, and OpenSearch.
pub fn evaluate_forensics_rules(installation: &MagentoInstallation) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. MySQL Slow Query Digests (MD-SQL-001)
    for digest in &installation.database_metrics.query_digests {
        if digest.avg_time_ms > 1000.0 || digest.avg_rows_examined > 50000 {
            let corr = correlate_query(digest, installation);
            let mut f = Finding::new(
                "MD-SQL-001",
                "High latency MySQL query digest detected",
                Severity::Critical,
                Confidence::High,
                Category::Queries,
            );
            f.summary = format!(
                "Query digest executes with average latency {:.1}ms (max {:.1}ms), examining avg {} rows.",
                digest.avg_time_ms, digest.max_time_ms, digest.avg_rows_examined
            );
            f.evidence.push(format!("Query fingerprint: {}", digest.fingerprint));
            f.evidence.push(format!("Execution count: {}", digest.execution_count));
            f.evidence.push(format!("Tables involved: {}", digest.tables_involved.join(", ")));
            if !corr.candidate_modules.is_empty() {
                f.evidence.push(format!("Candidate owning modules: {}", corr.candidate_modules.join(", ")));
                f.related_modules = corr.candidate_modules.clone();
            }
            f.related_tables = digest.tables_involved.clone();
            f.impact = "Heavy unindexed queries saturate MySQL threads, spike CPU usage, and cause cascading PHP-FPM worker exhaustion.".to_string();
            f.recommendation = "Add missing composite indexes, optimize join conditions, or add collection pagination/caching.".to_string();
            f.verification_commands.push(format!("EXPLAIN {}", digest.fingerprint));

            findings.push(f);
        }
    }

    // 2. MySQL Active Lock Contention (MD-SQL-002)
    for lock in &installation.database_metrics.active_lock_waits {
        if lock.wait_time_secs > 5 {
            let mut f = Finding::new(
                "MD-SQL-002",
                "Active MySQL transaction or metadata lock wait detected",
                Severity::Critical,
                Confidence::High,
                Category::Database,
            );
            f.summary = format!(
                "Query thread ID {} has been blocked waiting for locks for {} seconds.",
                lock.waiting_query_id, lock.wait_time_secs
            );
            f.evidence.push(format!("Blocked query: {}", lock.waiting_query));
            if let Some(tbl) = &lock.table_name {
                f.evidence.push(format!("Contended table: {}", tbl));
                f.related_tables.push(tbl.clone());
            }
            f.impact = "Transactions queue up behind locks, holding PHP worker threads open until 504 Gateway Timeouts occur.".to_string();
            f.recommendation = "Identify and terminate blocking long-running transactions (SHOW PROCESSLIST, SHOW ENGINE INNODB STATUS) and minimize lock scope in custom transactions.".to_string();
            f.verification_commands.push("SHOW FULL PROCESSLIST;".to_string());
            f.verification_commands.push("SHOW ENGINE INNODB STATUS;".to_string());

            findings.push(f);
        }
    }

    // 3. Redis Eviction in Session Store (MD-RDS-001)
    let session_redis = &installation.runtime.redis_session;
    if session_redis.is_configured && session_redis.is_reachable {
        let has_evictions = session_redis.evicted_keys.is_some_and(|e| e > 0);
        let policy = session_redis.maxmemory_policy.as_deref().unwrap_or("noeviction");
        let is_unsafe_policy = policy != "noeviction";

        if has_evictions || is_unsafe_policy {
            let mut f = Finding::new(
                "MD-RDS-001",
                "Redis session store configured with eviction or evicting keys",
                Severity::Critical,
                Confidence::High,
                Category::Cache,
            );
            f.summary = format!(
                "Session Redis has maxmemory_policy '{}' with {} evicted keys recorded.",
                policy, session_redis.evicted_keys.unwrap_or(0)
            );
            f.evidence.push(format!("Host: {}", installation.env_config.redis_session_host.as_deref().unwrap_or("default")));
            f.evidence.push(format!("maxmemory_policy: {}", policy));
            f.evidence.push(format!("evicted_keys: {}", session_redis.evicted_keys.unwrap_or(0)));
            f.impact = "Active customer sessions will be randomly destroyed under memory pressure, causing immediate cart drops and customer logouts.".to_string();
            f.recommendation = "Set maxmemory_policy to 'noeviction' on Redis session instance and increase maxmemory allocation.".to_string();
            f.verification_commands.push("redis-cli -p <session_port> CONFIG GET maxmemory-policy".to_string());
            f.verification_commands.push("redis-cli -p <session_port> INFO stats".to_string());

            findings.push(f);
        }
    }

    // 4. Redis Memory Pressure & Fragmentation (MD-RDS-002)
    let default_redis = &installation.runtime.redis_default;
    if default_redis.is_configured && default_redis.is_reachable {
        let frag_ratio = default_redis.mem_fragmentation_ratio.unwrap_or(1.0);
        let used = default_redis.used_memory_bytes.unwrap_or(0);
        let max = default_redis.maxmemory_bytes.unwrap_or(0);

        let is_high_memory = max > 0 && (used as f64 / max as f64) > 0.90;
        let is_high_frag = frag_ratio > 1.8 && used > 100_000_000; // >100MB

        if is_high_memory || is_high_frag {
            let mut f = Finding::new(
                "MD-RDS-002",
                "Redis memory pressure or severe memory fragmentation",
                Severity::Warning,
                Confidence::High,
                Category::Cache,
            );
            f.summary = format!(
                "Redis memory usage at {:.1}% of maxmemory with fragmentation ratio {:.2}.",
                if max > 0 { (used as f64 / max as f64) * 100.0 } else { 0.0 },
                frag_ratio
            );
            f.evidence.push(format!("Used memory: {} MB", used / (1024 * 1024)));
            f.evidence.push(format!("Max memory: {} MB", max / (1024 * 1024)));
            f.evidence.push(format!("Fragmentation ratio: {:.2}", frag_ratio));
            f.impact = "High fragmentation causes operating system swap thrashing and OS OOM kills of the Redis daemon.".to_string();
            f.recommendation = "Enable active defragmentation (CONFIG SET activedefrag yes) or restart Redis during maintenance window to compact memory.".to_string();

            findings.push(f);
        }

        // Redis Cache Thrashing (MD-RDS-003)
        if let Some(ratio) = default_redis.hit_ratio {
            let hits = default_redis.keyspace_hits.unwrap_or(0);
            let misses = default_redis.keyspace_misses.unwrap_or(0);
            if (hits + misses) > 5000 && ratio < 0.70 {
                let mut f = Finding::new(
                    "MD-RDS-003",
                    "Low Redis cache hit ratio (cache thrashing)",
                    Severity::Warning,
                    Confidence::High,
                    Category::Cache,
                );
                f.summary = format!("Redis keyspace hit ratio is only {:.1}% ({} hits / {} misses).", ratio * 100.0, hits, misses);
                f.impact = "Severe cache misses force every request to fall back to MySQL and PHP compilation, degrading storefront latency.".to_string();
                f.recommendation = "Check for excessive cache flushing, increase maxmemory, or inspect volatile tags.".to_string();

                findings.push(f);
            }
        }
    }

    // 5. PHP-FPM Worker Pool Saturation (MD-FPM-001)
    let fpm = &installation.runtime.php_workers;
    if fpm.is_detected && fpm.max_children > 0 {
        if fpm.saturation_pct > 85.0 || fpm.listen_queue > 0 {
            let mut f = Finding::new(
                "MD-FPM-001",
                "PHP-FPM worker pool saturation / queue buildup",
                Severity::Critical,
                Confidence::High,
                Category::Php,
            );
            f.summary = format!(
                "PHP-FPM pool '{}' is {:.1}% saturated ({}/{} active workers, listen queue: {}).",
                fpm.pool_name, fpm.saturation_pct, fpm.active_workers, fpm.max_children, fpm.listen_queue
            );
            f.evidence.push(format!("Process manager: {}", fpm.process_manager));
            f.evidence.push(format!("Active workers: {} / Max children: {}", fpm.active_workers, fpm.max_children));
            f.evidence.push(format!("Listen queue length: {}", fpm.listen_queue));
            f.impact = "Incoming web requests are queued or dropped, producing Nginx/Apache 502 Bad Gateway and 504 Gateway Timeout errors.".to_string();
            f.recommendation = "Increase pm.max_children if host RAM allows, or optimize slow PHP execution paths holding workers open.".to_string();

            findings.push(f);
        }

        // PHP-FPM OOM Risk (MD-FPM-002)
        if fpm.oom_risk {
            let mut f = Finding::new(
                "MD-FPM-002",
                "PHP-FPM worker pool memory allocation exceeds host RAM (OOM risk)",
                Severity::Critical,
                Confidence::High,
                Category::Php,
            );
            f.summary = format!(
                "Pool '{}' max_children ({}) can consume up to {:.0} MB, exceeding safe host RAM thresholds.",
                fpm.pool_name, fpm.max_children, fpm.total_pool_memory_mb
            );
            f.evidence.push(format!("Max children: {}", fpm.max_children));
            f.evidence.push(format!("Estimated worker memory: {:.0} MB", fpm.estimated_worker_memory_mb));
            f.evidence.push(format!("Potential pool memory: {:.0} MB", fpm.total_pool_memory_mb));
            f.impact = "Under traffic surges, Linux OOM-killer will forcibly kill php-fpm or MySQL processes, crashing the store.".to_string();
            f.recommendation = "Lower pm.max_children in pool configuration or upgrade server RAM to ensure total pool memory remains under 75% of physical memory.".to_string();

            findings.push(f);
        }
    }

    // 6. Storefront Layout FPC Punctures (MD-FPC-001)
    for block in &installation.runtime.fpc.uncacheable_blocks {
        let is_storefront_handle = block.layout_handle == "default"
            || block.layout_handle.starts_with("catalog_")
            || block.layout_handle.starts_with("cms_")
            || block.layout_handle == "catalogsearch_result_index";

        if is_storefront_handle {
            let mut f = Finding::new(
                "MD-FPC-001",
                "Storefront layout block declared with cacheable=\"false\" (FPC bypass)",
                Severity::Critical,
                Confidence::High,
                Category::Cache,
            );
            f.summary = format!(
                "Block '{}' in layout handle '{}' has cacheable=\"false\", completely disabling Full Page Cache for that page.",
                block.block_name, block.layout_handle
            );
            f.evidence.push(format!("Module: {}", block.module));
            f.evidence.push(format!("Layout handle: {}", block.layout_handle));
            f.evidence.push(format!("Block name: {}", block.block_name));
            if let Some(cls) = &block.class_name {
                f.evidence.push(format!("Class: {}", cls));
            }
            f.evidence.push(format!("Source: {}:{}", block.source_file.display(), block.line));
            f.related_modules.push(block.module.clone());
            f.related_files.push(format!("{}:{}", block.source_file.display(), block.line));
            f.impact = "In Magento 2, setting cacheable=\"false\" on ANY block in a layout disables FPC for the entire page, forcing 100% PHP/MySQL execution on every page view.".to_string();
            f.recommendation = "Remove cacheable=\"false\" from the layout XML. Load dynamic content via private customer data (customer-data.js) or GraphQL/REST AJAX instead.".to_string();

            findings.push(f);
        }
    }

    // 7. OpenSearch Cluster Degradation (MD-SRC-001)
    let os = &installation.runtime.opensearch;
    if os.is_configured && os.is_reachable {
        if let Some(st) = &os.status {
            if st == "red" || st == "yellow" || os.unassigned_shards.unwrap_or(0) > 0 {
                let mut f = Finding::new(
                    "MD-SRC-001",
                    "OpenSearch / Elasticsearch cluster health degraded",
                    if st == "red" { Severity::Critical } else { Severity::Warning },
                    Confidence::High,
                    Category::Search,
                );
                f.summary = format!(
                    "OpenSearch cluster '{}' status is '{}' with {} unassigned shards.",
                    os.cluster_name.as_deref().unwrap_or("unknown"),
                    st,
                    os.unassigned_shards.unwrap_or(0)
                );
                f.evidence.push(format!("Nodes: {}", os.number_of_nodes.unwrap_or(0)));
                f.evidence.push(format!("Active primary shards: {}", os.active_primary_shards.unwrap_or(0)));
                f.evidence.push(format!("Unassigned shards: {}", os.unassigned_shards.unwrap_or(0)));
                f.impact = "Cluster red status prevents search queries from executing, returning 500 errors on catalog pages. Unassigned shards cause degraded latency.".to_string();
                f.recommendation = "Investigate unassigned shards via GET /_cluster/allocation/explain and verify disk space on data nodes.".to_string();

                findings.push(f);
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdoctor_core::{QueryDigest, UncacheableBlock};
    use std::path::PathBuf;

    #[test]
    fn test_detect_slow_query_digest() {
        let mut inst = MagentoInstallation::new(PathBuf::from("/tmp"));
        let digest = QueryDigest {
            fingerprint: "SELECT * FROM catalog_product_entity WHERE sku = ?".to_string(),
            avg_time_ms: 1850.0,
            avg_rows_examined: 80000,
            tables_involved: vec!["catalog_product_entity".to_string()],
            ..Default::default()
        };
        inst.database_metrics.query_digests.push(digest);

        let findings = evaluate_forensics_rules(&inst);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "MD-SQL-001");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_detect_fpc_puncture() {
        let mut inst = MagentoInstallation::new(PathBuf::from("/tmp"));
        inst.runtime.fpc.uncacheable_blocks.push(UncacheableBlock {
            module: "Vendor_Social".to_string(),
            layout_handle: "catalog_product_view".to_string(),
            block_name: "social.share".to_string(),
            class_name: None,
            template: None,
            source_file: PathBuf::from("view/frontend/layout/catalog_product_view.xml"),
            line: 4,
        });

        let findings = evaluate_forensics_rules(&inst);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "MD-FPC-001");
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
