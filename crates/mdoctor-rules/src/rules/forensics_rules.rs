//! Runtime forensics rules for MySQL digests, Redis internals, PHP workers, FPC, and OpenSearch.

use mdoctor_core::{Category, Confidence, Finding, MagentoInstallation, RedisStatus, Severity};
use mdoctor_db::correlate_query;

/// Redis eviction policies that can discard a key which has no TTL.
///
/// Magento sets a TTL on every session key, so a `volatile-*` policy evicts only
/// expired sessions and is what Adobe Commerce documents for the session store. An
/// `allkeys-*` policy ignores TTLs and will drop live carts under memory pressure.
const SESSION_UNSAFE_POLICY_PREFIX: &str = "allkeys";

/// Evaluates all runtime forensics rules across MySQL, Redis, PHP-FPM, FPC, and OpenSearch.
pub fn evaluate_forensics_rules(installation: &MagentoInstallation) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(evaluate_slow_digests(installation));
    findings.extend(evaluate_lock_waits(installation));
    findings.extend(evaluate_session_redis(installation));
    findings.extend(evaluate_cache_redis(installation));
    findings.extend(evaluate_php_workers(installation));
    findings.extend(evaluate_fpc_punctures(installation));
    findings.extend(evaluate_opensearch(installation));

    findings
}

/// MD-SQL-001: high latency MySQL query digests.
fn evaluate_slow_digests(installation: &MagentoInstallation) -> Vec<Finding> {
    let mut findings = Vec::new();

    for digest in &installation.database_metrics.query_digests {
        let is_slow = digest.avg_time_ms > 1000.0;
        let scans_heavily = digest.avg_rows_examined > 50_000;
        if !is_slow && !scans_heavily {
            continue;
        }

        // A query that is merely wide (a reindex, a report) is not automatically a
        // production incident; latency is the signal that holds a worker open.
        let (severity, confidence) = if is_slow && scans_heavily {
            (Severity::Critical, Confidence::High)
        } else if is_slow {
            (Severity::Critical, Confidence::Medium)
        } else {
            (Severity::Warning, Confidence::Medium)
        };

        let corr = correlate_query(digest, installation);
        let mut f = Finding::new(
            "MD-SQL-001",
            "High latency MySQL query digest detected",
            severity,
            confidence,
            Category::Queries,
        );
        f.summary = format!(
            "Query digest executes with average latency {:.1}ms (max {:.1}ms), examining avg {} rows.",
            digest.avg_time_ms, digest.max_time_ms, digest.avg_rows_examined
        );
        f.evidence.push(format!("Query fingerprint: {}", digest.fingerprint));
        f.evidence.push(format!("Execution count: {}", digest.execution_count));
        if !digest.tables_involved.is_empty() {
            f.evidence.push(format!("Tables involved: {}", digest.tables_involved.join(", ")));
        }
        if !corr.candidate_modules.is_empty() {
            f.evidence.push(format!("Candidate owning modules: {}", corr.candidate_modules.join(", ")));
            f.related_modules = corr.candidate_modules.clone();
        }
        f.related_tables = digest.tables_involved.clone();
        f.impact = "Heavy unindexed queries saturate MySQL threads, spike CPU usage, and cause cascading PHP-FPM worker exhaustion.".to_string();
        f.recommendation = "Add missing composite indexes, optimize join conditions, or add collection pagination/caching.".to_string();
        // DIGEST_TEXT carries `?` placeholders, so it is not runnable as written.
        f.verification_commands.push(
            "Substitute literal values for the ? placeholders, then run: EXPLAIN ANALYZE <query>".to_string(),
        );

        findings.push(f);
    }

    findings
}

/// MD-SQL-002: lock contention. Only a performance_schema-confirmed blocker earns a
/// Critical; a long-running query alone is reported as one, not as a lock wait.
fn evaluate_lock_waits(installation: &MagentoInstallation) -> Vec<Finding> {
    let mut findings = Vec::new();

    for lock in &installation.database_metrics.active_lock_waits {
        if lock.wait_time_secs <= 5 {
            continue;
        }

        let mut f = if lock.is_confirmed_lock_wait {
            let mut f = Finding::new(
                "MD-SQL-002",
                "Active MySQL transaction lock wait detected",
                Severity::Critical,
                Confidence::High,
                Category::Database,
            );
            f.summary = format!(
                "Thread {} has been blocked waiting for a lock for {} seconds.",
                lock.waiting_query_id, lock.wait_time_secs
            );
            if let Some(blocker) = lock.blocking_query_id {
                f.evidence.push(format!("Blocking thread: {}", blocker));
            }
            if let Some(query) = &lock.blocking_query {
                f.evidence.push(format!("Blocking query: {}", query));
            }
            f
        } else {
            let mut f = Finding::new(
                "MD-SQL-003",
                "Long-running MySQL statement occupying a connection",
                Severity::Warning,
                Confidence::Medium,
                Category::Database,
            );
            f.summary = format!(
                "Thread {} has been executing for {} seconds. performance_schema did not name a blocking transaction, so this is a slow statement rather than a confirmed lock wait.",
                lock.waiting_query_id, lock.wait_time_secs
            );
            if let Some(cmd) = &lock.command {
                f.evidence.push(format!("Command/state: {}", cmd));
            }
            if let Some(user) = &lock.user {
                f.evidence.push(format!("Connection user: {}", user));
            }
            f
        };

        f.evidence.push(format!("Query: {}", lock.waiting_query));
        if let Some(tbl) = &lock.table_name {
            f.evidence.push(format!("Table: {}", tbl));
            f.related_tables.push(tbl.clone());
        }
        f.impact = "Transactions queue up behind locks, holding PHP worker threads open until 504 Gateway Timeouts occur.".to_string();
        f.recommendation = "Identify and terminate blocking long-running transactions (SHOW PROCESSLIST, SHOW ENGINE INNODB STATUS) and minimize lock scope in custom transactions.".to_string();
        f.verification_commands.push("SHOW FULL PROCESSLIST;".to_string());
        f.verification_commands
            .push("SELECT * FROM performance_schema.data_lock_waits;".to_string());

        findings.push(f);
    }

    findings
}

/// True when both instances resolve to the same server, so server-wide counters such
/// as `evicted_keys` cannot be attributed to one of them alone.
fn shares_instance(a: &RedisStatus, b: &RedisStatus) -> bool {
    match (&a.endpoint, &b.endpoint) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// MD-RDS-001: session store eviction risk.
fn evaluate_session_redis(installation: &MagentoInstallation) -> Vec<Finding> {
    let session = &installation.runtime.redis_session;
    if !session.is_reachable {
        return Vec::new();
    }

    let policy = match session.maxmemory_policy.as_deref() {
        Some(p) => p,
        // Without a policy reading there is nothing to judge.
        None => return Vec::new(),
    };

    // Only allkeys-* discards keys that still hold a live session.
    let policy_is_unsafe = policy.starts_with(SESSION_UNSAFE_POLICY_PREFIX);
    let evicted = session.evicted_keys.unwrap_or(0);
    // evicted_keys is a server-wide counter. On a shared instance it may be entirely
    // the cache database's evictions, so it cannot stand alone as session evidence.
    let shared_with_cache = shares_instance(session, &installation.runtime.redis_default);
    let evictions_are_attributable = evicted > 0 && !shared_with_cache;

    if !policy_is_unsafe && !evictions_are_attributable {
        return Vec::new();
    }

    let (severity, confidence) = if policy_is_unsafe && evicted > 0 {
        (Severity::Critical, Confidence::High)
    } else if policy_is_unsafe {
        // The policy will drop live sessions once maxmemory is reached, but nothing
        // has been evicted yet.
        (Severity::Critical, Confidence::Medium)
    } else {
        (Severity::Warning, Confidence::Medium)
    };

    let mut f = Finding::new(
        "MD-RDS-001",
        "Redis session store can evict live customer sessions",
        severity,
        confidence,
        Category::Cache,
    );
    f.summary = if policy_is_unsafe {
        format!(
            "Session Redis uses maxmemory-policy '{}', which evicts keys regardless of TTL, with {} keys evicted so far.",
            policy, evicted
        )
    } else {
        format!(
            "Session Redis has evicted {} keys under policy '{}'.",
            evicted, policy
        )
    };
    f.evidence.push(format!(
        "Endpoint: {}",
        session
            .endpoint
            .as_deref()
            .or(installation.env_config.redis_session_host.as_deref())
            .unwrap_or("unknown")
    ));
    f.evidence.push(format!("maxmemory-policy: {}", policy));
    f.evidence.push(format!("evicted_keys (server-wide): {}", evicted));
    if shared_with_cache {
        f.evidence.push(
            "Session and cache share one Redis instance, so evicted_keys cannot be attributed to sessions alone.".to_string(),
        );
    }
    f.impact = "Active shopping sessions are discarded under memory pressure, dropping carts and logging customers out mid-checkout.".to_string();
    f.recommendation = if policy_is_unsafe {
        "Magento sets a TTL on every session key, so use 'volatile-lru' (Adobe's documented setting for the session store) or 'noeviction' with enough maxmemory. Avoid allkeys-* policies, which ignore TTLs.".to_string()
    } else {
        "Raise maxmemory on the session instance, or give sessions a dedicated Redis instance so cache churn cannot pressure them.".to_string()
    };
    f.verification_commands
        .push("redis-cli -h <session_host> -p <session_port> CONFIG GET maxmemory-policy".to_string());
    f.verification_commands
        .push("redis-cli -h <session_host> -p <session_port> INFO stats | grep evicted_keys".to_string());

    vec![f]
}

/// MD-RDS-002 and MD-RDS-003: cache instance memory pressure and hit ratio.
fn evaluate_cache_redis(installation: &MagentoInstallation) -> Vec<Finding> {
    let cache = &installation.runtime.redis_default;
    if !cache.is_reachable {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let used = cache.used_memory_bytes.unwrap_or(0);
    let max = cache.maxmemory_bytes.unwrap_or(0);
    let frag_ratio = cache.mem_fragmentation_ratio.unwrap_or(1.0);

    let is_high_memory = max > 0 && (used as f64 / max as f64) > 0.90;
    let is_high_frag = frag_ratio > 1.8 && used > 100_000_000;

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
        f.evidence.push(if max > 0 {
            format!("Max memory: {} MB", max / (1024 * 1024))
        } else {
            "Max memory: unlimited (maxmemory is 0)".to_string()
        });
        f.evidence.push(format!("Fragmentation ratio: {:.2}", frag_ratio));
        f.impact = "High fragmentation causes operating system swap thrashing and OS OOM kills of the Redis daemon.".to_string();
        f.recommendation = "Enable active defragmentation (CONFIG SET activedefrag yes) or restart Redis during a maintenance window to compact memory.".to_string();
        findings.push(f);
    }

    if let Some(ratio) = cache.hit_ratio {
        let hits = cache.keyspace_hits.unwrap_or(0);
        let misses = cache.keyspace_misses.unwrap_or(0);
        if (hits + misses) > 5000 && ratio < 0.70 {
            let mut f = Finding::new(
                "MD-RDS-003",
                "Low Redis cache hit ratio (cache thrashing)",
                Severity::Warning,
                Confidence::High,
                Category::Cache,
            );
            f.summary = format!(
                "Redis keyspace hit ratio is only {:.1}% ({} hits / {} misses).",
                ratio * 100.0,
                hits,
                misses
            );
            f.impact = "Severe cache misses force every request to fall back to MySQL and PHP compilation, degrading storefront latency.".to_string();
            f.recommendation = "Check for excessive cache flushing, increase maxmemory, or inspect volatile tags.".to_string();
            findings.push(f);
        }
    }

    findings
}

/// MD-FPM-001 and MD-FPM-002: worker saturation and pool sizing.
fn evaluate_php_workers(installation: &MagentoInstallation) -> Vec<Finding> {
    let fpm = &installation.runtime.php_workers;
    if !fpm.is_detected {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Saturation and listen queue are only meaningful from the FPM scoreboard. A
    // /proc scan counts only workers in R state, so a pool saturated with workers
    // blocked on MySQL looks idle; alerting on that number invents both false
    // positives and false negatives.
    if fpm.source.has_reliable_saturation() {
        let saturated = fpm.saturation_pct.is_some_and(|s| s > 85.0);
        let queued = fpm.listen_queue.is_some_and(|q| q > 0);
        let hit_ceiling = fpm.max_children_reached.is_some_and(|c| c > 0);

        if saturated || queued || hit_ceiling {
            let mut f = Finding::new(
                "MD-FPM-001",
                "PHP-FPM worker pool saturation / queue buildup",
                if queued || hit_ceiling { Severity::Critical } else { Severity::Warning },
                Confidence::High,
                Category::Php,
            );
            f.summary = format!(
                "PHP-FPM pool '{}' is {} saturated ({} of {} workers active, listen queue {}).",
                fpm.pool_name.as_deref().unwrap_or("unknown"),
                fpm.saturation_pct.map(|s| format!("{:.1}%", s)).unwrap_or_else(|| "unknown".into()),
                fpm.active_workers.map(|w| w.to_string()).unwrap_or_else(|| "?".into()),
                fpm.max_children.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
                fpm.listen_queue.map(|q| q.to_string()).unwrap_or_else(|| "?".into()),
            );
            f.evidence.push(format!("Metric source: {}", fpm.source));
            if let Some(origin) = &fpm.origin {
                f.evidence.push(format!("Read from: {}", origin));
            }
            if let Some(pm) = &fpm.process_manager {
                f.evidence.push(format!("Process manager: {}", pm));
            }
            if let Some(reached) = fpm.max_children_reached {
                f.evidence.push(format!("max children reached (cumulative): {}", reached));
            }
            if let Some(slow) = fpm.slow_requests {
                f.evidence.push(format!("slow requests: {}", slow));
            }
            f.impact = "Incoming web requests are queued or dropped, producing Nginx/Apache 502 Bad Gateway and 504 Gateway Timeout errors.".to_string();
            f.recommendation = "Increase pm.max_children if host RAM allows, or optimize slow PHP execution paths holding workers open.".to_string();
            findings.push(f);
        }
    }

    // OOM risk is only asserted from a real pm.max_children and a real host memory
    // figure; inspect_php_fpm leaves oom_risk false when either is missing.
    if fpm.oom_risk {
        let mut f = Finding::new(
            "MD-FPM-002",
            "PHP-FPM worker pool memory allocation exceeds host RAM (OOM risk)",
            Severity::Critical,
            Confidence::High,
            Category::Php,
        );
        f.summary = format!(
            "Pool '{}' max_children ({}) can consume up to {:.0} MB against {:.0} MB of host RAM.",
            fpm.pool_name.as_deref().unwrap_or("unknown"),
            fpm.max_children.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
            fpm.total_pool_memory_mb.unwrap_or(0.0),
            fpm.host_total_memory_mb.unwrap_or(0.0),
        );
        f.evidence.push(format!("Metric source: {}", fpm.source));
        if let Some(origin) = &fpm.origin {
            f.evidence.push(format!("Read from: {}", origin));
        }
        f.evidence.push(format!(
            "Worker footprint: {:.0} MB ({})",
            fpm.worker_memory_mb.unwrap_or(0.0),
            if fpm.worker_memory_measured {
                "measured from process RSS"
            } else {
                "estimated; no live workers to measure"
            }
        ));
        f.evidence.push(format!(
            "Potential pool memory: {:.0} MB",
            fpm.total_pool_memory_mb.unwrap_or(0.0)
        ));
        f.impact = "Under traffic surges, the Linux OOM killer will terminate php-fpm or MySQL, crashing the store.".to_string();
        f.recommendation = "Lower pm.max_children in the pool configuration or add RAM so total pool memory stays under 75% of physical memory.".to_string();
        findings.push(f);
    }

    findings
}

/// MD-FPC-001: storefront layout punctures.
fn evaluate_fpc_punctures(installation: &MagentoInstallation) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = Vec::new();

    for block in &installation.runtime.fpc.uncacheable_blocks {
        let is_storefront_handle = block.layout_handle == "default"
            || block.layout_handle.starts_with("catalog_")
            || block.layout_handle.starts_with("cms_")
            || block.layout_handle == "catalogsearch_result_index";

        if !is_storefront_handle {
            continue;
        }

        // The same block declared in a module and overridden in a theme is one problem.
        let key = (block.layout_handle.clone(), block.block_name.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);

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

    findings
}

/// MD-SRC-001: OpenSearch cluster health and catalog index presence.
fn evaluate_opensearch(installation: &MagentoInstallation) -> Vec<Finding> {
    let os = &installation.runtime.opensearch;
    if !os.is_reachable {
        return Vec::new();
    }
    let Some(status) = os.status.as_deref() else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let nodes = os.number_of_nodes.unwrap_or(0);
    let unassigned = os.unassigned_shards.unwrap_or(0);

    // A single-node cluster is permanently yellow: replica shards have nowhere to go.
    // Reporting that as degradation warns forever about a cluster working as designed.
    let single_node = nodes <= 1;
    let is_red = status == "red";
    let is_degraded = is_red || (status == "yellow" && !single_node) || (unassigned > 0 && !single_node);

    if is_degraded {
        let mut f = Finding::new(
            "MD-SRC-001",
            "OpenSearch / Elasticsearch cluster health degraded",
            if is_red { Severity::Critical } else { Severity::Warning },
            Confidence::High,
            Category::Search,
        );
        f.summary = format!(
            "OpenSearch cluster '{}' status is '{}' with {} unassigned shards across {} node(s).",
            os.cluster_name.as_deref().unwrap_or("unknown"),
            status,
            unassigned,
            nodes
        );
        f.evidence.push(format!("Nodes: {}", nodes));
        f.evidence.push(format!("Active primary shards: {}", os.active_primary_shards.unwrap_or(0)));
        f.evidence.push(format!("Unassigned shards: {}", unassigned));
        f.impact = "A red cluster cannot execute search queries, returning 500 errors on catalog pages. Unassigned shards remove replica redundancy and degrade latency.".to_string();
        f.recommendation = "Investigate unassigned shards via GET /_cluster/allocation/explain and verify disk space on data nodes.".to_string();
        findings.push(f);
    } else if status == "yellow" && single_node {
        let mut f = Finding::new(
            "MD-SRC-002",
            "Single-node OpenSearch cluster has no replica redundancy",
            Severity::Info,
            Confidence::High,
            Category::Search,
        );
        f.summary = format!(
            "Cluster '{}' reports yellow because it runs on one node, so replica shards cannot be assigned. This is expected for a single-node deployment, not a fault.",
            os.cluster_name.as_deref().unwrap_or("unknown")
        );
        f.evidence.push(format!("Nodes: {}", nodes));
        f.evidence.push(format!("Unassigned (replica) shards: {}", unassigned));
        f.impact = "Losing the single search node takes catalog search down with no failover.".to_string();
        f.recommendation = "Acceptable for staging. For production resilience add a second data node, or set number_of_replicas to 0 to make the green/yellow signal meaningful.".to_string();
        findings.push(f);
    }

    // Index presence is only claimed when the listing probe actually succeeded.
    if os.catalog_index_probe.is_success() && !os.has_catalog_index {
        let mut f = Finding::new(
            "MD-SRC-003",
            "No Magento catalog search index present in the cluster",
            Severity::Critical,
            Confidence::High,
            Category::Search,
        );
        f.summary = "The cluster is reachable but holds no product or category search index, so catalog search and layered navigation cannot return results.".to_string();
        f.evidence.push(format!("Cluster: {}", os.cluster_name.as_deref().unwrap_or("unknown")));
        f.impact = "Category listing and search pages raise search adapter exceptions until the catalog is indexed.".to_string();
        f.recommendation = "Run bin/magento indexer:reindex catalogsearch_fulltext and confirm the configured Elasticsearch index prefix matches the cluster.".to_string();
        f.verification_commands.push("curl -s '<host>:9200/_cat/indices?v'".to_string());
        findings.push(f);
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdoctor_core::{
        FpcProbeStatus, OpenSearchStatus, PhpWorkerMetrics, ProbeOutcome, QueryDigest, RedisStatus,
        UncacheableBlock, WorkerMetricSource,
    };
    use std::path::PathBuf;

    fn installation() -> MagentoInstallation {
        MagentoInstallation::new(PathBuf::from("/tmp"))
    }

    fn reachable_redis(policy: &str, evicted: u64, endpoint: &str) -> RedisStatus {
        RedisStatus {
            is_configured: true,
            is_reachable: true,
            endpoint: Some(endpoint.to_string()),
            probe: ProbeOutcome::Succeeded,
            maxmemory_policy: Some(policy.to_string()),
            evicted_keys: Some(evicted),
            ..Default::default()
        }
    }

    #[test]
    fn test_detect_slow_query_digest() {
        let mut inst = installation();
        inst.database_metrics.query_digests.push(QueryDigest {
            fingerprint: "SELECT * FROM catalog_product_entity WHERE sku = ?".to_string(),
            avg_time_ms: 1850.0,
            avg_rows_examined: 80000,
            tables_involved: vec!["catalog_product_entity".to_string()],
            ..Default::default()
        });

        let findings = evaluate_forensics_rules(&inst);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "MD-SQL-001");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(
            !findings[0].verification_commands.iter().any(|c| c.starts_with("EXPLAIN SELECT")),
            "a digest with ? placeholders is not runnable SQL"
        );
    }

    #[test]
    fn test_wide_but_fast_digest_is_only_a_warning() {
        let mut inst = installation();
        inst.database_metrics.query_digests.push(QueryDigest {
            fingerprint: "SELECT ... FROM catalog_product_entity".to_string(),
            avg_time_ms: 45.0,
            avg_rows_examined: 90_000,
            ..Default::default()
        });

        let findings = evaluate_forensics_rules(&inst);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_volatile_lru_session_policy_is_not_flagged() {
        // Adobe documents volatile-lru for the session store, and Magento sets a TTL
        // on every session key, so only expired sessions are evicted.
        let mut inst = installation();
        inst.runtime.redis_session = reachable_redis("volatile-lru", 0, "session-1:6379");

        let findings = evaluate_forensics_rules(&inst);
        assert!(
            findings.iter().all(|f| f.rule_id != "MD-RDS-001"),
            "volatile-lru with no evictions must not be reported"
        );
    }

    #[test]
    fn test_noeviction_session_policy_is_not_flagged() {
        let mut inst = installation();
        inst.runtime.redis_session = reachable_redis("noeviction", 0, "session-1:6379");
        assert!(evaluate_forensics_rules(&inst).iter().all(|f| f.rule_id != "MD-RDS-001"));
    }

    #[test]
    fn test_allkeys_lru_session_policy_is_critical() {
        let mut inst = installation();
        inst.runtime.redis_session = reachable_redis("allkeys-lru", 4210, "session-1:6379");

        let f = evaluate_forensics_rules(&inst)
            .into_iter()
            .find(|f| f.rule_id == "MD-RDS-001")
            .expect("allkeys-lru discards live sessions");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence, Confidence::High);
        assert!(f.recommendation.contains("volatile-lru"));
    }

    #[test]
    fn test_unreachable_session_redis_produces_no_finding() {
        let mut inst = installation();
        inst.runtime.redis_session = RedisStatus {
            is_configured: true,
            is_reachable: false,
            probe: ProbeOutcome::failed("connection refused"),
            ..Default::default()
        };
        assert!(evaluate_forensics_rules(&inst).is_empty());
    }

    #[test]
    fn test_shared_instance_evictions_are_not_blamed_on_sessions() {
        // evicted_keys is server-wide: on a shared instance the evictions may be
        // entirely the cache database's.
        let mut inst = installation();
        inst.runtime.redis_session = reachable_redis("volatile-lru", 9000, "redis-1:6379");
        inst.runtime.redis_default = reachable_redis("volatile-lru", 9000, "redis-1:6379");

        assert!(
            evaluate_forensics_rules(&inst).iter().all(|f| f.rule_id != "MD-RDS-001"),
            "a shared counter cannot prove session eviction"
        );
    }

    #[test]
    fn test_dedicated_session_instance_evictions_are_flagged() {
        let mut inst = installation();
        inst.runtime.redis_session = reachable_redis("volatile-lru", 9000, "session-1:6379");
        inst.runtime.redis_default = reachable_redis("volatile-lru", 0, "cache-1:6379");

        let f = evaluate_forensics_rules(&inst)
            .into_iter()
            .find(|f| f.rule_id == "MD-RDS-001")
            .expect("evictions on a dedicated session instance are attributable");
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn test_no_php_fpm_produces_no_findings() {
        // Default metrics mean "not detected"; the old code defaulted max_children to
        // 20 and raised a Critical OOM risk on hosts with no PHP-FPM at all.
        let inst = installation();
        assert!(evaluate_forensics_rules(&inst).iter().all(|f| !f.rule_id.starts_with("MD-FPM")));
    }

    #[test]
    fn test_proc_scan_saturation_does_not_raise_fpm_001() {
        // A /proc scan counts only workers in R state, so its saturation figure cannot
        // support a saturation alert.
        let mut inst = installation();
        inst.runtime.php_workers = PhpWorkerMetrics {
            is_detected: true,
            source: WorkerMetricSource::ProcScan,
            pool_name: Some("www".to_string()),
            active_workers: Some(48),
            max_children: Some(50),
            saturation_pct: Some(96.0),
            ..Default::default()
        };

        assert!(evaluate_forensics_rules(&inst).iter().all(|f| f.rule_id != "MD-FPM-001"));
    }

    #[test]
    fn test_fpm_status_saturation_raises_fpm_001() {
        let mut inst = installation();
        inst.runtime.php_workers = PhpWorkerMetrics {
            is_detected: true,
            source: WorkerMetricSource::FpmStatus,
            origin: Some("http://web-1.internal:80/status?json".to_string()),
            pool_name: Some("www".to_string()),
            active_workers: Some(48),
            max_children: Some(50),
            listen_queue: Some(12),
            max_children_reached: Some(3),
            saturation_pct: Some(96.0),
            ..Default::default()
        };

        let f = evaluate_forensics_rules(&inst)
            .into_iter()
            .find(|f| f.rule_id == "MD-FPM-001")
            .expect("a real scoreboard with a queue is a genuine saturation signal");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.evidence.iter().any(|e| e.contains("web-1.internal")));
    }

    #[test]
    fn test_single_node_yellow_cluster_is_informational() {
        let mut inst = installation();
        inst.runtime.opensearch = OpenSearchStatus {
            is_configured: true,
            is_reachable: true,
            status: Some("yellow".to_string()),
            number_of_nodes: Some(1),
            unassigned_shards: Some(6),
            probe: ProbeOutcome::Succeeded,
            ..Default::default()
        };

        let findings = evaluate_forensics_rules(&inst);
        assert!(findings.iter().all(|f| f.rule_id != "MD-SRC-001"), "single-node yellow is by design");
        let info = findings.iter().find(|f| f.rule_id == "MD-SRC-002").expect("informational note");
        assert_eq!(info.severity, Severity::Info);
    }

    #[test]
    fn test_multi_node_yellow_cluster_is_degraded() {
        let mut inst = installation();
        inst.runtime.opensearch = OpenSearchStatus {
            is_configured: true,
            is_reachable: true,
            status: Some("yellow".to_string()),
            number_of_nodes: Some(3),
            unassigned_shards: Some(4),
            probe: ProbeOutcome::Succeeded,
            ..Default::default()
        };

        let f = evaluate_forensics_rules(&inst)
            .into_iter()
            .find(|f| f.rule_id == "MD-SRC-001")
            .expect("unassigned shards on a multi-node cluster are real");
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn test_failed_index_probe_does_not_claim_missing_index() {
        let mut inst = installation();
        inst.runtime.opensearch = OpenSearchStatus {
            is_configured: true,
            is_reachable: true,
            status: Some("green".to_string()),
            number_of_nodes: Some(3),
            has_catalog_index: false,
            catalog_index_probe: ProbeOutcome::failed("HTTP 403"),
            probe: ProbeOutcome::Succeeded,
            ..Default::default()
        };

        assert!(
            evaluate_forensics_rules(&inst).iter().all(|f| f.rule_id != "MD-SRC-003"),
            "an index listing we could not read is unknown, not missing"
        );
    }

    #[test]
    fn test_successful_probe_with_no_catalog_index_is_critical() {
        let mut inst = installation();
        inst.runtime.opensearch = OpenSearchStatus {
            is_configured: true,
            is_reachable: true,
            status: Some("green".to_string()),
            number_of_nodes: Some(3),
            has_catalog_index: false,
            catalog_index_probe: ProbeOutcome::Succeeded,
            probe: ProbeOutcome::Succeeded,
            ..Default::default()
        };

        let f = evaluate_forensics_rules(&inst)
            .into_iter()
            .find(|f| f.rule_id == "MD-SRC-003")
            .expect("a confirmed empty cluster breaks catalog search");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn test_detect_fpc_puncture() {
        let mut inst = installation();
        inst.runtime.fpc = FpcProbeStatus {
            uncacheable_blocks: vec![UncacheableBlock {
                module: "Vendor_Social".to_string(),
                layout_handle: "catalog_product_view".to_string(),
                block_name: "social.share".to_string(),
                class_name: None,
                template: None,
                source_file: PathBuf::from("view/frontend/layout/catalog_product_view.xml"),
                line: 4,
            }],
            ..Default::default()
        };

        let findings = evaluate_forensics_rules(&inst);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "MD-FPC-001");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_fpc_puncture_deduplicated_across_theme_override() {
        let mut inst = installation();
        let block = |source: &str| UncacheableBlock {
            module: "Vendor_Social".to_string(),
            layout_handle: "catalog_product_view".to_string(),
            block_name: "social.share".to_string(),
            class_name: None,
            template: None,
            source_file: PathBuf::from(source),
            line: 4,
        };
        inst.runtime.fpc.uncacheable_blocks = vec![
            block("app/code/Vendor/Social/view/frontend/layout/catalog_product_view.xml"),
            block("app/design/frontend/Acme/main/Vendor_Social/layout/catalog_product_view.xml"),
        ];

        let findings = evaluate_forensics_rules(&inst);
        assert_eq!(findings.len(), 1, "the same block in two files is one problem");
    }

    #[test]
    fn test_confirmed_lock_wait_is_critical_and_long_query_is_not() {
        let mut inst = installation();
        inst.database_metrics.active_lock_waits = vec![
            mdoctor_core::ActiveLockWait {
                waiting_query_id: 11,
                waiting_query: "UPDATE quote SET ...".to_string(),
                blocking_query_id: Some(9),
                blocking_query: Some("UPDATE quote_item SET ...".to_string()),
                wait_time_secs: 14,
                is_confirmed_lock_wait: true,
                ..Default::default()
            },
            mdoctor_core::ActiveLockWait {
                waiting_query_id: 12,
                waiting_query: "SELECT ... FROM sales_order_grid".to_string(),
                wait_time_secs: 900,
                is_confirmed_lock_wait: false,
                command: Some("Query".to_string()),
                ..Default::default()
            },
        ];

        let findings = evaluate_forensics_rules(&inst);
        let confirmed = findings.iter().find(|f| f.rule_id == "MD-SQL-002").expect("confirmed lock wait");
        assert_eq!(confirmed.severity, Severity::Critical);

        let slow = findings.iter().find(|f| f.rule_id == "MD-SQL-003").expect("long query");
        assert_eq!(slow.severity, Severity::Warning);
        assert!(slow.summary.contains("rather than a confirmed lock wait"));
    }
}
