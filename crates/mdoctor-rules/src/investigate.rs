//! Multi-dimensional Root Cause Investigation Engine for Magento Doctor.

use mdoctor_core::{
    CausalChain, CausalNode, CausalNodeType, Confidence, InvestigationResult, MagentoInstallation,
};
use mdoctor_db::correlate_query;
use mdoctor_php::{AstFinding, OperationType};
use mdoctor_runtime::check_redis_config;

/// Executes deep root-cause correlation synthesizing runtime metrics, database digests,
/// FPC punctures, worker pressure, and AST static analysis.
pub fn investigate_installation(
    installation: &MagentoInstallation,
    ast_findings: &[AstFinding],
    target_symptom: Option<&str>,
) -> Vec<InvestigationResult> {
    let mut results = Vec::new();

    // 1. INVESTIGATION: Storefront 504 Gateway Timeouts & Worker Saturation
    if let Some(res) = investigate_worker_saturation_and_timeouts(installation, ast_findings) {
        results.push(res);
    }

    // 2. INVESTIGATION: Full Page Cache (FPC) Punctures & High Storefront TTFB
    if let Some(res) = investigate_fpc_punctures_and_ttfb(installation, ast_findings) {
        results.push(res);
    }

    // 3. INVESTIGATION: Random Customer Logouts & Cart Drops (Session Eviction)
    if let Some(res) = investigate_session_eviction_and_logouts(installation) {
        results.push(res);
    }

    // 4. INVESTIGATION: Checkout Friction & Order Placement Stalls
    if let Some(res) = investigate_checkout_stalls(installation, ast_findings) {
        results.push(res);
    }

    // 5. INVESTIGATION: Catalog Search Outage & 500 Errors
    if let Some(res) = investigate_search_degradation(installation) {
        results.push(res);
    }

    // Filter by target symptom if requested (e.g. "slow", "checkout", "504", "cache", "search")
    if let Some(symptom) = target_symptom {
        let sym_lower = symptom.to_lowercase();
        results.retain(|r| {
            r.target.to_lowercase().contains(&sym_lower)
                || r.title.to_lowercase().contains(&sym_lower)
                || r.summary.to_lowercase().contains(&sym_lower)
        });
    }

    // Sort by impact score descending
    results.sort_by_key(|b| std::cmp::Reverse(b.impact_score));

    results
}

/// Investigates PHP worker exhaustion, slow query digests, and stuck cron jobs causing 504 timeouts.
fn investigate_worker_saturation_and_timeouts(
    installation: &MagentoInstallation,
    ast_findings: &[AstFinding],
) -> Option<InvestigationResult> {
    let fpm = &installation.runtime.php_workers;
    let digests = &installation.database_metrics.query_digests;
    let cron_summary = &installation.database_metrics.cron_schedule;

    let has_slow_queries = digests.iter().any(|d| d.avg_time_ms > 1000.0);
    let has_worker_pressure = fpm.is_detected && (fpm.saturation_pct > 75.0 || fpm.listen_queue > 0);
    let has_cron_backlog = cron_summary.running_rows > 5 || cron_summary.pending_rows > 100;

    if !has_slow_queries && !has_worker_pressure && !has_cron_backlog {
        return None;
    }

    let mut chain = CausalChain::new("Intermittent HTTP 504 Gateway Timeouts & High Web Latency");
    let mut culprits = Vec::new();
    let mut culprit_queries = Vec::new();
    let mut remediations = Vec::new();
    let mut verifications = Vec::new();

    // Node 1: Symptom
    chain.add_node(
        CausalNode::new(
            CausalNodeType::Symptom,
            "PHP-FPM",
            format!(
                "Worker pool '{}' is operating under elevated pressure ({:.1}% active, {} queued)",
                fpm.pool_name, fpm.saturation_pct, fpm.listen_queue
            ),
        )
        .with_metric(format!("{}/{} workers", fpm.active_workers, fpm.max_children)),
    );

    // Node 2: Mechanism (Slow MySQL Digests)
    if let Some(slowest) = digests.iter().max_by(|a, b| a.avg_time_ms.total_cmp(&b.avg_time_ms)) {
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Mechanism,
                "MySQL",
                format!(
                    "Query digest takes avg {:.1}ms (max {:.1}ms), holding database threads and PHP workers open",
                    slowest.avg_time_ms, slowest.max_time_ms
                ),
            )
            .with_metric(format!("{:.1}ms avg", slowest.avg_time_ms)),
        );
        culprit_queries.push(slowest.fingerprint.clone());

        // Node 3: Trigger & Culprit Correlation
        let corr = correlate_query(slowest, installation);
        for m in &corr.candidate_modules {
            if !culprits.contains(m) {
                culprits.push(m.clone());
            }
        }

        // Add Culprit node for table and module ownership
        if !culprits.is_empty() {
            let tables_str = slowest.tables_involved.join(", ");
            chain.add_node(
                CausalNode::new(
                    CausalNodeType::Culprit,
                    culprits.join(", "),
                    format!("Slow query on table(s) [{}] managed by {}", tables_str, culprits.join(", ")),
                ),
            );
        }

        // Check if there is an AST finding in the same candidate modules
        for ast in ast_findings {
            if ast.in_loop && (ast.operation == OperationType::RepositoryLoad || ast.operation == OperationType::CollectionLoad) {
                if let Some(file) = &ast.file_path {
                    let file_str = file.to_string_lossy();
                    for m in &culprits {
                        let m_path = m.replace('_', "/");
                        if file_str.contains(&m_path) || file_str.contains(m) {
                            chain.add_node(
                                CausalNode::new(
                                    CausalNodeType::Trigger,
                                    m.as_str(),
                                    format!("Unbatched entity loop at {}:{} ({})", file.display(), ast.line_number, ast.call_signature),
                                ),
                            );
                            remediations.push(format!("Refactor loop in {} to batch load or join attributes.", file.display()));
                        }
                    }
                }
            }
        }

        if !slowest.tables_involved.is_empty() {
            remediations.push(format!("Inspect indexing on table(s): {}", slowest.tables_involved.join(", ")));
            verifications.push(format!("EXPLAIN {}", slowest.fingerprint));
        }
    }

    if remediations.is_empty() {
        remediations.push("Increase pm.max_children if RAM permits, and optimize heavy database queries.".to_string());
    }

    Some(InvestigationResult {
        target: "504-slow-timeouts".to_string(),
        title: "Web Worker Starvation Caused by High-Latency MySQL Query Digests".to_string(),
        confidence: Confidence::High,
        impact_score: 92,
        summary: "PHP-FPM worker threads are held open waiting for long-running MySQL queries to complete, causing the listen queue to saturate and triggering Nginx 504 timeouts.".to_string(),
        causal_chain: chain,
        culprit_modules: culprits,
        culprit_queries,
        remediation_steps: remediations,
        verification_commands: verifications,
    })
}

/// Investigates Full Page Cache bypass caused by layout XML cacheable="false" punctures.
fn investigate_fpc_punctures_and_ttfb(
    installation: &MagentoInstallation,
    ast_findings: &[AstFinding],
) -> Option<InvestigationResult> {
    let uncacheable = &installation.runtime.fpc.uncacheable_blocks;
    if uncacheable.is_empty() {
        return None;
    }

    let mut chain = CausalChain::new("High Storefront TTFB & Cache Hit Ratio Collapse");
    let mut culprits = Vec::new();
    let mut remediations = Vec::new();

    chain.add_node(
        CausalNode::new(
            CausalNodeType::Symptom,
            "Full Page Cache",
            format!("{} storefront layout block(s) explicitly declare cacheable=\"false\"", uncacheable.len()),
        )
        .with_metric(format!("{} uncacheable blocks", uncacheable.len())),
    );

    for block in uncacheable {
        if !culprits.contains(&block.module) {
            culprits.push(block.module.clone());
        }

        chain.add_node(
            CausalNode::new(
                CausalNodeType::Culprit,
                block.module.as_str(),
                format!(
                    "Block '{}' in {} ({}:{}) disables page caching",
                    block.block_name, block.layout_handle, block.source_file.display(), block.line
                ),
            ),
        );

        remediations.push(format!(
            "Remove cacheable=\"false\" from {} in {}:{}. Fetch dynamic data via customer-data.js or GraphQL instead.",
            block.block_name, block.source_file.display(), block.line
        ));
    }

    // Check if any AST finding is in the uncacheable block class
    for ast in ast_findings {
        if ast.in_loop {
            for b in uncacheable {
                if let (Some(b_cls), Some(ast_cls)) = (&b.class_name, &ast.class_name) {
                    if b_cls.contains(ast_cls) {
                        chain.add_node(
                            CausalNode::new(
                                CausalNodeType::Mechanism,
                                b.module.as_str(),
                                format!("Costly {} inside uncacheable block {}", ast.call_signature, b.block_name),
                            ),
                        );
                    }
                }
            }
        }
    }

    Some(InvestigationResult {
        target: "fpc-ttfb-cache".to_string(),
        title: "Storefront Full Page Cache Punctured by Custom Layout XML Declarations".to_string(),
        confidence: Confidence::High,
        impact_score: 95,
        summary: "A third-party or custom extension includes cacheable=\"false\" in a catalog or storefront layout file, destroying edge caching and forcing full PHP compilation on every page hit.".to_string(),
        causal_chain: chain,
        culprit_modules: culprits,
        culprit_queries: Vec::new(),
        remediation_steps: remediations,
        verification_commands: vec!["curl -I -H 'X-Magento-Cache-Debug: 1' https://your-store.com/sample-product".to_string()],
    })
}

/// Investigates customer cart drops and random logouts due to Redis session eviction or collision.
fn investigate_session_eviction_and_logouts(
    installation: &MagentoInstallation,
) -> Option<InvestigationResult> {
    let session_redis = &installation.runtime.redis_session;
    let collisions = check_redis_config(&installation.env_config);

    let has_unsafe_policy = session_redis.is_configured
        && session_redis.maxmemory_policy.as_deref().unwrap_or("noeviction") != "noeviction";
    let has_evicted_keys = session_redis.evicted_keys.is_some_and(|e| e > 0);
    let has_collision = !collisions.is_empty();

    if !has_unsafe_policy && !has_evicted_keys && !has_collision {
        return None;
    }

    let mut chain = CausalChain::new("Customers Unexpectedly Logged Out & Empty Shopping Carts");
    let mut remediations = Vec::new();
    let mut verifications = Vec::new();

    if has_collision {
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Mechanism,
                "Redis Config",
                "Session storage shares database index or instance with default/FPC cache",
            ),
        );
        remediations.push("Separate Redis session database from cache storage in app/etc/env.php.".to_string());
    }

    if has_unsafe_policy || has_evicted_keys {
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Culprit,
                "Redis Server",
                format!(
                    "Session instance policy is '{}' with {} evicted keys",
                    session_redis.maxmemory_policy.as_deref().unwrap_or("unknown"),
                    session_redis.evicted_keys.unwrap_or(0)
                ),
            )
            .with_metric(format!("{} evicted keys", session_redis.evicted_keys.unwrap_or(0))),
        );
        remediations.push("Configure session Redis instance with maxmemory_policy 'noeviction'.".to_string());
        verifications.push("redis-cli CONFIG GET maxmemory-policy".to_string());
    }

    Some(InvestigationResult {
        target: "session-cart-logouts".to_string(),
        title: "Customer Session Purging Caused by Misconfigured Redis Eviction Policy".to_string(),
        confidence: Confidence::High,
        impact_score: 98,
        summary: "Active shopping sessions are being purged under Redis memory pressure because the session store does not have eviction disabled, directly losing orders and abandoning customer carts.".to_string(),
        causal_chain: chain,
        culprit_modules: vec!["Magento_Session".to_string()],
        culprit_queries: Vec::new(),
        remediation_steps: remediations,
        verification_commands: verifications,
    })
}

/// Investigates checkout stalls, hanging order buttons, and lock waits on quote tables.
fn investigate_checkout_stalls(
    installation: &MagentoInstallation,
    ast_findings: &[AstFinding],
) -> Option<InvestigationResult> {
    let mut hot_plugins = Vec::new();
    for plg in &installation.plugins {
        if (plg.target_class.contains("QuoteManagement") || plg.target_class.contains("CartRepository"))
            && plg.plugin_type == mdoctor_core::PluginType::Around
        {
            hot_plugins.push(plg);
        }
    }

    let mut http_calls_in_plugin = Vec::new();
    for plg in &hot_plugins {
        for ast in ast_findings {
            if ast.operation == OperationType::HttpRequest {
                if let Some(cls) = &ast.class_name {
                    if plg.plugin_class.contains(cls) {
                        http_calls_in_plugin.push((plg, ast));
                    }
                }
            }
        }
    }

    if hot_plugins.is_empty() && http_calls_in_plugin.is_empty() {
        return None;
    }

    let mut chain = CausalChain::new("Checkout 'Place Order' Freezes & Quote Lock Contention");
    let mut culprits = Vec::new();
    let mut remediations = Vec::new();

    chain.add_node(
        CausalNode::new(
            CausalNodeType::Symptom,
            "Storefront Checkout",
            "Slow or timing out quote submission during checkout order placement",
        ),
    );

    for (plg, ast) in &http_calls_in_plugin {
        if !culprits.contains(&plg.module) {
            culprits.push(plg.module.clone());
        }

        chain.add_node(
            CausalNode::new(
                CausalNodeType::Culprit,
                plg.module.as_str(),
                format!(
                    "Around plugin '{}' makes synchronous HTTP call ({}) during quote submission at {}:{}",
                    plg.name, ast.call_signature, plg.source_file.display(), ast.line_number
                ),
            ),
        );

        remediations.push(format!(
            "Refactor around plugin '{}' in module '{}' to execute network calls asynchronously or via message queue.",
            plg.name, plg.module
        ));
    }

    Some(InvestigationResult {
        target: "checkout-order-hang".to_string(),
        title: "Synchronous External Network Calls Intercepting Checkout Hot Path".to_string(),
        confidence: Confidence::High,
        impact_score: 96,
        summary: "A custom extension intercepts the Magento order placement transaction with an around plugin that executes synchronous external HTTP requests, freezing the checkout process.".to_string(),
        causal_chain: chain,
        culprit_modules: culprits,
        culprit_queries: Vec::new(),
        remediation_steps: remediations,
        verification_commands: vec!["Check payment gateway / ERP latency and timeout configurations.".to_string()],
    })
}

/// Investigates search engine failures, catalog 500 errors, and missing indices.
fn investigate_search_degradation(
    installation: &MagentoInstallation,
) -> Option<InvestigationResult> {
    let os = &installation.runtime.opensearch;
    if !os.is_configured || !os.is_reachable {
        return None;
    }

    let is_red = os.status.as_deref() == Some("red");
    let has_unassigned = os.unassigned_shards.is_some_and(|s| s > 0);
    let missing_catalog_idx = !os.has_catalog_index;

    if !is_red && !has_unassigned && !missing_catalog_idx {
        return None;
    }

    let mut chain = CausalChain::new("Catalog Search Failures & HTTP 500 on Category Pages");
    let mut remediations = Vec::new();

    chain.add_node(
        CausalNode::new(
            CausalNodeType::Symptom,
            "Catalog Navigation",
            format!("OpenSearch cluster status is '{}'", os.status.as_deref().unwrap_or("unknown")),
        )
        .with_metric(format!("{} unassigned shards", os.unassigned_shards.unwrap_or(0))),
    );

    if missing_catalog_idx {
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Culprit,
                "OpenSearch / Indexer",
                "Product search index (magento2_product_*) does not exist in cluster",
            ),
        );
        remediations.push("Execute bin/magento indexer:reindex catalogsearch_fulltext.".to_string());
    }

    if has_unassigned {
        remediations.push("Check OpenSearch data node disk space and shard allocation settings.".to_string());
    }

    Some(InvestigationResult {
        target: "search-catalog-500".to_string(),
        title: "OpenSearch Cluster Shard Degradation or Missing Catalog Search Index".to_string(),
        confidence: Confidence::High,
        impact_score: 90,
        summary: "OpenSearch shard unallocation or missing product catalog indices are causing search adapter exceptions and breaking catalog pages.".to_string(),
        causal_chain: chain,
        culprit_modules: vec!["Magento_CatalogSearch".to_string()],
        culprit_queries: Vec::new(),
        remediation_steps: remediations,
        verification_commands: vec!["curl http://<host>:9200/_cluster/health?pretty".to_string()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdoctor_core::{FpcEngine, FpcProbeStatus, PhpWorkerMetrics, QueryDigest, UncacheableBlock};
    use std::path::PathBuf;

    #[test]
    fn test_investigate_fpc_puncture() {
        let mut inst = MagentoInstallation::new(PathBuf::from("/tmp"));
        inst.runtime.fpc = FpcProbeStatus {
            engine: FpcEngine::BuiltIn,
            is_varnish_configured: false,
            is_varnish_reachable: false,
            varnish_host: None,
            varnish_port: None,
            uncacheable_blocks: vec![UncacheableBlock {
                module: "Vendor_BadMod".to_string(),
                layout_handle: "catalog_product_view".to_string(),
                block_name: "bad.block".to_string(),
                class_name: None,
                template: None,
                source_file: PathBuf::from("view/frontend/layout/catalog_product_view.xml"),
                line: 12,
            }],
        };

        let results = investigate_installation(&inst, &[], None);
        assert!(!results.is_empty());
        let fpc_res = results.iter().find(|r| r.target.contains("fpc")).expect("FPC investigation");
        assert_eq!(fpc_res.culprit_modules, vec!["Vendor_BadMod".to_string()]);
        assert_eq!(fpc_res.impact_score, 95);
    }

    #[test]
    fn test_investigate_worker_saturation_and_slow_query() {
        let mut inst = MagentoInstallation::new(PathBuf::from("/tmp"));
        inst.runtime.php_workers = PhpWorkerMetrics {
            is_detected: true,
            pool_name: "www".to_string(),
            process_manager: "dynamic".to_string(),
            active_workers: 48,
            idle_workers: 2,
            total_workers: 50,
            max_children: 50,
            listen_queue: 8,
            max_children_reached: 1,
            saturation_pct: 96.0,
            estimated_worker_memory_mb: 150.0,
            total_pool_memory_mb: 7500.0,
            oom_risk: false,
        };

        let digest = QueryDigest {
            fingerprint: "SELECT * FROM sales_order_grid WHERE status = ?".to_string(),
            avg_time_ms: 4200.0,
            tables_involved: vec!["sales_order_grid".to_string()],
            ..Default::default()
        };
        inst.database_metrics.query_digests.push(digest);

        let results = investigate_installation(&inst, &[], Some("504"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].confidence, Confidence::High);
        assert!(results[0].causal_chain.nodes.len() >= 2);
    }
}
