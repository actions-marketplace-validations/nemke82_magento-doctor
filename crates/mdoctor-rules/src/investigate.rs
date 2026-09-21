//! Multi-dimensional Root Cause Investigation Engine for Magento Doctor.
//!
//! Every diagnosis is assembled from *signals that were actually measured*. Confidence,
//! impact score, title and summary are all derived from those signals, so a result built
//! on one static config check cannot present itself as a corroborated runtime diagnosis.

use mdoctor_core::{
    CausalChain, CausalNode, CausalNodeType, Confidence, InvestigationResult, MagentoInstallation,
};
use mdoctor_db::correlate_query;
use mdoctor_php::{AstFinding, OperationType};
use mdoctor_runtime::check_redis_config;

/// Redis policies that discard keys regardless of TTL, and so drop live sessions.
const SESSION_UNSAFE_POLICY_PREFIX: &str = "allkeys";

/// Evidence gathered for one diagnosis.
///
/// The weights are a deliberate ranking of how much each observation tells us: a live
/// scoreboard reading outweighs a static config smell, and two independent signals
/// pointing the same way outweigh either alone.
#[derive(Debug, Default)]
struct SignalSet {
    entries: Vec<(String, u32)>,
}

impl SignalSet {
    fn add(&mut self, description: impl Into<String>, weight: u32) {
        self.entries.push((description.into(), weight));
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn total_weight(&self) -> u32 {
        self.entries.iter().map(|(_, w)| w).sum()
    }

    fn strongest_weight(&self) -> u32 {
        self.entries.iter().map(|(_, w)| *w).max().unwrap_or(0)
    }

    fn descriptions(&self) -> Vec<String> {
        self.entries.iter().map(|(d, _)| d.clone()).collect()
    }

    /// High requires corroboration from more than one measurement; a single weak
    /// signal can only ever be Low.
    fn confidence(&self) -> Confidence {
        if self.entries.len() >= 2 && self.total_weight() >= 70 {
            Confidence::High
        } else if self.strongest_weight() >= 40 {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }

    /// Impact is capped by confidence, so only a corroborated High-confidence
    /// diagnosis can reach the >= 90 band that callers treat as critical.
    fn impact_score(&self) -> u32 {
        let cap = match self.confidence() {
            Confidence::High => 98,
            Confidence::Medium => 85,
            Confidence::Low => 65,
        };
        self.total_weight().clamp(10, cap)
    }
}

/// Executes deep root-cause correlation synthesizing runtime metrics, database digests,
/// FPC punctures, worker pressure, and AST static analysis.
pub fn investigate_installation(
    installation: &MagentoInstallation,
    ast_findings: &[AstFinding],
    target_symptom: Option<&str>,
) -> Vec<InvestigationResult> {
    let mut results: Vec<InvestigationResult> = [
        investigate_worker_saturation_and_timeouts(installation, ast_findings),
        investigate_fpc_punctures_and_ttfb(installation, ast_findings),
        investigate_session_eviction_and_logouts(installation),
        investigate_checkout_stalls(installation, ast_findings),
        investigate_search_degradation(installation),
    ]
    .into_iter()
    .flatten()
    .collect();

    // Filter by target symptom if requested (e.g. "slow", "checkout", "504", "cache").
    if let Some(symptom) = target_symptom {
        let sym_lower = symptom.to_lowercase();
        results.retain(|r| {
            r.target.to_lowercase().contains(&sym_lower)
                || r.title.to_lowercase().contains(&sym_lower)
                || r.summary.to_lowercase().contains(&sym_lower)
        });
    }

    results.sort_by_key(|b| std::cmp::Reverse(b.impact_score));
    results
}

/// Investigates PHP worker exhaustion, slow query digests, and stuck cron jobs causing
/// 504 timeouts.
fn investigate_worker_saturation_and_timeouts(
    installation: &MagentoInstallation,
    ast_findings: &[AstFinding],
) -> Option<InvestigationResult> {
    let fpm = &installation.runtime.php_workers;
    let digests = &installation.database_metrics.query_digests;
    let cron_summary = &installation.database_metrics.cron_schedule;

    let mut signals = SignalSet::default();
    let mut chain = CausalChain::new("Intermittent HTTP 504 Gateway Timeouts & High Web Latency");
    let mut culprits: Vec<String> = Vec::new();
    let mut culprit_queries = Vec::new();
    let mut remediations = Vec::new();
    let mut verifications = Vec::new();

    // Worker pressure only counts when it comes from the FPM scoreboard: a /proc scan
    // sees a worker waiting on MySQL as idle, so its saturation figure cannot support
    // a claim either way.
    let worker_pressure = fpm.is_detected
        && fpm.source.has_reliable_saturation()
        && (fpm.saturation_pct.is_some_and(|s| s > 75.0)
            || fpm.listen_queue.is_some_and(|q| q > 0)
            || fpm.max_children_reached.is_some_and(|c| c > 0));

    if worker_pressure {
        signals.add(
            format!(
                "PHP-FPM scoreboard: {} of {} workers active, listen queue {}",
                fpm.active_workers.map(|w| w.to_string()).unwrap_or_else(|| "?".into()),
                fpm.max_children.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
                fpm.listen_queue.map(|q| q.to_string()).unwrap_or_else(|| "?".into()),
            ),
            45,
        );
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Symptom,
                "PHP-FPM",
                format!(
                    "Worker pool '{}' is under pressure ({} active, {} queued)",
                    fpm.pool_name.as_deref().unwrap_or("unknown"),
                    fpm.saturation_pct.map(|s| format!("{:.1}%", s)).unwrap_or_else(|| "?".into()),
                    fpm.listen_queue.map(|q| q.to_string()).unwrap_or_else(|| "0".into()),
                ),
            )
            .with_metric(format!(
                "{}/{} workers",
                fpm.active_workers.map(|w| w.to_string()).unwrap_or_else(|| "?".into()),
                fpm.max_children.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
            )),
        );
        remediations.push(
            "Increase pm.max_children if host RAM allows, or shorten the slow paths holding workers open.".to_string(),
        );
    }

    let slowest = digests
        .iter()
        .filter(|d| d.avg_time_ms > 1000.0)
        .max_by(|a, b| a.avg_time_ms.total_cmp(&b.avg_time_ms));

    if let Some(slow) = slowest {
        signals.add(
            format!("MySQL digest averaging {:.0}ms over {} executions", slow.avg_time_ms, slow.execution_count),
            40,
        );
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Mechanism,
                "MySQL",
                format!(
                    "Query digest takes avg {:.1}ms (max {:.1}ms), holding database threads and PHP workers open",
                    slow.avg_time_ms, slow.max_time_ms
                ),
            )
            .with_metric(format!("{:.1}ms avg", slow.avg_time_ms)),
        );
        culprit_queries.push(slow.fingerprint.clone());

        let corr = correlate_query(slow, installation);
        for m in &corr.candidate_modules {
            if !culprits.contains(m) {
                culprits.push(m.clone());
            }
        }
        if !culprits.is_empty() {
            chain.add_node(CausalNode::new(
                CausalNodeType::Culprit,
                culprits.join(", "),
                format!(
                    "Slow query on table(s) [{}] managed by {}",
                    slow.tables_involved.join(", "),
                    culprits.join(", ")
                ),
            ));
        }

        // An unbatched entity loop in a module that owns the slow table is real
        // corroboration between the runtime and the code.
        for ast in ast_findings {
            if !ast.in_loop
                || !(ast.operation == OperationType::RepositoryLoad
                    || ast.operation == OperationType::CollectionLoad)
            {
                continue;
            }
            let Some(file) = &ast.file_path else { continue };
            let file_str = file.to_string_lossy();
            for m in &culprits {
                let m_path = m.replace('_', "/");
                if file_str.contains(&m_path) || file_str.contains(m) {
                    signals.add(
                        format!("Unbatched entity load inside a loop at {}:{}", file.display(), ast.line_number),
                        25,
                    );
                    chain.add_node(CausalNode::new(
                        CausalNodeType::Trigger,
                        m.as_str(),
                        format!(
                            "Unbatched entity loop at {}:{} ({})",
                            file.display(),
                            ast.line_number,
                            ast.call_signature
                        ),
                    ));
                    remediations.push(format!(
                        "Refactor the loop in {} to batch load or join attributes.",
                        file.display()
                    ));
                    break;
                }
            }
        }

        if !slow.tables_involved.is_empty() {
            remediations.push(format!("Inspect indexing on table(s): {}", slow.tables_involved.join(", ")));
            verifications.push(
                "Substitute literal values for the ? placeholders, then run: EXPLAIN ANALYZE <query>".to_string(),
            );
        }
    }

    let confirmed_locks: Vec<_> = installation
        .database_metrics
        .active_lock_waits
        .iter()
        .filter(|l| l.is_confirmed_lock_wait && l.wait_time_secs > 5)
        .collect();
    if let Some(lock) = confirmed_locks.first() {
        signals.add(
            format!("Confirmed MySQL lock wait of {}s on thread {}", lock.wait_time_secs, lock.waiting_query_id),
            35,
        );
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Mechanism,
                "MySQL",
                format!(
                    "Thread {} blocked {}s behind another transaction",
                    lock.waiting_query_id, lock.wait_time_secs
                ),
            )
            .with_metric(format!("{}s wait", lock.wait_time_secs)),
        );
        remediations.push(
            "Terminate the blocking transaction and narrow the lock scope in the code that opened it.".to_string(),
        );
    }

    let cron_backlog = cron_summary.running_rows > 5 || cron_summary.pending_rows > 100;
    if cron_backlog {
        signals.add(
            format!(
                "Cron backlog: {} running, {} pending rows",
                cron_summary.running_rows, cron_summary.pending_rows
            ),
            20,
        );
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Trigger,
                "Cron",
                format!(
                    "{} jobs running and {} pending, competing with storefront traffic for MySQL and CPU",
                    cron_summary.running_rows, cron_summary.pending_rows
                ),
            )
            .with_metric(format!("{} pending", cron_summary.pending_rows)),
        );
        remediations
            .push("Clear the cron_schedule backlog and stagger heavy job groups away from peak traffic.".to_string());
    }

    if signals.is_empty() {
        return None;
    }

    // The headline names the mechanisms actually observed, rather than asserting a
    // worker/MySQL chain that may not have been measured.
    let (title, summary) = match (worker_pressure, slowest.is_some(), !confirmed_locks.is_empty(), cron_backlog) {
        (true, true, _, _) => (
            "Web Worker Starvation Caused by High-Latency MySQL Query Digests",
            "PHP-FPM workers are held open waiting for long-running MySQL queries, saturating the listen queue and producing 504 timeouts.",
        ),
        (true, false, true, _) => (
            "Web Worker Starvation Behind MySQL Lock Contention",
            "PHP-FPM workers are held open by transactions blocked on MySQL locks, saturating the pool.",
        ),
        (true, false, false, _) => (
            "PHP-FPM Worker Pool Saturation",
            "The PHP-FPM scoreboard shows the pool at or near its ceiling with requests queuing. No slow query or lock wait was measured, so the time is being spent in PHP or an external call.",
        ),
        (false, true, true, _) => (
            "MySQL Latency and Lock Contention on the Request Path",
            "Slow query digests and a confirmed lock wait were measured. PHP-FPM worker data was not available, so the web-tier effect is inferred from the database evidence alone.",
        ),
        (false, true, false, _) => (
            "High-Latency MySQL Query Digests on the Request Path",
            "Slow query digests were measured in performance_schema. PHP-FPM worker data was not available, so worker saturation has not been confirmed.",
        ),
        (false, false, true, _) => (
            "MySQL Lock Contention Blocking Transactions",
            "performance_schema reports transactions blocked behind another transaction's locks.",
        ),
        (false, false, false, _) => (
            "Cron Backlog Competing With Storefront Traffic",
            "The cron_schedule table shows a backlog of running and pending jobs. No worker, query-latency or lock evidence was collected, so this is the only measured signal.",
        ),
    };

    if remediations.is_empty() {
        remediations.push("Increase pm.max_children if RAM permits, and optimize heavy database queries.".to_string());
    }

    Some(InvestigationResult {
        target: "504-slow-timeouts".to_string(),
        title: title.to_string(),
        confidence: signals.confidence(),
        impact_score: signals.impact_score(),
        summary: summary.to_string(),
        evidence_basis: signals.descriptions(),
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

    let mut signals = SignalSet::default();
    let mut chain = CausalChain::new("High Storefront TTFB & Cache Hit Ratio Collapse");
    let mut culprits = Vec::new();
    let mut remediations = Vec::new();

    // Reading cacheable="false" out of layout XML is a fact about the code, not a
    // probe, so it is strong evidence on its own.
    signals.add(
        format!("{} storefront layout block(s) declare cacheable=\"false\"", uncacheable.len()),
        55,
    );

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
        chain.add_node(CausalNode::new(
            CausalNodeType::Culprit,
            block.module.as_str(),
            format!(
                "Block '{}' in {} ({}:{}) disables page caching",
                block.block_name,
                block.layout_handle,
                block.source_file.display(),
                block.line
            ),
        ));
        remediations.push(format!(
            "Remove cacheable=\"false\" from {} in {}:{}. Fetch dynamic data via customer-data.js or GraphQL instead.",
            block.block_name,
            block.source_file.display(),
            block.line
        ));
    }

    // A costly loop inside the very block that punctures the cache is independent
    // corroboration that the puncture is expensive, not merely present.
    for ast in ast_findings {
        if !ast.in_loop {
            continue;
        }
        for b in uncacheable {
            let (Some(b_cls), Some(ast_cls)) = (&b.class_name, &ast.class_name) else {
                continue;
            };
            if b_cls.contains(ast_cls) {
                signals.add(
                    format!("Costly {} inside uncacheable block {}", ast.call_signature, b.block_name),
                    25,
                );
                chain.add_node(CausalNode::new(
                    CausalNodeType::Mechanism,
                    b.module.as_str(),
                    format!("Costly {} inside uncacheable block {}", ast.call_signature, b.block_name),
                ));
            }
        }
    }

    // A measured low cache hit ratio ties the punctures to real cache behaviour.
    if let Some(ratio) = installation.runtime.redis_default.hit_ratio {
        if installation.runtime.redis_default.is_reachable && ratio < 0.70 {
            signals.add(format!("Redis cache hit ratio measured at {:.1}%", ratio * 100.0), 30);
        }
    }

    Some(InvestigationResult {
        target: "fpc-ttfb-cache".to_string(),
        title: "Storefront Full Page Cache Punctured by Layout XML Declarations".to_string(),
        confidence: signals.confidence(),
        impact_score: signals.impact_score(),
        summary: format!(
            "{} storefront layout block(s) declare cacheable=\"false\". In Magento 2 that disables Full Page Cache for the entire page, forcing full PHP and MySQL execution on every hit.",
            uncacheable.len()
        ),
        evidence_basis: signals.descriptions(),
        causal_chain: chain,
        culprit_modules: culprits,
        culprit_queries: Vec::new(),
        remediation_steps: remediations,
        verification_commands: vec![
            "curl -I -H 'X-Magento-Cache-Debug: 1' https://your-store.com/<product-url>".to_string(),
        ],
    })
}

/// Investigates customer cart drops and random logouts due to Redis session eviction or
/// database-index collision.
fn investigate_session_eviction_and_logouts(
    installation: &MagentoInstallation,
) -> Option<InvestigationResult> {
    let session = &installation.runtime.redis_session;
    let cache = &installation.runtime.redis_default;
    let collisions = check_redis_config(&installation.env_config);

    let policy = session.maxmemory_policy.as_deref();
    // Magento TTLs every session key, so only allkeys-* can discard a live session.
    let has_unsafe_policy =
        session.is_reachable && policy.is_some_and(|p| p.starts_with(SESSION_UNSAFE_POLICY_PREFIX));
    let shares_instance = match (&session.endpoint, &cache.endpoint) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    let evicted = session.evicted_keys.unwrap_or(0);
    // A server-wide eviction counter on a shared instance may be entirely the cache's.
    let has_attributable_evictions = session.is_reachable && evicted > 0 && !shares_instance;
    let has_collision = !collisions.is_empty();

    if !has_unsafe_policy && !has_attributable_evictions && !has_collision {
        return None;
    }

    let mut signals = SignalSet::default();
    let mut chain = CausalChain::new("Customers Unexpectedly Logged Out & Empty Shopping Carts");
    let mut remediations = Vec::new();
    let mut verifications = Vec::new();

    if has_collision {
        signals.add("env.php shares one Redis database between sessions and cache", 30);
        chain.add_node(CausalNode::new(
            CausalNodeType::Mechanism,
            "Redis Config",
            "Session storage shares a database index or instance with the default/FPC cache, so a cache flush also clears sessions",
        ));
        remediations.push("Separate the Redis session database from cache storage in app/etc/env.php.".to_string());
    }

    if has_unsafe_policy {
        signals.add(
            format!("Session Redis maxmemory-policy is '{}', which ignores TTLs", policy.unwrap_or("unknown")),
            50,
        );
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Culprit,
                "Redis Server",
                format!(
                    "Session instance policy '{}' evicts keys regardless of TTL",
                    policy.unwrap_or("unknown")
                ),
            )
            .with_metric(format!("{} evicted keys", evicted)),
        );
        remediations.push(
            "Set the session instance to 'volatile-lru' (Adobe's documented setting, which only evicts expired sessions) or 'noeviction' with sufficient maxmemory.".to_string(),
        );
        verifications.push("redis-cli -h <session_host> CONFIG GET maxmemory-policy".to_string());
    }

    if has_attributable_evictions {
        signals.add(format!("{} keys evicted on the dedicated session instance", evicted), 40);
        if !has_unsafe_policy {
            chain.add_node(
                CausalNode::new(
                    CausalNodeType::Culprit,
                    "Redis Server",
                    format!("{} keys evicted from the session instance under memory pressure", evicted),
                )
                .with_metric(format!("{} evicted keys", evicted)),
            );
        }
        remediations.push("Raise maxmemory on the session instance so sessions are not evicted at all.".to_string());
        verifications.push("redis-cli -h <session_host> INFO stats | grep evicted_keys".to_string());
    }

    // Name the mechanism that was actually found.
    let (title, summary) = if has_unsafe_policy || has_attributable_evictions {
        (
            "Customer Session Purging Caused by Redis Eviction Under Memory Pressure",
            "The Redis instance holding PHP sessions is discarding keys under memory pressure, losing active carts and logging customers out.",
        )
    } else {
        (
            "Session and Cache Storage Share One Redis Database",
            "app/etc/env.php points sessions and cache at the same Redis database, so any cache flush or cache eviction also destroys active customer sessions. No live eviction was measured.",
        )
    };

    Some(InvestigationResult {
        target: "session-cart-logouts".to_string(),
        title: title.to_string(),
        confidence: signals.confidence(),
        impact_score: signals.impact_score(),
        summary: summary.to_string(),
        evidence_basis: signals.descriptions(),
        causal_chain: chain,
        culprit_modules: Vec::new(),
        culprit_queries: Vec::new(),
        remediation_steps: remediations,
        verification_commands: verifications,
    })
}

/// Investigates checkout stalls and hanging order buttons.
fn investigate_checkout_stalls(
    installation: &MagentoInstallation,
    ast_findings: &[AstFinding],
) -> Option<InvestigationResult> {
    let hot_plugins: Vec<_> = installation
        .plugins
        .iter()
        .filter(|plg| {
            (plg.target_class.contains("QuoteManagement") || plg.target_class.contains("CartRepository"))
                && plg.plugin_type == mdoctor_core::PluginType::Around
        })
        .collect();

    if hot_plugins.is_empty() {
        return None;
    }

    // An around plugin on the order-placement path is common and often legitimate.
    // Only a synchronous HTTP call found inside one turns it into a stall diagnosis.
    let mut http_calls_in_plugin = Vec::new();
    for plg in &hot_plugins {
        for ast in ast_findings {
            if ast.operation != OperationType::HttpRequest {
                continue;
            }
            if let Some(cls) = &ast.class_name {
                if plg.plugin_class.contains(cls) {
                    http_calls_in_plugin.push((*plg, ast));
                }
            }
        }
    }

    let confirmed_lock_on_quote = installation
        .database_metrics
        .active_lock_waits
        .iter()
        .find(|l| {
            l.is_confirmed_lock_wait
                && l.table_name.as_deref().is_some_and(|t| t.starts_with("quote") || t.starts_with("sales_"))
        });

    let mut signals = SignalSet::default();
    let mut chain = CausalChain::new("Checkout 'Place Order' Freezes & Quote Lock Contention");
    let mut culprits: Vec<String> = Vec::new();
    let mut remediations = Vec::new();

    signals.add(
        format!(
            "{} around plugin(s) intercept QuoteManagement/CartRepository",
            hot_plugins.len()
        ),
        25,
    );
    chain.add_node(CausalNode::new(
        CausalNodeType::Symptom,
        "Storefront Checkout",
        format!(
            "{} around plugin(s) wrap the order placement path, so their execution time is added to every order",
            hot_plugins.len()
        ),
    ));
    for plg in &hot_plugins {
        if !culprits.contains(&plg.module) {
            culprits.push(plg.module.clone());
        }
        chain.add_node(CausalNode::new(
            CausalNodeType::Mechanism,
            plg.module.as_str(),
            format!(
                "Around plugin '{}' wraps {} ({})",
                plg.name,
                plg.target_class,
                plg.source_file.display()
            ),
        ));
    }

    for (plg, ast) in &http_calls_in_plugin {
        signals.add(
            format!("Synchronous {} inside around plugin '{}'", ast.call_signature, plg.name),
            45,
        );
        chain.add_node(CausalNode::new(
            CausalNodeType::Culprit,
            plg.module.as_str(),
            format!(
                "Around plugin '{}' makes a synchronous HTTP call ({}) during quote submission at {}:{}",
                plg.name,
                ast.call_signature,
                plg.source_file.display(),
                ast.line_number
            ),
        ));
        remediations.push(format!(
            "Move the network call out of around plugin '{}' in module '{}' into a message queue or an async consumer.",
            plg.name, plg.module
        ));
    }

    if let Some(lock) = confirmed_lock_on_quote {
        signals.add(
            format!(
                "Confirmed lock wait of {}s on {}",
                lock.wait_time_secs,
                lock.table_name.as_deref().unwrap_or("a quote/sales table")
            ),
            35,
        );
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Mechanism,
                "MySQL",
                format!(
                    "Transaction blocked {}s on {}, serialising order placement",
                    lock.wait_time_secs,
                    lock.table_name.as_deref().unwrap_or("a quote table")
                ),
            )
            .with_metric(format!("{}s wait", lock.wait_time_secs)),
        );
    }

    let (title, summary) = if !http_calls_in_plugin.is_empty() {
        (
            "Synchronous External Network Calls Intercepting Checkout Hot Path",
            "A custom extension wraps Magento order placement with an around plugin that performs a synchronous external HTTP request, adding its full latency to every order.",
        )
    } else if confirmed_lock_on_quote.is_some() {
        (
            "Order Placement Serialised by Quote Table Lock Contention",
            "Around plugins wrap the order placement path while MySQL reports a confirmed lock wait on a quote/sales table, serialising checkout submissions.",
        )
    } else {
        (
            "Around Plugins Intercept the Order Placement Hot Path",
            "Around plugins wrap QuoteManagement or CartRepository, so their execution time is added to every order. No synchronous HTTP call or lock wait was found inside them, so this is an area to review rather than a confirmed stall.",
        )
    };

    if remediations.is_empty() {
        remediations.push(format!(
            "Review the around plugin(s) on the order placement path ({}) for external calls, heavy loops, and unnecessary interception; prefer before/after plugins where possible.",
            culprits.join(", ")
        ));
    }

    Some(InvestigationResult {
        target: "checkout-order-hang".to_string(),
        title: title.to_string(),
        confidence: signals.confidence(),
        impact_score: signals.impact_score(),
        summary: summary.to_string(),
        evidence_basis: signals.descriptions(),
        causal_chain: chain,
        culprit_modules: culprits,
        culprit_queries: Vec::new(),
        remediation_steps: remediations,
        verification_commands: vec![
            "Time an order placement end to end, then compare with the plugin disabled.".to_string(),
        ],
    })
}

/// Investigates search engine failures, catalog 500 errors, and missing indices.
fn investigate_search_degradation(installation: &MagentoInstallation) -> Option<InvestigationResult> {
    let os = &installation.runtime.opensearch;
    if !os.is_reachable {
        return None;
    }

    let nodes = os.number_of_nodes.unwrap_or(0);
    let unassigned = os.unassigned_shards.unwrap_or(0);
    let is_red = os.status.as_deref() == Some("red");
    // A single-node cluster is permanently yellow with unassigned replicas by design.
    let single_node = nodes <= 1;
    let has_unassigned = unassigned > 0 && !single_node;
    // Index absence is only a fact when the listing probe succeeded.
    let missing_catalog_index = os.catalog_index_probe.is_success() && !os.has_catalog_index;

    if !is_red && !has_unassigned && !missing_catalog_index {
        return None;
    }

    let mut signals = SignalSet::default();
    let mut chain = CausalChain::new("Catalog Search Failures & HTTP 500 on Category Pages");
    let mut remediations = Vec::new();

    if is_red {
        signals.add("Cluster health is red", 50);
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Symptom,
                "Catalog Navigation",
                "OpenSearch cluster health is red: primary shards are unavailable",
            )
            .with_metric(format!("{} unassigned shards", unassigned)),
        );
        remediations.push("Recover the red indices via GET /_cluster/allocation/explain before reindexing.".to_string());
    } else if has_unassigned {
        signals.add(format!("{} unassigned shards across {} nodes", unassigned, nodes), 30);
        chain.add_node(
            CausalNode::new(
                CausalNodeType::Symptom,
                "Catalog Navigation",
                format!("{} shards unassigned on a {}-node cluster", unassigned, nodes),
            )
            .with_metric(format!("{} unassigned shards", unassigned)),
        );
        remediations.push("Check data node disk space and shard allocation settings.".to_string());
    }

    if missing_catalog_index {
        signals.add("Index listing confirmed no product or category index exists", 45);
        chain.add_node(CausalNode::new(
            CausalNodeType::Culprit,
            "OpenSearch / Indexer",
            "No product or category search index exists in the cluster",
        ));
        remediations.push("Execute bin/magento indexer:reindex catalogsearch_fulltext.".to_string());
    }

    let title = if missing_catalog_index && !is_red && !has_unassigned {
        "Catalog Search Index Missing From a Healthy Cluster"
    } else if missing_catalog_index {
        "OpenSearch Shard Degradation With No Catalog Search Index"
    } else {
        "OpenSearch Cluster Shard Degradation"
    };

    Some(InvestigationResult {
        target: "search-catalog-500".to_string(),
        title: title.to_string(),
        confidence: signals.confidence(),
        impact_score: signals.impact_score(),
        summary: format!(
            "Cluster '{}' reports status '{}' with {} unassigned shards across {} node(s){}.",
            os.cluster_name.as_deref().unwrap_or("unknown"),
            os.status.as_deref().unwrap_or("unknown"),
            unassigned,
            nodes,
            if missing_catalog_index {
                ", and no Magento catalog index is present"
            } else {
                ""
            }
        ),
        evidence_basis: signals.descriptions(),
        causal_chain: chain,
        culprit_modules: vec!["Magento_CatalogSearch".to_string()],
        culprit_queries: Vec::new(),
        remediation_steps: remediations,
        verification_commands: vec!["curl -s '<host>:9200/_cluster/health?pretty'".to_string()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdoctor_core::{
        ActiveLockWait, FpcEngine, FpcProbeStatus, OpenSearchStatus, PhpWorkerMetrics, ProbeOutcome,
        QueryDigest, RedisStatus, UncacheableBlock, WorkerMetricSource,
    };
    use std::path::PathBuf;

    fn installation() -> MagentoInstallation {
        MagentoInstallation::new(PathBuf::from("/tmp"))
    }

    fn scoreboard(saturation: f64, queue: usize) -> PhpWorkerMetrics {
        PhpWorkerMetrics {
            is_detected: true,
            source: WorkerMetricSource::FpmStatus,
            pool_name: Some("www".to_string()),
            process_manager: Some("dynamic".to_string()),
            active_workers: Some(48),
            idle_workers: Some(2),
            total_workers: Some(50),
            max_children: Some(50),
            listen_queue: Some(queue),
            saturation_pct: Some(saturation),
            ..Default::default()
        }
    }

    #[test]
    fn test_investigate_fpc_puncture() {
        let mut inst = installation();
        inst.runtime.fpc = FpcProbeStatus {
            engine: FpcEngine::BuiltIn,
            uncacheable_blocks: vec![UncacheableBlock {
                module: "Vendor_BadMod".to_string(),
                layout_handle: "catalog_product_view".to_string(),
                block_name: "bad.block".to_string(),
                class_name: None,
                template: None,
                source_file: PathBuf::from("view/frontend/layout/catalog_product_view.xml"),
                line: 12,
            }],
            ..Default::default()
        };

        let results = investigate_installation(&inst, &[], None);
        let fpc = results.iter().find(|r| r.target.contains("fpc")).expect("FPC investigation");
        assert_eq!(fpc.culprit_modules, vec!["Vendor_BadMod".to_string()]);
        assert!(!fpc.evidence_basis.is_empty(), "the basis must be stated");
    }

    #[test]
    fn test_investigate_worker_saturation_and_slow_query() {
        let mut inst = installation();
        inst.runtime.php_workers = scoreboard(96.0, 8);
        inst.database_metrics.query_digests.push(QueryDigest {
            fingerprint: "SELECT * FROM sales_order_grid WHERE status = ?".to_string(),
            avg_time_ms: 4200.0,
            tables_involved: vec!["sales_order_grid".to_string()],
            ..Default::default()
        });

        let results = investigate_installation(&inst, &[], Some("504"));
        assert_eq!(results.len(), 1);
        // Two independent measurements corroborate, so High confidence is earned.
        assert_eq!(results[0].confidence, Confidence::High);
        assert!(results[0].impact_score >= 85);
        assert_eq!(results[0].evidence_basis.len(), 2);
        assert!(results[0].causal_chain.nodes.len() >= 2);
    }

    #[test]
    fn test_cron_backlog_alone_is_low_confidence_and_says_so() {
        // The old engine returned a fixed 92/HIGH here, with a summary blaming MySQL
        // latency and a symptom node describing a worker pool it never measured.
        let mut inst = installation();
        inst.database_metrics.cron_schedule.pending_rows = 500;

        let results = investigate_installation(&inst, &[], None);
        let r = results.first().expect("cron backlog is still worth reporting");

        assert_eq!(r.confidence, Confidence::Low);
        assert!(r.impact_score < 90, "a single weak signal must not read as critical");
        assert!(r.title.contains("Cron"), "the title must name what was found: {}", r.title);
        assert!(r.summary.contains("only measured signal"));
        assert_eq!(r.evidence_basis.len(), 1);
        assert!(
            !r.causal_chain.nodes.iter().any(|n| n.subsystem == "PHP-FPM"),
            "no PHP-FPM node when no worker data was collected"
        );
    }

    #[test]
    fn test_proc_scan_saturation_is_not_treated_as_worker_pressure() {
        let mut inst = installation();
        inst.runtime.php_workers = PhpWorkerMetrics {
            source: WorkerMetricSource::ProcScan,
            saturation_pct: Some(99.0),
            ..scoreboard(99.0, 0)
        };

        assert!(
            investigate_installation(&inst, &[], None).is_empty(),
            "an approximate /proc figure cannot found a diagnosis"
        );
    }

    #[test]
    fn test_checkout_plugin_without_http_call_does_not_claim_one() {
        // The old engine asserted "Synchronous External Network Calls" with impact 96
        // and HIGH confidence from the mere presence of an around plugin.
        let mut inst = installation();
        inst.plugins.push(mdoctor_core::Plugin {
            name: "vendor_order_sync".to_string(),
            module: "Vendor_OrderSync".to_string(),
            plugin_class: "Vendor\\OrderSync\\Plugin\\SubmitQuote".to_string(),
            target_class: "Magento\\Quote\\Model\\QuoteManagement".to_string(),
            plugin_type: mdoctor_core::PluginType::Around,
            sort_order: 10,
            is_disabled: false,
            area: "global".to_string(),
            source_file: PathBuf::from("app/code/Vendor/OrderSync/etc/di.xml"),
            line: 12,
            cost_indicators: Vec::new(),
        });

        let r = investigate_installation(&inst, &[], None)
            .into_iter()
            .find(|r| r.target.contains("checkout"))
            .expect("an around plugin on the order path is worth surfacing");

        assert!(
            !r.summary.contains("synchronous external HTTP"),
            "must not assert an HTTP call that was never found: {}",
            r.summary
        );
        assert!(r.title.contains("Around Plugins Intercept"));
        assert_eq!(r.confidence, Confidence::Low);
        assert!(r.impact_score < 90);
        assert!(!r.culprit_modules.is_empty(), "the plugin's module is still named");
    }

    #[test]
    fn test_redis_collision_alone_names_the_collision_not_eviction() {
        let mut inst = installation();
        inst.env_config.redis_session_host = Some("127.0.0.1:6379".to_string());
        inst.env_config.redis_cache_host = Some("127.0.0.1:6379".to_string());
        inst.env_config.redis_session_db = Some("0".to_string());
        inst.env_config.redis_cache_db = Some("0".to_string());

        let r = investigate_installation(&inst, &[], None)
            .into_iter()
            .find(|r| r.target.contains("session"))
            .expect("a shared session/cache database is a real problem");

        assert!(r.title.contains("Share One Redis Database"), "title was: {}", r.title);
        assert!(r.summary.contains("No live eviction was measured"));
        assert!(r.impact_score < 90);
    }

    #[test]
    fn test_unsafe_session_policy_plus_evictions_is_high_confidence() {
        let mut inst = installation();
        inst.runtime.redis_session = RedisStatus {
            is_configured: true,
            is_reachable: true,
            endpoint: Some("session-1:6379".to_string()),
            probe: ProbeOutcome::Succeeded,
            maxmemory_policy: Some("allkeys-lru".to_string()),
            evicted_keys: Some(8400),
            ..Default::default()
        };
        inst.runtime.redis_default = RedisStatus {
            is_configured: true,
            is_reachable: true,
            endpoint: Some("cache-1:6379".to_string()),
            probe: ProbeOutcome::Succeeded,
            ..Default::default()
        };

        let r = investigate_installation(&inst, &[], None)
            .into_iter()
            .find(|r| r.target.contains("session"))
            .expect("eviction diagnosis");

        assert_eq!(r.confidence, Confidence::High);
        assert!(r.impact_score >= 90);
        assert!(r.title.contains("Eviction"));
    }

    #[test]
    fn test_single_node_yellow_cluster_is_not_investigated() {
        let mut inst = installation();
        inst.runtime.opensearch = OpenSearchStatus {
            is_configured: true,
            is_reachable: true,
            status: Some("yellow".to_string()),
            number_of_nodes: Some(1),
            unassigned_shards: Some(8),
            has_catalog_index: true,
            catalog_index_probe: ProbeOutcome::Succeeded,
            probe: ProbeOutcome::Succeeded,
            ..Default::default()
        };

        assert!(investigate_installation(&inst, &[], None).is_empty());
    }

    #[test]
    fn test_failed_index_probe_is_not_a_missing_index() {
        let mut inst = installation();
        inst.runtime.opensearch = OpenSearchStatus {
            is_configured: true,
            is_reachable: true,
            status: Some("green".to_string()),
            number_of_nodes: Some(3),
            has_catalog_index: false,
            catalog_index_probe: ProbeOutcome::failed("HTTP 401"),
            probe: ProbeOutcome::Succeeded,
            ..Default::default()
        };

        assert!(
            investigate_installation(&inst, &[], None).is_empty(),
            "an unreadable index listing must not be reported as a missing index"
        );
    }

    #[test]
    fn test_confirmed_lock_wait_raises_checkout_and_worker_signals() {
        let mut inst = installation();
        inst.runtime.php_workers = scoreboard(90.0, 3);
        inst.database_metrics.active_lock_waits.push(ActiveLockWait {
            waiting_query_id: 42,
            waiting_query: "UPDATE quote SET ...".to_string(),
            blocking_query_id: Some(41),
            blocking_query: Some("UPDATE quote_item ...".to_string()),
            wait_time_secs: 18,
            table_name: Some("quote".to_string()),
            is_confirmed_lock_wait: true,
            ..Default::default()
        });

        let r = investigate_installation(&inst, &[], Some("504"))
            .into_iter()
            .next()
            .expect("worker plus lock evidence");
        assert_eq!(r.confidence, Confidence::High);
        assert!(r.title.contains("Lock Contention"));
    }

    #[test]
    fn test_clean_installation_yields_nothing() {
        assert!(investigate_installation(&installation(), &[], None).is_empty());
    }
}
