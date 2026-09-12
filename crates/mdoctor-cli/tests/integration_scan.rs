use std::path::PathBuf;
use mdoctor_core::{DiagnosticSnapshot, Edition, HealthScore, Severity};
use mdoctor_magento::collect_installation;
use mdoctor_rules::CrossAnalysisEngine;

#[test]
fn test_fixture_scan_end_to_end() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.join("../../fixtures/magento-2.4.7");

    assert!(root.exists(), "Fixture directory must exist at {:?}", root);

    // 1. Collect installation
    let installation = collect_installation(&root);
    assert_eq!(installation.edition, Edition::OpenSource);
    assert_eq!(installation.version.as_deref(), Some("2.4.7-p3"));
    assert_eq!(installation.enabled_modules_count(), 4);
    assert_eq!(installation.disabled_modules_count(), 1);

    // Verify module footprint
    let feed_module = installation.find_module("Vendor_Feed").expect("Vendor_Feed must exist");
    assert_eq!(feed_module.footprint.cron_jobs_count, 1);
    assert_eq!(feed_module.footprint.db_tables_count, 1);

    let payment_module = installation.find_module("Vendor_Payment").expect("Vendor_Payment must exist");
    assert_eq!(payment_module.footprint.plugins_count, 1);

    // 2. Run CrossAnalysisEngine
    let findings = CrossAnalysisEngine::analyze(&installation);
    assert!(!findings.is_empty());

    // Check MD-PERF-021 (N+1 in loop)
    let n_plus_one = findings.iter().find(|f| f.rule_id == "MD-PERF-021");
    assert!(n_plus_one.is_some(), "Expected MD-PERF-021 finding for repository in loop");
    let n1 = n_plus_one.unwrap();
    assert_eq!(n1.severity, Severity::Critical);
    assert!(n1.evidence.iter().any(|e| e.contains("getById")));

    // Check MD-PLG-001 (Around plugin on hot path)
    let around_hot = findings.iter().find(|f| f.rule_id == "MD-PLG-001");
    assert!(around_hot.is_some(), "Expected MD-PLG-001 finding for around plugin on QuoteManagement");
    let plg = around_hot.unwrap();
    assert!(plg.evidence.iter().any(|e| e.contains("Vendor\\Payment\\Plugin\\QuoteManagement")));

    // Check MD-PERF-015 (Synchronous HTTP call)
    let http_call = findings.iter().find(|f| f.rule_id == "MD-PERF-015");
    assert!(http_call.is_some(), "Expected MD-PERF-015 finding for HTTP client call");

    // 3. Health Score calculation
    let health = HealthScore::calculate(&findings);
    assert!(health.overall < 100);
    assert!(health.critical_count >= 2);

    // 4. Test Snapshot serialization and roundtrip
    let snapshot = DiagnosticSnapshot::new(installation.clone(), findings.clone(), health);
    let json = snapshot.to_json().expect("Snapshot should serialize to JSON");
    assert!(!json.contains("secret_mock_password_never_print"), "Secrets must never be in snapshot!");
    assert!(!json.contains("mock_crypt_key_do_not_expose_12345"), "Crypt key must never be in snapshot!");

    let restored = DiagnosticSnapshot::from_json(&json).expect("Snapshot should deserialize cleanly");
    assert_eq!(restored.installation.version, Some("2.4.7-p3".to_string()));
    assert_eq!(restored.findings.len(), findings.len());

    // 5. Test v0.2 Drift Comparison
    let drift = mdoctor_core::compare_installations(&snapshot, &restored);
    assert!(!drift.has_regressions);
    assert_eq!(drift.health_drift.delta_overall, 0);
    assert!(drift.findings_drift.new_findings.is_empty());
    assert!(drift.modules_drift.is_empty());

    // 6. Test v0.2 Module Impact Scoring
    let ast_findings = mdoctor_rules::scan_php_sources(&installation);
    let impacts = mdoctor_rules::calculate_all_modules_impact(&installation, &ast_findings);
    assert_eq!(impacts.len(), 2, "Expected 2 custom/third-party modules scored");
    let feed_impact = impacts.iter().find(|i| i.module_name == "Vendor_Feed").expect("Vendor_Feed impact");
    assert_eq!(feed_impact.level, mdoctor_core::ImpactLevel::High);
    assert!(feed_impact.score >= 50);

    let payment_impact = impacts.iter().find(|i| i.module_name == "Vendor_Payment").expect("Vendor_Payment impact");
    assert_eq!(payment_impact.level, mdoctor_core::ImpactLevel::Medium);
    assert_eq!(payment_impact.hotpath_plugins_count, 1);

    // 7. Test v0.2 Module Uninstall Impact Forensics
    let feed_uninstall = mdoctor_core::calculate_uninstall_impact(&installation, "Vendor_Feed").expect("Vendor_Feed analysis");
    assert_eq!(feed_uninstall.safety, mdoctor_core::UninstallSafety::Caution);
    assert_eq!(feed_uninstall.orphaned_tables.len(), 1);
    assert_eq!(feed_uninstall.orphaned_tables[0], "vendor_feed_queue");

    let catalog_uninstall = mdoctor_core::calculate_uninstall_impact(&installation, "Magento_Catalog").expect("Magento_Catalog analysis");
    assert_eq!(catalog_uninstall.safety, mdoctor_core::UninstallSafety::Blocked);
    assert!(catalog_uninstall.dependents.iter().any(|d| d.name == "Vendor_Feed"));

    // 8. Test v0.2 Mermaid Graph Generation
    let graph = mdoctor_report::render_mermaid_graph(feed_module, &installation);
    assert!(graph.contains("flowchart TD"));
    assert!(graph.contains("Vendor_Feed"));
    assert!(graph.contains("vendor_export_feed"));
    assert!(graph.contains("vendor_feed_queue"));

    // 9. Test Runtime Forensics & FPC Puncture Detection
    assert_eq!(installation.runtime.fpc.uncacheable_blocks.len(), 1);
    let uncacheable = &installation.runtime.fpc.uncacheable_blocks[0];
    assert_eq!(uncacheable.module, "Vendor_Feed");
    assert_eq!(uncacheable.layout_handle, "catalog_product_view");
    assert_eq!(uncacheable.block_name, "vendor.feed.tracker");

    // Check MD-FPC-001 finding generated by CrossAnalysisEngine
    let fpc_finding = findings.iter().find(|f| f.rule_id == "MD-FPC-001");
    assert!(fpc_finding.is_some(), "Expected MD-FPC-001 finding for storefront layout puncture");
    let fpc_f = fpc_finding.unwrap();
    assert_eq!(fpc_f.severity, Severity::Critical);
    assert!(fpc_f.evidence.iter().any(|e| e.contains("vendor.feed.tracker")));

    // 10. Test Root Cause Investigate Engine end-to-end
    let mut runtime_inst = installation.clone();

    // Inject runtime telemetry: PHP worker pressure + slow query digest
    runtime_inst.runtime.php_workers = mdoctor_core::PhpWorkerMetrics {
        is_detected: true,
        pool_name: "www".to_string(),
        process_manager: "dynamic".to_string(),
        active_workers: 45,
        idle_workers: 5,
        total_workers: 50,
        max_children: 50,
        listen_queue: 6,
        max_children_reached: 1,
        saturation_pct: 90.0,
        estimated_worker_memory_mb: 150.0,
        total_pool_memory_mb: 7500.0,
        oom_risk: false,
    };

    let slow_digest = mdoctor_core::QueryDigest {
        fingerprint: "SELECT * FROM vendor_feed_queue WHERE status = ?".to_string(),
        avg_time_ms: 3500.0,
        tables_involved: vec!["vendor_feed_queue".to_string()],
        ..Default::default()
    };
    runtime_inst.database_metrics.query_digests.push(slow_digest);

    let investigations = mdoctor_rules::investigate_installation(&runtime_inst, &ast_findings, None);
    assert!(!investigations.is_empty(), "Investigate engine should find root causes");

    // Check 504 / Worker Saturation root cause
    let timeout_root = investigations.iter().find(|r| r.target.contains("504"));
    assert!(timeout_root.is_some(), "Expected 504 timeout root cause");
    let t_root = timeout_root.unwrap();
    assert_eq!(t_root.confidence, mdoctor_core::Confidence::High);
    assert!(t_root.culprit_modules.contains(&"Vendor_Feed".to_string()));
    assert!(t_root.causal_chain.nodes.len() >= 3);

    // Check FPC puncture root cause
    let fpc_root = investigations.iter().find(|r| r.target.contains("fpc"));
    assert!(fpc_root.is_some(), "Expected FPC layout puncture root cause");

    // 11. Test Investigation Report Formatting
    let terminal_rep = mdoctor_report::render_investigate_terminal(&investigations, None);
    assert!(terminal_rep.contains("ROOT CAUSE"));
    assert!(terminal_rep.contains("Causal Chain"));
    assert!(terminal_rep.contains("Vendor_Feed"));

    let json_rep = mdoctor_report::render_investigate_json(&investigations).expect("Investigation JSON output");
    assert!(json_rep.contains("impact_score"));
    assert!(json_rep.contains("causal_chain"));
}

