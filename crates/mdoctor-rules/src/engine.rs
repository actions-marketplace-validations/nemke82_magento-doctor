//! Central correlation engine executing all cross-analysis rules.

use mdoctor_core::{Finding, MagentoInstallation, Severity};
use mdoctor_php::{AstFinding, PhpAstAnalyzer};
use walkdir::WalkDir;

use crate::rules::cache_rules::evaluate_cache_rules;
use crate::rules::cron_rules::evaluate_cron_rules;
use crate::rules::db_rules::evaluate_db_rules;
use crate::rules::di_rules::evaluate_di_rules;
use crate::rules::env_rules::evaluate_env_rules;
use crate::rules::forensics_rules::evaluate_forensics_rules;
use crate::rules::perf_rules::evaluate_perf_rules;
use crate::rules::plugin_rules::evaluate_plugin_rules;

pub struct CrossAnalysisEngine;

impl CrossAnalysisEngine {
    /// Runs full cross-analysis against the normalized installation model.
    pub fn analyze(installation: &MagentoInstallation) -> Vec<Finding> {
        // 1. Run PHP AST analysis across app/code and custom/third-party modules
        let ast_findings = scan_php_sources(installation);

        // 2. Evaluate all rules
        let mut findings = Vec::new();

        findings.extend(evaluate_cron_rules(installation, &ast_findings));
        findings.extend(evaluate_plugin_rules(installation, &ast_findings));
        findings.extend(evaluate_di_rules(installation, &ast_findings));
        findings.extend(evaluate_perf_rules(&ast_findings));
        findings.extend(evaluate_db_rules(installation));
        findings.extend(evaluate_cache_rules(installation));
        findings.extend(evaluate_env_rules(installation));
        findings.extend(evaluate_forensics_rules(installation));

        // 3. Sort findings: Critical first, then Warning, then Info
        findings.sort_by(|a, b| {
            let sev_order = match (a.severity, b.severity) {
                (Severity::Critical, Severity::Critical) => std::cmp::Ordering::Equal,
                (Severity::Critical, _) => std::cmp::Ordering::Less,
                (_, Severity::Critical) => std::cmp::Ordering::Greater,
                (Severity::Warning, Severity::Warning) => std::cmp::Ordering::Equal,
                (Severity::Warning, _) => std::cmp::Ordering::Less,
                (_, Severity::Warning) => std::cmp::Ordering::Greater,
                (Severity::Info, Severity::Info) => std::cmp::Ordering::Equal,
            };

            if sev_order == std::cmp::Ordering::Equal {
                a.rule_id.cmp(&b.rule_id)
            } else {
                sev_order
            }
        });

        findings
    }
}

/// Scans PHP files in app/code and relevant third-party modules.
pub fn scan_php_sources(installation: &MagentoInstallation) -> Vec<AstFinding> {
    let mut findings = Vec::new();
    let mut analyzer = PhpAstAnalyzer::new();

    let mut scan_dirs = Vec::new();

    // 1. app/code (all custom store modules)
    let app_code = installation.root.join("app/code");
    if app_code.exists() {
        scan_dirs.push(app_code.clone());
    }

    // 2. Non-core vendor modules (skip generic vendor libraries like AWS SDK, Symfony, Doctrine, etc.)
    for module in &installation.modules {
        if !module.is_enabled || module.path.as_os_str().is_empty() {
            continue;
        }

        match module.classification {
            mdoctor_core::ModuleClassification::Core
            | mdoctor_core::ModuleClassification::AdobeCommerce => {
                // Core framework code is verified by Adobe; skip brute-force traversal
            }
            _ => {
                let is_under_app_code = module.path.starts_with(&app_code);
                if module.path.exists() && !is_under_app_code && !scan_dirs.contains(&module.path) {
                    scan_dirs.push(module.path.clone());
                }
            }
        }
    }

    for dir in scan_dirs {
        for entry in WalkDir::new(dir)
            .max_depth(6)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "php" {
                        let path_str = entry.path().to_string_lossy();
                        // Ignore test/dev files to prevent false alarms
                        if path_str.contains("/Test/") || path_str.contains("/tests/") || path_str.contains("/dev/") {
                            continue;
                        }

                        if let Ok(ast_f) = analyzer.analyze_file(entry.path()) {
                            findings.extend(ast_f);
                        }
                    }
                }
            }
        }
    }

    findings
}
