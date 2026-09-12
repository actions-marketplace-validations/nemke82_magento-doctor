//! Full installation collector building the normalized MagentoInstallation model.

use std::collections::HashMap;
use std::path::Path;
use mdoctor_core::{DatabaseSchema, Environment, MagentoInstallation};

use crate::composer_parser::parse_composer_info;
use crate::env_parser::parse_env_php;
use crate::module_parser::{discover_modules, parse_config_php};
use crate::xml::crontab::parse_crontab_xml;
use crate::xml::db_schema::parse_db_schema_xml;
use crate::xml::di::parse_di_xml;
use crate::xml::events::parse_events_xml;
use crate::xml::indexer::parse_indexer_xml;
use crate::xml::layout::parse_layout_xml;

/// Collect static Magento installation model from disk.
pub fn collect_installation(root: &Path) -> MagentoInstallation {
    let mut installation = MagentoInstallation::new(root.to_path_buf());

    // 1. Parse env.php
    let env_php_path = root.join("app/etc/env.php");
    if env_php_path.exists() {
        let parsed_env = parse_env_php(&env_php_path);
        installation.mode = parsed_env.mode;
        installation.env_config = parsed_env.config;
    }

    // 2. Parse Composer & Magento version
    let composer_info = parse_composer_info(root);
    installation.version = composer_info.magento_version;
    installation.edition = composer_info.edition;

    // 3. Parse config.php for enabled modules
    let config_php_path = root.join("app/etc/config.php");
    let module_statuses = parse_config_php(&config_php_path);

    // 4. Discover all modules
    let mut modules = discover_modules(root, &module_statuses, &composer_info.installed_packages);

    let mut all_plugins = Vec::new();
    let mut all_preferences = Vec::new();
    let mut all_observers = Vec::new();
    let mut all_crons = Vec::new();
    let mut all_indexers = Vec::new();
    let mut all_tables = HashMap::new();
    let mut all_uncacheable_blocks = Vec::new();

    // 5. For each module on disk, parse its XML definitions
    for module in &mut modules {
        if module.path.as_os_str().is_empty() || !module.path.exists() {
            continue;
        }

        let etc_dir = module.path.join("etc");
        if !etc_dir.exists() {
            continue;
        }

        // DI: global, frontend, adminhtml, crontab
        let di_areas = [
            ("di.xml", "global"),
            ("frontend/di.xml", "frontend"),
            ("adminhtml/di.xml", "adminhtml"),
            ("crontab/di.xml", "crontab"),
        ];
        for (rel_path, area) in di_areas {
            let di_path = etc_dir.join(rel_path);
            if di_path.exists() {
                let (plgs, prefs) = parse_di_xml(&di_path, &module.name, area);
                module.footprint.plugins_count += plgs.len();
                module.footprint.preferences_count += prefs.len();
                all_plugins.extend(plgs);
                all_preferences.extend(prefs);
            }
        }

        // Events: global, frontend, adminhtml, crontab
        let event_areas = [
            ("events.xml", "global"),
            ("frontend/events.xml", "frontend"),
            ("adminhtml/events.xml", "adminhtml"),
            ("crontab/events.xml", "crontab"),
        ];
        for (rel_path, area) in event_areas {
            let event_path = etc_dir.join(rel_path);
            if event_path.exists() {
                let obs = parse_events_xml(&event_path, &module.name, area);
                module.footprint.observers_count += obs.len();
                for o in &obs {
                    if !module.footprint.events_listened.contains(&o.event_name) {
                        module.footprint.events_listened.push(o.event_name.clone());
                    }
                }
                all_observers.extend(obs);
            }
        }

        // Crontab
        let crontab_path = etc_dir.join("crontab.xml");
        if crontab_path.exists() {
            let crons = parse_crontab_xml(&crontab_path, &module.name);
            module.footprint.cron_jobs_count += crons.len();
            all_crons.extend(crons);
        }

        // Declarative schema
        let db_schema_path = etc_dir.join("db_schema.xml");
        if db_schema_path.exists() {
            let tables = parse_db_schema_xml(&db_schema_path, &module.name);
            module.footprint.db_tables_count += tables.len();
            for (t_name, table) in tables {
                module.footprint.db_columns_count += table.columns.len();
                module.footprint.db_indexes_count += table.indexes.len();
                all_tables.insert(t_name, table);
            }
        }

        // Indexers
        let indexer_path = etc_dir.join("indexer.xml");
        if indexer_path.exists() {
            let idxs = parse_indexer_xml(&indexer_path, &module.name);
            all_indexers.extend(idxs);
        }

        // Layout XML: check view/frontend/layout and view/base/layout for uncacheable blocks
        for layout_rel in &["view/frontend/layout", "view/base/layout"] {
            let layout_dir = module.path.join(layout_rel);
            if layout_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&layout_dir) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.extension().is_some_and(|ext| ext == "xml") {
                            let uncacheable = parse_layout_xml(&path, &module.name);
                            all_uncacheable_blocks.extend(uncacheable);
                        }
                    }
                }
            }
        }
    }

    installation.modules = modules;
    installation.plugins = all_plugins;
    installation.preferences = all_preferences;
    installation.observers = all_observers;
    installation.cron_jobs = all_crons;
    installation.indexers = all_indexers;
    installation.declared_schema = DatabaseSchema { tables: all_tables };
    installation.runtime.fpc.uncacheable_blocks = all_uncacheable_blocks;

    // 6. Environment metadata
    installation.environment = Environment {
        php_cli_version: detect_cli_php_version(),
        php_web_version: None,
        composer_version: None,
        os_name: std::env::consts::OS.to_string(),
        current_user: whoami_user(),
        document_root: Some(root.to_path_buf()),
        filesystem_owner: None,
        git_branch: detect_git_branch(root),
        git_commit: None,
        is_vendor_committed: root.join("vendor").exists() && root.join(".git").exists(),
    };

    installation
}

fn detect_cli_php_version() -> Option<String> {
    let output = std::process::Command::new("php")
        .arg("-r")
        .arg("echo PHP_VERSION;")
        .output()
        .ok()?;
    if output.status.success() {
        let v = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
}

fn whoami_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn detect_git_branch(root: &Path) -> Option<String> {
    let head = root.join(".git/HEAD");
    if head.exists() {
        if let Ok(content) = std::fs::read_to_string(head) {
            if let Some(ref_str) = content.strip_prefix("ref: refs/heads/") {
                return Some(ref_str.trim().to_string());
            }
        }
    }
    None
}
