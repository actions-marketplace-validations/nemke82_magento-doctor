//! ANSI Terminal renderer for Magento Doctor.

use colored::*;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use mdoctor_core::{Finding, HealthScore, MagentoInstallation, Severity, CALVER_VERSION};

pub fn render_terminal_report(
    installation: &MagentoInstallation,
    findings: &[Finding],
    health: &HealthScore,
) -> String {
    let mut out = String::new();

    // 1. Header Banner
    out.push_str(&format!("\n{}\n\n", format!("Magento Doctor {}", CALVER_VERSION).bold().cyan()));

    // 2. Store Metadata Summary
    let edition_str = format!("{}", installation.edition);
    let version_str = installation.version.as_deref().unwrap_or("unknown");
    out.push_str(&format!("{} {}\n", edition_str.bold(), version_str));
    out.push_str(&format!("Mode: {}\n", format!("{}", installation.mode).green()));

    if let Some(php_ver) = &installation.environment.php_cli_version {
        out.push_str(&format!("PHP: {}\n", php_ver));
    }
    if let Some(db_ver) = &installation.database_metrics.server_version {
        out.push_str(&format!("Database: {}\n", db_ver));
    }
    if let Some(host) = &installation.env_config.db_host {
        out.push_str(&format!("Database Host: {}\n", host));
    }

    let enabled_count = installation.enabled_modules_count();
    let disabled_count = installation.disabled_modules_count();
    let third_party_count = installation.third_party_modules_count();

    out.push_str(&format!("Modules: {} enabled / {} disabled\n", enabled_count, disabled_count));
    out.push_str(&format!("Third-party modules: {}\n", third_party_count));

    // Runtime Forensics Telemetry overview
    let mut runtime_notes = Vec::new();
    if !installation.runtime.fpc.uncacheable_blocks.is_empty() {
        runtime_notes.push(format!("FPC: {} uncacheable layout block(s)", installation.runtime.fpc.uncacheable_blocks.len()));
    }
    if installation.runtime.php_workers.is_detected {
        runtime_notes.push(format!(
            "PHP-FPM: {}/{} workers ({:.0}%)",
            installation.runtime.php_workers.active_workers,
            installation.runtime.php_workers.max_children,
            installation.runtime.php_workers.saturation_pct
        ));
    }
    if !installation.database_metrics.query_digests.is_empty() {
        runtime_notes.push(format!("SQL Digests: {} tracked", installation.database_metrics.query_digests.len()));
    }
    if let Some(ratio) = installation.runtime.redis_default.hit_ratio {
        runtime_notes.push(format!("Redis Hit Ratio: {:.1}%", ratio * 100.0));
    }
    if !runtime_notes.is_empty() {
        out.push_str(&format!("Runtime: {}\n\n", runtime_notes.join(" | ")));
    } else {
        out.push('\n');
    }

    // 3. Health Score Badge
    let health_color = if health.overall >= 80 {
        health.overall.to_string().green().bold()
    } else if health.overall >= 50 {
        health.overall.to_string().yellow().bold()
    } else {
        health.overall.to_string().red().bold()
    };

    out.push_str(&format!("Overall Health: {} / 100\n\n", health_color));

    out.push_str(&format!(
        "{}   {}\n{}   {}\n{}      {}\n\n",
        "CRITICAL".red().bold(),
        health.critical_count,
        "WARNING".yellow().bold(),
        health.warning_count,
        "INFO".blue().bold(),
        health.info_count
    ));

    // 4. Primary Concerns / Findings
    if findings.is_empty() {
        out.push_str(&format!("{}\n", "✓ No critical issues or warnings detected!".green().bold()));
    } else {
        out.push_str(&format!("{}\n\n", "Primary concerns".bold().underline()));

        for finding in findings {
            let badge = match finding.severity {
                Severity::Critical => "[CRITICAL]".red().bold(),
                Severity::Warning => "[WARNING]".yellow().bold(),
                Severity::Info => "[INFO]".blue().bold(),
            };

            out.push_str(&format!("{} {} ({})\n", badge, finding.title.bold(), finding.rule_id.dimmed()));
            if !finding.summary.is_empty() {
                out.push_str(&format!("  {}\n", finding.summary));
            }

            if !finding.evidence.is_empty() {
                out.push_str(&format!("  {}\n", "Evidence / Correlation:".bold()));
                for ev in &finding.evidence {
                    out.push_str(&format!("    {}\n", ev));
                }
            }

            if !finding.impact.is_empty() {
                out.push_str(&format!("  {}: {}\n", "Impact".bold(), finding.impact));
            }

            if !finding.recommendation.is_empty() {
                out.push_str(&format!("  {}: {}\n", "Recommendation".bold(), finding.recommendation));
            }

            if !finding.verification_commands.is_empty() {
                out.push_str(&format!("  {}\n", "Manual Verification:".bold()));
                for cmd in &finding.verification_commands {
                    out.push_str(&format!("    $ {}\n", cmd.cyan()));
                }
            }

            let conf_str = match finding.confidence {
                mdoctor_core::Confidence::High => "HIGH".green(),
                mdoctor_core::Confidence::Medium => "MEDIUM".yellow(),
                mdoctor_core::Confidence::Low => "LOW".dimmed(),
            };
            out.push_str(&format!("  Confidence: {}\n\n", conf_str));
        }
    }

    // 5. Subsystem Score Table
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Subsystem").fg(Color::Cyan),
            Cell::new("Health Score").fg(Color::Cyan),
        ]);

    let mut cat_list: Vec<_> = health.categories.iter().collect();
    cat_list.sort_by_key(|(cat, _)| format!("{}", cat));

    for (cat, score) in cat_list {
        let score_cell = if *score >= 80 {
            Cell::new(format!("{}", score)).fg(Color::Green)
        } else if *score >= 50 {
            Cell::new(format!("{}", score)).fg(Color::Yellow)
        } else {
            Cell::new(format!("{}", score)).fg(Color::Red)
        };
        table.add_row(vec![Cell::new(format!("{}", cat)), score_cell]);
    }

    out.push_str(&format!("{}\n", table));
    out
}
