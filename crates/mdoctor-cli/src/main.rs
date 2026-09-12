//! CLI entry point for Magento Doctor (mdoctor).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use mdoctor_core::{
    calculate_uninstall_impact, compare_installations, DiagnosticSnapshot, HealthScore,
    MagentoInstallation, SafetyLevel, ScanBudget, Severity, CALVER_VERSION,
};
use mdoctor_db::inspect_live_database;
use mdoctor_magento::{collect_installation, discover_magento_root};
use mdoctor_report::{
    render_drift_json, render_drift_markdown, render_drift_terminal, render_impact_table,
    render_investigate_json, render_investigate_terminal, render_json_report,
    render_markdown_report, render_mermaid_graph, render_sarif_report, render_terminal_report,
    render_uninstall_terminal,
};
use mdoctor_rules::{
    calculate_all_modules_impact, get_rule_explanation, investigate_installation, scan_php_sources,
    CrossAnalysisEngine,
};
use mdoctor_runtime::{
    evaluate_fpc, inspect_opensearch, inspect_php_fpm, inspect_redis, probe_varnish,
};

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Markdown,
    Sarif,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum GraphFormat {
    Mermaid,
}

#[derive(Parser)]
#[command(
    name = "mdoctor",
    version = CALVER_VERSION,
    about = "Deep diagnostics, static analysis and performance forensics for Magento 2"
)]
struct Cli {
    #[arg(short, long, global = true, help = "Path to Magento root directory")]
    root: Option<PathBuf>,

    #[arg(
        short,
        long,
        action = clap::ArgAction::Count,
        global = true,
        help = "Verbosity level (-v, -vv)"
    )]
    verbose: u8,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Multi-dimensional root cause analysis correlating runtime forensics with code
    Investigate {
        #[arg(help = "Focus symptom or target area (e.g. 'slow', 'checkout', '504', 'cache', 'search')")]
        symptom: Option<String>,

        #[arg(short, long, value_enum, default_value = "text", help = "Report format")]
        format: OutputFormat,
    },

    /// Run full comprehensive scan across code, configuration, database, and cron
    Scan {
        #[arg(long, help = "Run offline without connecting to live MySQL or network")]
        offline: bool,

        #[arg(long, help = "Enable deeper inspections with moderate resource safety")]
        deep: bool,

        #[arg(long, default_value = "60", help = "Time budget in seconds")]
        budget: u64,

        #[arg(short, long, value_enum, default_value = "text", help = "Report format")]
        format: OutputFormat,
    },

    /// Run quick operational health check
    Doctor,

    /// Deep Redis and Valkey internals, memory fragmentation, and eviction forensics
    Redis,

    /// Full Page Cache (FPC), Varnish probe, and uncacheable layout block audit
    Fpc,

    /// PHP-FPM pool status, worker saturation, and memory OOM risk
    Fpm,

    /// OpenSearch cluster health, shard allocation, and catalog index status
    #[command(name = "opensearch", alias = "open-search", alias = "search")]
    OpenSearch,

    /// Compare current store state against a baseline snapshot to detect configuration drift
    Compare {
        #[arg(help = "Path to baseline snapshot (.json or .mdoctor)")]
        baseline_file: PathBuf,

        #[arg(short, long, value_enum, default_value = "text", help = "Report format")]
        format: OutputFormat,
    },

    /// Manage baseline configuration snapshots for drift comparison
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },

    /// Rank installed modules by performance impact and architectural risk
    Impact {
        #[arg(short, long, help = "Filter by vendor or module name")]
        filter: Option<String>,
    },

    /// List all installed modules with classification and footprint
    Modules {
        #[arg(short, long, help = "Filter by vendor or module name")]
        filter: Option<String>,

        #[arg(long, help = "Rank modules by performance impact and architectural risk")]
        impact: bool,
    },

    /// Deep inspection of a specific module's integration footprint
    Module {
        #[arg(help = "Module name (e.g. Vendor_Module or Magento_Catalog)")]
        name: String,

        #[arg(long, help = "Perform forensic blast-radius analysis before uninstalling")]
        uninstall_impact: bool,

        #[arg(long, value_enum, help = "Generate visual architecture diagram")]
        graph: Option<GraphFormat>,
    },

    /// Cron forensics, scheduling intervals, and overlap analysis
    Cron,

    /// Indexer status and MView changelog analysis
    Indexers,

    /// Database schema reconciliation, missing/redundant indexes, and table sizes
    Db,

    /// In-depth explanation, impact, and manual verification steps for a rule ID
    Explain {
        #[arg(help = "Rule ID (e.g. MD-CRON-010, MD-PLG-001, MD-PERF-021)")]
        rule_id: String,
    },

    /// Create or analyze diagnostic snapshots
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Identify likely performance bottlenecks (alias for investigate)
    Why {
        #[arg(help = "Target issue (e.g. 'slow', 'checkout', '504')")]
        target: Option<String>,
    },
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Create a baseline snapshot from the current store state
    Create {
        #[arg(short, long, help = "Output baseline path (default: mdoctor-baseline.json)")]
        output: Option<PathBuf>,
    },
    /// Compare current store state against a baseline snapshot
    Compare {
        #[arg(help = "Path to baseline snapshot (.json or .mdoctor)")]
        baseline_file: PathBuf,

        #[arg(short, long, value_enum, default_value = "text", help = "Report format")]
        format: OutputFormat,
    },
}

#[derive(Subcommand)]
enum SnapshotAction {
    /// Create a sanitized diagnostic snapshot file
    Create {
        #[arg(short, long, help = "Output file path (default: <store>-<timestamp>.mdoctor)")]
        output: Option<PathBuf>,
    },
    /// Analyze an exported snapshot file offline
    Analyze {
        #[arg(help = "Path to .mdoctor snapshot file")]
        file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Setup logging
    if cli.verbose > 0 {
        tracing_subscriber::fmt::init();
    }

    // Default to 'scan' if no subcommand provided
    let command = cli.command.unwrap_or(Commands::Scan {
        offline: false,
        deep: false,
        budget: 60,
        format: OutputFormat::Text,
    });

    match command {
        Commands::Investigate { symptom, format } => {
            handle_investigate(cli.root.as_deref(), symptom.as_deref(), format).await
        }
        Commands::Redis => handle_redis(cli.root.as_deref()).await,
        Commands::Fpc => handle_fpc(cli.root.as_deref()).await,
        Commands::Fpm => handle_fpm(cli.root.as_deref()).await,
        Commands::OpenSearch => handle_opensearch(cli.root.as_deref()).await,
        Commands::Explain { rule_id } => {
            handle_explain(&rule_id);
            ExitCode::from(0)
        }
        Commands::Baseline { action } => match action {
            BaselineAction::Create { output } => {
                handle_baseline_create(cli.root.as_deref(), output).await
            }
            BaselineAction::Compare { baseline_file, format } => {
                handle_baseline_compare(cli.root.as_deref(), &baseline_file, format).await
            }
        },
        Commands::Compare { baseline_file, format } => {
            handle_baseline_compare(cli.root.as_deref(), &baseline_file, format).await
        }
        Commands::Impact { filter } => {
            handle_modules_impact(cli.root.as_deref(), filter.as_deref()).await
        }
        Commands::Snapshot { action } => match action {
            SnapshotAction::Create { output } => {
                handle_snapshot_create(cli.root.as_deref(), output).await
            }
            SnapshotAction::Analyze { file } => handle_snapshot_analyze(&file),
        },
        Commands::Scan {
            offline,
            deep,
            budget,
            format,
        } => handle_scan(cli.root.as_deref(), offline, deep, budget, format).await,
        Commands::Doctor => handle_doctor(cli.root.as_deref()).await,
        Commands::Modules { filter, impact } => {
            if impact {
                handle_modules_impact(cli.root.as_deref(), filter.as_deref()).await
            } else {
                handle_modules(cli.root.as_deref(), filter.as_deref()).await
            }
        }
        Commands::Module { name, uninstall_impact, graph } => {
            if uninstall_impact {
                handle_module_uninstall_impact(cli.root.as_deref(), &name).await
            } else if let Some(g_fmt) = graph {
                handle_module_graph(cli.root.as_deref(), &name, g_fmt).await
            } else {
                handle_module(cli.root.as_deref(), &name).await
            }
        }
        Commands::Cron => handle_cron(cli.root.as_deref()).await,
        Commands::Indexers => handle_indexers(cli.root.as_deref()).await,
        Commands::Db => handle_db(cli.root.as_deref()).await,
        Commands::Why { target } => {
            handle_investigate(cli.root.as_deref(), target.as_deref(), OutputFormat::Text).await
        }
    }
}

async fn build_installation_model(
    custom_root: Option<&Path>,
    offline: bool,
    deep: bool,
    budget_secs: u64,
) -> Result<MagentoInstallation, String> {
    let root = discover_magento_root(custom_root, None)
        .map_err(|e| format!("Discovery error: {}", e))?;

    let mut budget = if deep {
        ScanBudget::deep()
    } else {
        ScanBudget::default()
    };
    budget.max_seconds = budget_secs;

    let mut installation = collect_installation(&root);

    // If live probes are allowed and not in offline mode, collect runtime forensics
    if !offline && budget.is_allowed(SafetyLevel::Low) {
        let env_php_path = root.join("app/etc/env.php");
        let parsed_env = mdoctor_magento::parse_env_php(&env_php_path);
        let raw_pass = parsed_env.raw_db_password.as_deref();

        // 1. MySQL live inspection
        if let (Some(host), Some(db), Some(user)) = (
            &installation.env_config.db_host,
            &installation.env_config.db_name,
            &installation.env_config.db_user,
        ) {
            let db_timeout = std::time::Duration::from_secs(budget.max_db_seconds.max(5) + 2);
            if let Ok(Ok(db_metrics)) = tokio::time::timeout(
                db_timeout,
                inspect_live_database(host, db, user, raw_pass, budget.max_db_seconds),
            )
            .await
            {
                installation.database_metrics = db_metrics;
            }
        }

        // 2. PHP-FPM inspection
        installation.runtime.php_workers = inspect_php_fpm(None);

        // 3. Redis / Valkey inspection
        if let Some(endpoint) = &installation.env_config.redis_cache_host {
            let (host, port) = parse_host_port(endpoint, 6379);
            if let Ok(st) = inspect_redis(&host, port, None, 2).await {
                installation.runtime.redis_default = st;
            }
        }
        if let Some(endpoint) = &installation.env_config.redis_session_host {
            let (host, port) = parse_host_port(endpoint, 6379);
            if let Ok(st) = inspect_redis(&host, port, None, 2).await {
                installation.runtime.redis_session = st;
            }
        }

        // 4. OpenSearch inspection
        if let Some(host) = &installation.env_config.opensearch_host {
            let port = installation.env_config.opensearch_port.unwrap_or(9200);
            if let Ok(st) = inspect_opensearch(host, port, 2).await {
                installation.runtime.opensearch = st;
            }
        }

        // 5. Varnish / FPC reverse proxy probe
        let is_varnish_live = probe_varnish("127.0.0.1", 6081, 1).await
            || probe_varnish("127.0.0.1", 80, 1).await;
        let uncacheable = std::mem::take(&mut installation.runtime.fpc.uncacheable_blocks);
        installation.runtime.fpc = evaluate_fpc(&installation.env_config, uncacheable, is_varnish_live);
    }

    Ok(installation)
}

fn parse_host_port(endpoint: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = endpoint.split_once(':') {
        let port = p.parse::<u16>().unwrap_or(default_port);
        (h.to_string(), port)
    } else {
        (endpoint.to_string(), default_port)
    }
}

async fn handle_scan(
    root_opt: Option<&Path>,
    offline: bool,
    deep: bool,
    budget: u64,
    format: OutputFormat,
) -> ExitCode {
    let installation = match build_installation_model(root_opt, offline, deep, budget).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let findings = CrossAnalysisEngine::analyze(&installation);
    let health = HealthScore::calculate(&findings);

    let output = match format {
        OutputFormat::Text => render_terminal_report(&installation, &findings, &health),
        OutputFormat::Json => render_json_report(&installation, &findings, &health)
            .unwrap_or_else(|e| format!("JSON error: {}", e)),
        OutputFormat::Markdown => render_markdown_report(&installation, &findings, &health),
        OutputFormat::Sarif => render_sarif_report(&findings),
    };

    println!("{}", output);

    // Determine exit code
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        ExitCode::from(2)
    } else if findings.iter().any(|f| f.severity == Severity::Warning) {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

async fn handle_doctor(root_opt: Option<&Path>) -> ExitCode {
    let installation = match build_installation_model(root_opt, false, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let findings = CrossAnalysisEngine::analyze(&installation);
    let health = HealthScore::calculate(&findings);

    println!("\n{} - Operational Health Check\n", CALVER_VERSION.cyan().bold());
    println!("Overall Health: {} / 100", health.overall);
    println!("Critical: {}  Warning: {}  Info: {}\n", health.critical_count, health.warning_count, health.info_count);

    if health.critical_count > 0 {
        println!("{}", "CRITICAL CONCERNS:".red().bold());
        for f in findings.iter().filter(|f| f.severity == Severity::Critical) {
            println!("  • [{}] {}", f.rule_id, f.title.bold());
            println!("    {}", f.recommendation);
        }
    } else {
        println!("{}", "✓ No critical operational blockages detected.".green().bold());
    }

    ExitCode::from(0)
}

async fn handle_modules(root_opt: Option<&Path>, filter: Option<&str>) -> ExitCode {
    let installation = match build_installation_model(root_opt, true, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Module").fg(Color::Cyan),
            Cell::new("Classification").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Cyan),
            Cell::new("Plugins").fg(Color::Cyan),
            Cell::new("Prefs").fg(Color::Cyan),
            Cell::new("Observers").fg(Color::Cyan),
            Cell::new("Crons").fg(Color::Cyan),
            Cell::new("Tables").fg(Color::Cyan),
        ]);

    for m in &installation.modules {
        if let Some(filt) = filter {
            if !m.name.to_lowercase().contains(&filt.to_lowercase()) {
                continue;
            }
        }

        let status_cell = if m.is_enabled {
            Cell::new("enabled").fg(Color::Green)
        } else {
            Cell::new("disabled").fg(Color::DarkGrey)
        };

        table.add_row(vec![
            Cell::new(&m.name),
            Cell::new(format!("{}", m.classification)),
            status_cell,
            Cell::new(m.footprint.plugins_count),
            Cell::new(m.footprint.preferences_count),
            Cell::new(m.footprint.observers_count),
            Cell::new(m.footprint.cron_jobs_count),
            Cell::new(m.footprint.db_tables_count),
        ]);
    }

    println!("\nInstalled Modules Inventory ({})\n", installation.modules.len());
    println!("{}\n", table);
    ExitCode::from(0)
}

async fn handle_module(root_opt: Option<&Path>, name: &str) -> ExitCode {
    let installation = match build_installation_model(root_opt, true, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let module = match installation.find_module(name) {
        Some(m) => m,
        None => {
            eprintln!("{}: Module '{}' not found in this installation.", "Error".red().bold(), name);
            return ExitCode::from(1);
        }
    };

    println!("\n{}\n", module.name.bold().cyan());
    println!("Status: {}", if module.is_enabled { "enabled".green() } else { "disabled".red() });
    if let Some(pkg) = &module.package_name {
        println!("Package: {}", pkg);
    }
    if let Some(ver) = &module.version {
        println!("Version: {}", ver);
    }
    println!("Classification: {}", module.classification);
    println!("Location: {}", module.path.display());

    if !module.sequence.is_empty() {
        println!("\nDependencies (sequence):");
        for dep in &module.sequence {
            println!("  • {}", dep);
        }
    }

    println!("\nMagento Integration Footprint:");
    println!("  Plugins:      {}", module.footprint.plugins_count);
    println!("  Preferences:  {}", module.footprint.preferences_count);
    println!("  Observers:    {}", module.footprint.observers_count);
    println!("  Cron jobs:    {}", module.footprint.cron_jobs_count);
    println!("  DB tables:    {}", module.footprint.db_tables_count);
    println!("  DB columns:   {}", module.footprint.db_columns_count);
    println!("  Indexes:      {}", module.footprint.db_indexes_count);

    ExitCode::from(0)
}

async fn handle_cron(root_opt: Option<&Path>) -> ExitCode {
    let installation = match build_installation_model(root_opt, false, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    println!("\n{} - Cron Forensics\n", CALVER_VERSION.cyan().bold());

    let summary = &installation.database_metrics.cron_schedule;
    if summary.total_rows > 0 {
        println!("cron_schedule state: {} rows ({} pending, {} running, {} missed)",
            summary.total_rows, summary.pending_rows, summary.running_rows, summary.missed_rows);
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Job Code").fg(Color::Cyan),
            Cell::new("Module").fg(Color::Cyan),
            Cell::new("Schedule").fg(Color::Cyan),
            Cell::new("Interval").fg(Color::Cyan),
            Cell::new("Instance Class").fg(Color::Cyan),
        ]);

    for job in &installation.cron_jobs {
        let interval_str = job
            .interval_seconds
            .map(|s| format!("{}s", s))
            .unwrap_or_else(|| "custom".to_string());

        table.add_row(vec![
            Cell::new(&job.name),
            Cell::new(&job.module),
            Cell::new(job.schedule.as_deref().unwrap_or("none")),
            Cell::new(interval_str),
            Cell::new(&job.instance),
        ]);
    }

    println!("{}\n", table);
    ExitCode::from(0)
}

async fn handle_indexers(root_opt: Option<&Path>) -> ExitCode {
    let installation = match build_installation_model(root_opt, false, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    println!("\n{} - Indexers Doctor\n", CALVER_VERSION.cyan().bold());

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Indexer ID").fg(Color::Cyan),
            Cell::new("View ID").fg(Color::Cyan),
            Cell::new("Title").fg(Color::Cyan),
            Cell::new("Module").fg(Color::Cyan),
        ]);

    for idx in &installation.indexers {
        table.add_row(vec![
            Cell::new(&idx.id),
            Cell::new(&idx.view_id),
            Cell::new(&idx.title),
            Cell::new(&idx.module),
        ]);
    }

    println!("{}\n", table);
    ExitCode::from(0)
}

async fn handle_db(root_opt: Option<&Path>) -> ExitCode {
    let installation = match build_installation_model(root_opt, false, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    println!("\n{} - Database Forensics\n", CALVER_VERSION.cyan().bold());
    println!("Declared tables: {}", installation.declared_schema.tables.len());

    let diff = mdoctor_db::reconcile_schemas(&installation.declared_schema, &installation.actual_schema);
    println!("Missing declared indexes: {}", diff.missing_indexes.len());
    println!("Orphan tables: {}", diff.orphan_tables.len());

    if !diff.missing_indexes.is_empty() {
        println!("\n{}", "Missing declared indexes:".yellow().bold());
        for (t, idx) in &diff.missing_indexes {
            println!("  • {}.{}", t, idx);
        }
    }

    if !installation.database_metrics.table_sizes.is_empty() {
        println!("\n{}", "Top tables by storage size:".bold());
        for t in installation.database_metrics.table_sizes.iter().take(10) {
            let mb = t.total_bytes / (1024 * 1024);
            println!("  • {:<35} {:>10} rows   {:>6} MB", t.table_name, t.row_count, mb);
        }
    }

    ExitCode::from(0)
}

fn handle_explain(rule_id: &str) {
    if let Some(exp) = get_rule_explanation(rule_id) {
        println!("\n{} [{}]\n", exp.title.bold().cyan(), exp.rule_id);
        println!("{}\n{}\n", "WHAT IS THIS?".bold().underline(), exp.what);
        println!("{}\n{}\n", "WHY DOES IT MATTER?".bold().underline(), exp.why_affected);
        println!("{}\n{}\n", "HOW DETECTION WORKS".bold().underline(), exp.detection_mechanism);
        println!("{}\n{}\n", "POTENTIAL FALSE POSITIVES".bold().underline(), exp.false_positives);
        println!("{}\n{}\n", "MANUAL VERIFICATION".bold().underline(), exp.verification.cyan());
        println!("{}\n{}\n", "REMEDIATION".bold().underline(), exp.remediation.green());
    } else {
        eprintln!("{}: No detailed explanation found for rule ID '{}'.", "Error".red().bold(), rule_id);
    }
}

async fn handle_snapshot_create(custom_root: Option<&Path>, output_path: Option<PathBuf>) -> ExitCode {
    let installation = match build_installation_model(custom_root, false, false, 60).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let findings = CrossAnalysisEngine::analyze(&installation);
    let health = HealthScore::calculate(&findings);

    let snapshot = DiagnosticSnapshot::new(installation, findings, health);
    let json = match snapshot.to_json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}: Failed to serialize snapshot: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let target_file = output_path.unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        PathBuf::from(format!("mdoctor-snapshot-{}.mdoctor", ts))
    });

    if let Err(e) = std::fs::write(&target_file, json) {
        eprintln!("{}: Failed to write snapshot to '{}': {}", "Error".red().bold(), target_file.display(), e);
        return ExitCode::from(3);
    }

    println!("\n{} Diagnostic snapshot saved safely to '{}'.", "✓".green().bold(), target_file.display().to_string().cyan());
    println!("Secrets were strictly sanitized. This file is safe to attach to GitHub or support tickets.\n");
    ExitCode::from(0)
}

fn handle_snapshot_analyze(file: &Path) -> ExitCode {
    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: Cannot read snapshot file '{}': {}", "Error".red().bold(), file.display(), e);
            return ExitCode::from(3);
        }
    };

    let snapshot = match DiagnosticSnapshot::from_json(&content) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: Invalid snapshot JSON: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    println!("\nAnalyzing Snapshot created at {}", snapshot.created_at);
    let report = render_terminal_report(&snapshot.installation, &snapshot.findings, &snapshot.health_score);
    println!("{}", report);
    ExitCode::from(0)
}

async fn handle_investigate(
    root_opt: Option<&Path>,
    symptom: Option<&str>,
    format: OutputFormat,
) -> ExitCode {
    let installation = match build_installation_model(root_opt, false, false, 60).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let ast_findings = scan_php_sources(&installation);
    let results = investigate_installation(&installation, &ast_findings, symptom);

    let output = match format {
        OutputFormat::Text | OutputFormat::Markdown => render_investigate_terminal(&results, symptom),
        OutputFormat::Json | OutputFormat::Sarif => {
            render_investigate_json(&results).unwrap_or_else(|e| format!("JSON error: {}", e))
        }
    };

    println!("{}", output);

    if results.iter().any(|r| r.impact_score >= 90) {
        ExitCode::from(2)
    } else if !results.is_empty() {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

async fn handle_redis(root_opt: Option<&Path>) -> ExitCode {
    let installation = match build_installation_model(root_opt, false, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    println!("\n{} - Redis & Valkey Deep Internals Forensics\n", CALVER_VERSION.cyan().bold());

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Instance").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Cyan),
            Cell::new("Version").fg(Color::Cyan),
            Cell::new("Used Memory").fg(Color::Cyan),
            Cell::new("Fragmentation").fg(Color::Cyan),
            Cell::new("Eviction Policy").fg(Color::Cyan),
            Cell::new("Evicted Keys").fg(Color::Cyan),
            Cell::new("Hit Ratio").fg(Color::Cyan),
        ]);

    let instances = [
        ("Default / Cache", &installation.runtime.redis_default),
        ("Session", &installation.runtime.redis_session),
    ];

    for (name, st) in &instances {
        let status_cell = if st.is_reachable {
            Cell::new("connected").fg(Color::Green)
        } else if st.is_configured {
            Cell::new("unreachable").fg(Color::Red)
        } else {
            Cell::new("not configured").fg(Color::DarkGrey)
        };

        let mem_str = st
            .used_memory_bytes
            .map(|b| format!("{} MB", b / (1024 * 1024)))
            .unwrap_or_else(|| "-".to_string());

        let frag_str = st
            .mem_fragmentation_ratio
            .map(|r| format!("{:.2}", r))
            .unwrap_or_else(|| "-".to_string());

        let evict_cell = match st.evicted_keys {
            Some(k) if k > 0 && *name == "Session" => Cell::new(k.to_string()).fg(Color::Red),
            Some(k) => Cell::new(k.to_string()),
            None => Cell::new("-"),
        };

        let hit_str = st
            .hit_ratio
            .map(|r| format!("{:.1}%", r * 100.0))
            .unwrap_or_else(|| "-".to_string());

        table.add_row(vec![
            Cell::new(name),
            status_cell,
            Cell::new(st.version.as_deref().unwrap_or("-")),
            Cell::new(mem_str),
            Cell::new(frag_str),
            Cell::new(st.maxmemory_policy.as_deref().unwrap_or("-")),
            evict_cell,
            Cell::new(hit_str),
        ]);
    }

    println!("{}\n", table);

    let collisions = mdoctor_runtime::check_redis_config(&installation.env_config);
    if !collisions.is_empty() {
        println!("{}", "CRITICAL REDIS CONFIGURATION CONCERN:".red().bold());
        for c in &collisions {
            println!("  • {:?}", c);
        }
        println!();
    }

    ExitCode::from(0)
}

async fn handle_fpc(root_opt: Option<&Path>) -> ExitCode {
    let installation = match build_installation_model(root_opt, false, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    println!("\n{} - Full Page Cache (FPC) & Varnish Forensics\n", CALVER_VERSION.cyan().bold());
    println!("FPC Engine: {}", installation.runtime.fpc.engine);
    println!("Varnish Reverse Proxy Reachable: {}", if installation.runtime.fpc.is_varnish_reachable { "YES".green() } else { "NO / NOT DETECTED".yellow() });

    let uncacheable = &installation.runtime.fpc.uncacheable_blocks;
    println!("Uncacheable Layout Blocks (cacheable=\"false\"): {}\n", uncacheable.len());

    if uncacheable.is_empty() {
        println!("{}", "✓ No storefront layout blocks found puncturing Full Page Cache.".green().bold());
    } else {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("Module").fg(Color::Cyan),
                Cell::new("Layout Handle").fg(Color::Cyan),
                Cell::new("Block Name").fg(Color::Cyan),
                Cell::new("Declaration Location").fg(Color::Cyan),
            ]);

        for b in uncacheable {
            table.add_row(vec![
                Cell::new(&b.module),
                Cell::new(&b.layout_handle),
                Cell::new(&b.block_name),
                Cell::new(format!("{}:{}", b.source_file.display(), b.line)),
            ]);
        }
        println!("{}\n", table);
        println!("{}", "WARNING: cacheable=\"false\" disables FPC for the entire page, forcing 100% dynamic rendering.".yellow().bold());
    }

    ExitCode::from(0)
}

async fn handle_fpm(root_opt: Option<&Path>) -> ExitCode {
    let installation = match build_installation_model(root_opt, false, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    println!("\n{} - PHP-FPM Worker Pool Forensics\n", CALVER_VERSION.cyan().bold());
    let fpm = &installation.runtime.php_workers;

    if !fpm.is_detected {
        println!("No active PHP-FPM pools detected in standard Linux socket/process paths.");
        return ExitCode::from(0);
    }

    println!("Pool: {}", fpm.pool_name.cyan().bold());
    println!("Process Manager: {}", fpm.process_manager);
    println!("Active Workers:  {}/{} ({:.1}% saturation)", fpm.active_workers, fpm.max_children, fpm.saturation_pct);
    println!("Idle Workers:    {}", fpm.idle_workers);
    println!("Listen Queue:    {}", fpm.listen_queue);
    println!("Max Children Hit Count: {}", fpm.max_children_reached);
    println!("Estimated Worker Footprint: {:.0} MB", fpm.estimated_worker_memory_mb);
    println!("Potential Pool Memory:      {:.0} MB", fpm.total_pool_memory_mb);

    if fpm.oom_risk {
        println!("\n{}", "CRITICAL: Pool memory exceeds host RAM capacity. Linux OOM-killer risk under traffic spikes!".red().bold());
    } else if fpm.saturation_pct > 85.0 {
        println!("\n{}", "WARNING: Worker saturation > 85%. Requests risk queuing or timing out with HTTP 504.".yellow().bold());
    } else {
        println!("\n{}", "✓ Worker pool operating within safe memory and concurrency bounds.".green().bold());
    }

    ExitCode::from(0)
}

async fn handle_opensearch(root_opt: Option<&Path>) -> ExitCode {
    let installation = match build_installation_model(root_opt, false, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    println!("\n{} - OpenSearch & Catalog Index Diagnostics\n", CALVER_VERSION.cyan().bold());
    let os = &installation.runtime.opensearch;

    if !os.is_configured && !os.is_reachable {
        println!("OpenSearch endpoint not configured or unreachable.");
        return ExitCode::from(0);
    }

    let status_cell = match os.status.as_deref() {
        Some("green") => "GREEN".green().bold(),
        Some("yellow") => "YELLOW".yellow().bold(),
        Some("red") => "RED (CRITICAL)".red().bold(),
        _ => "UNKNOWN".dimmed(),
    };

    println!("Cluster Name:      {}", os.cluster_name.as_deref().unwrap_or("unknown"));
    println!("Cluster Status:    {}", status_cell);
    println!("Nodes:             {}", os.number_of_nodes.unwrap_or(0));
    println!("Active Shards:     {}", os.active_shards.unwrap_or(0));
    println!("Unassigned Shards: {}", os.unassigned_shards.unwrap_or(0));
    println!("Catalog Index:     {}", if os.has_catalog_index { "PRESENT (OK)".green().bold() } else { "MISSING (catalogsearch_fulltext required)".red().bold() });

    ExitCode::from(0)
}

async fn handle_baseline_create(custom_root: Option<&Path>, output_path: Option<PathBuf>) -> ExitCode {
    let target_file = output_path.unwrap_or_else(|| PathBuf::from("mdoctor-baseline.json"));
    let installation = match build_installation_model(custom_root, false, false, 60).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let findings = CrossAnalysisEngine::analyze(&installation);
    let health = HealthScore::calculate(&findings);

    let snapshot = DiagnosticSnapshot::new(installation, findings, health);
    let json = match snapshot.to_json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}: Failed to serialize baseline: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    if let Err(e) = std::fs::write(&target_file, json) {
        eprintln!("{}: Failed to write baseline to '{}': {}", "Error".red().bold(), target_file.display(), e);
        return ExitCode::from(3);
    }

    println!("\n{} Baseline snapshot saved safely to '{}'.", "✓".green().bold(), target_file.display().to_string().cyan());
    println!("Store configuration, modules, and diagnostic findings were recorded for drift comparison.\n");
    ExitCode::from(0)
}

async fn handle_baseline_compare(
    custom_root: Option<&Path>,
    baseline_file: &Path,
    format: OutputFormat,
) -> ExitCode {
    let content = match std::fs::read_to_string(baseline_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: Cannot read baseline file '{}': {}", "Error".red().bold(), baseline_file.display(), e);
            return ExitCode::from(3);
        }
    };

    let baseline = match DiagnosticSnapshot::from_json(&content) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: Invalid baseline JSON in '{}': {}", "Error".red().bold(), baseline_file.display(), e);
            return ExitCode::from(3);
        }
    };

    let current_inst = match build_installation_model(custom_root, false, false, 60).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let current_findings = CrossAnalysisEngine::analyze(&current_inst);
    let current_health = HealthScore::calculate(&current_findings);
    let current_snapshot = DiagnosticSnapshot::new(current_inst, current_findings, current_health);

    let drift = compare_installations(&baseline, &current_snapshot);

    let output = match format {
        OutputFormat::Text => render_drift_terminal(&drift),
        OutputFormat::Json => render_drift_json(&drift).unwrap_or_else(|e| format!("JSON error: {}", e)),
        OutputFormat::Markdown => render_drift_markdown(&drift),
        OutputFormat::Sarif => render_sarif_report(&drift.findings_drift.new_findings),
    };

    println!("{}", output);

    if drift.has_regressions {
        if drift.max_regression_severity == Some(Severity::Critical) {
            ExitCode::from(2)
        } else {
            ExitCode::from(1)
        }
    } else {
        ExitCode::from(0)
    }
}

async fn handle_modules_impact(root_opt: Option<&Path>, filter: Option<&str>) -> ExitCode {
    let installation = match build_installation_model(root_opt, true, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let ast_findings = scan_php_sources(&installation);
    let mut impacts = calculate_all_modules_impact(&installation, &ast_findings);

    if let Some(filt) = filter {
        impacts.retain(|i| i.module_name.to_lowercase().contains(&filt.to_lowercase()));
    }

    let report = render_impact_table(&impacts);
    println!("{}", report);
    ExitCode::from(0)
}

async fn handle_module_uninstall_impact(root_opt: Option<&Path>, name: &str) -> ExitCode {
    let installation = match build_installation_model(root_opt, true, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let analysis = match calculate_uninstall_impact(&installation, name) {
        Some(a) => a,
        None => {
            eprintln!("{}: Module '{}' not found in this installation.", "Error".red().bold(), name);
            return ExitCode::from(1);
        }
    };

    let report = render_uninstall_terminal(&analysis);
    println!("{}", report);

    if analysis.safety == mdoctor_core::UninstallSafety::Blocked {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

async fn handle_module_graph(root_opt: Option<&Path>, name: &str, format: GraphFormat) -> ExitCode {
    let installation = match build_installation_model(root_opt, true, false, 30).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::from(3);
        }
    };

    let module = match installation.find_module(name) {
        Some(m) => m,
        None => {
            eprintln!("{}: Module '{}' not found in this installation.", "Error".red().bold(), name);
            return ExitCode::from(1);
        }
    };

    match format {
        GraphFormat::Mermaid => {
            let diagram = render_mermaid_graph(module, &installation);
            println!("{}", diagram);
        }
    }

    ExitCode::from(0)
}
