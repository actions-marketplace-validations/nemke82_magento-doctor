# Changelog

All notable changes to **Magento Doctor** (`mdoctor`) are documented in this file.
This project follows [CalVer](https://calver.org) (`YYYY.MM.DD`) release versioning.

## [v2026.09.12] - 2026-09-12

### 🚀 New Features (Runtime Forensics)
- **Root Cause `investigate` Engine**:
  - `mdoctor investigate [symptom]`: Synthesizes multi-dimensional causal failure chains connecting code defects, layout misconfigurations, database lock contention, and runtime saturation to real store symptoms (e.g. checkout latency, high CPU, FPC misses).
  - Produces prioritized remediation workflows with immediate mitigations and long-term architectural fixes.
  - Terminal causal flow tree formatting (`──> CAUSED BY ──> TRIGGERED BY`), interactive symptom filtering, and `--json` machine-readable output.
  - Upgraded `mdoctor why` command to execute the causal investigation engine.
- **MySQL Runtime Forensics & Query Correlation**:
  - Real-time `performance_schema.events_statements_summary_by_digest` live query inspection: captures slow query digests, execution counts, average latency, and rows examined.
  - Active lock wait and connection pool inspection via `information_schema.processlist` and `Threads_connected`.
  - Query fingerprint → code correlation engine: automatically maps SQL table access patterns back to declarative XML schemas and responsible custom/vendor Magento modules and PHP classes.
  - Rules: `MD-SQL-001` (Slow query digest exceeding threshold), `MD-SQL-002` (Excessive lock wait contention).
- **Redis & Valkey Deep Analysis**:
  - `mdoctor redis`: Real-time RESP async probe with non-blocking commands (`INFO`, `CONFIG GET`) and strict 1-second timeouts.
  - Deep telemetry: memory usage, fragmentation ratio (`used_memory_rss / used_memory`), eviction rates, keyspace hit ratio, and session eviction policy safety verification (`maxmemory-policy != noeviction` warning on session db).
  - Rules: `MD-RDS-001` (High Redis memory fragmentation > 1.5), `MD-RDS-002` (Active key evictions), `MD-RDS-003` (Dangerous session store eviction policy).
- **Storefront FPC & Varnish Forensics**:
  - `mdoctor fpc`: Scans storefront layout XML files (`view/frontend/layout`, `view/base/layout`) for uncacheable blocks (`cacheable="false"`).
  - Pinhole detection: pinpoints blocks puncturing Full Page Cache on critical high-traffic catalog and content routes (`catalog_product_view`, `catalog_category_view`, `cms_index_index`, etc.).
  - Reverse proxy Varnish reachability probe (`Via`, `X-Magento-Cache-Debug`, `Age` headers).
  - Rule: `MD-FPC-001` (Storefront Full Page Cache puncture by uncacheable layout block).
- **PHP-FPM Worker Saturation & OOM Diagnostics**:
  - `mdoctor fpm`: Inspects PHP-FPM process pool status (active vs idle processes, max children reached count, listen queue depth).
  - Calculates process memory footprint and alerts on potential Out-Of-Memory (OOM) risk under peak traffic.
  - Rules: `MD-FPM-001` (PHP-FPM worker pool saturation), `MD-FPM-002` (Listen queue backlog / request drops).
- **OpenSearch / Elasticsearch Diagnostics**:
  - `mdoctor opensearch` (aliases: `mdoctor open-search`, `mdoctor search`): Inspects cluster health status (`green`, `yellow`, `red`), unassigned shards count, node count, and verifies Magento catalog search index presence.
  - Rule: `MD-SRC-001` (OpenSearch cluster degraded or missing catalog index).

---

## [v2026.09.06] - 2026-09-06

### 🚀 New Features (v0.2 Capabilities)
- **Configuration Drift & Baseline Comparison**:
  - `mdoctor baseline create [--output <path>]`: Serializes complete store configuration, modules, declared schemas, and findings into a safe, sanitized baseline snapshot.
  - `mdoctor compare <baseline.json> [--format text|json|markdown|sarif]`: Detects store drift, version shifts, added/removed modules, schema changes, and new diagnostic regressions.
  - Deterministic CI exit codes: `2` on critical regressions, `1` on warnings, `0` on pass.
- **Module Architectural Risk & Impact Scoring**:
  - `mdoctor modules --impact` (and `mdoctor impact`): Scans custom and third-party extensions and ranks them by performance drag and risk (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Evaluates hotpath interceptions, around plugin stack depth, minutely crons, core preferences, and AST cost indicators.
- **Module Uninstall Blast-Radius Forensics**:
  - `mdoctor module <Name> --uninstall-impact`: Evaluates sequence breaks (`[BLOCKED]`), orphaned custom database tables/columns (`[CAUTION]`), and generates an ordered safe removal checklist.
- **Mermaid.js Architecture Graph Generator**:
  - `mdoctor module <Name> --graph mermaid`: Visualizes extension touchpoints (sequence dependencies, plugins, observers, cron jobs, database tables) in standard Mermaid `flowchart TD` format.
- **GitHub Action PR Reviewer**:
  - Added official composite [action.yml](action.yml) for GitHub Actions CI/CD workflows.
  - Added sample pull-request workflow in `.github/workflows/pr-review.yml` for automated SARIF security and diagnostic code scanning.

### 🛠️ Improvements & Fixes (MVP Refinements)
- **Redis Multi-Instance Hostname Differentiation**:
  - Upgraded Redis parser to extract `host`, `server`, `port`, and `path`.
  - Same database numbers across different Redis hosts, ports, or sockets no longer trigger false-positive collision warnings.
- **Enhanced N+1 Repository Load Diagnostics (`MD-PERF-021`)**:
  - Attached exact file path (`File: path/to/Class.php:line`) to AST findings.
  - Added entity type detection (Category, Product, Order) and concrete copy-pasteable batch-loading recommendations (`CollectionFactory` / `SearchCriteriaBuilder`).
- **Core Magento Preference Filtering (`MD-DI-001`)**:
  - Filtered core Magento modules (`Magento_*`, `vendor/magento/*`) from preference anti-pattern warnings. Only custom and 3rd-party modules are evaluated.
  - Excluded vanilla core plugins from `MD-PLG-001` and `MD-PLG-005`.
- **Zero-Secret Exposure Guarantee**:
  - All database passwords, crypt keys, and Redis auth strings are strictly redacted (`SecretValue::Present`), preventing leakage in snapshots or terminal output.

---

## [v2026.08.26] - 2026-08-26

### Initial Release
- Initial release of Magento Doctor diagnostic engine.
- Zero-configuration discovery for Magento Open Source and Adobe Commerce.
- Tree-sitter PHP AST static analysis without PHP runtime dependencies.
- Declarative database schema reconciliation (`db_schema.xml` vs MySQL).
- Cron schedule forensics and overlap ratio analysis.
- Multi-format reporting: ANSI Terminal, JSON, Markdown, and SARIF.
