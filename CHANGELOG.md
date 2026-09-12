# Changelog

All notable changes to **Magento Doctor** (`mdoctor`) are documented in this file.
This project follows [CalVer](https://calver.org) (`YYYY.MM.DD`) release versioning.

## [v2026.09.12] - 2026-09-12

### 🚀 New Features (Runtime Forensics)

- **Root Cause `investigate` Engine**:
  - `mdoctor investigate [symptom]`: correlates runtime metrics, query digests, lock waits, FPC punctures and AST static analysis into causal failure chains.
  - Confidence, impact score, title and summary are **derived from the signals actually measured**. Each result lists its `evidence_basis`, so a diagnosis built on one static config check cannot present itself as a corroborated runtime finding. Only a multi-signal, high-confidence result reaches the critical (>= 90) impact band.
  - Terminal causal flow tree, symptom filtering, and `--json` output.
  - `mdoctor why` now runs the causal investigation engine.
- **MySQL Runtime Forensics & Query Correlation**:
  - `performance_schema.events_statements_summary_by_digest` inspection, filtered to the store's own schema so a shared MySQL server's other workloads are not blamed on Magento modules.
  - Lock waits come from `performance_schema.data_lock_waits` joined to `innodb_trx`, so the **blocking** transaction is identified, not just the blocked one.
  - Query fingerprint → code correlation mapping SQL table access back to declarative schemas and owning modules.
  - Rules: `MD-SQL-001` (high latency digest), `MD-SQL-002` (confirmed lock wait), `MD-SQL-003` (long-running statement).
- **Redis & Valkey Deep Analysis** (`mdoctor redis`):
  - RESP probe issuing `AUTH`, `INFO` and `CONFIG GET maxmemory*` under a single deadline. Passwords come from `env.php`, `--redis-password`, or `MDOCTOR_REDIS_PASSWORD`.
  - Memory usage, fragmentation ratio, eviction counters, keyspace hit ratio, and eviction-policy safety for the session store.
  - Rules: `MD-RDS-001` (session store can evict live sessions), `MD-RDS-002` (memory pressure / fragmentation), `MD-RDS-003` (low cache hit ratio).
- **Storefront FPC & Varnish Forensics** (`mdoctor fpc`):
  - Scans module layout XML (`view/frontend/layout`, `view/base/layout`, recursively) **and theme overrides** under `app/design/frontend`, where `cacheable="false"` most often hides.
  - Varnish is probed over HTTP and identified from `Via` / `X-Varnish` / `Server` headers; `X-Magento-Cache-Debug` and `Age` are reported.
  - Rule: `MD-FPC-001` (storefront FPC puncture), deduplicated across module and theme declarations.
- **PHP-FPM Worker Saturation & OOM Diagnostics** (`mdoctor fpm`):
  - Reads PHP-FPM's own status page (`pm.status_path`), locally or on a remote node, for a true active-worker count, listen queue depth, `max children reached` and slow-request counters.
  - Local `/proc` fallback measures real worker RSS instead of assuming a fixed footprint.
  - Rules: `MD-FPM-001` (worker pool saturation / queue buildup), `MD-FPM-002` (pool memory exceeds host RAM).
- **OpenSearch / Elasticsearch Diagnostics** (`mdoctor opensearch`):
  - Cluster health, node and shard counts, version, and catalog index presence matched **prefix-agnostically**, since `elasticsearch_index_prefix` is configurable.
  - Rules: `MD-SRC-001` (cluster degraded), `MD-SRC-002` (single-node cluster has no replica redundancy, informational), `MD-SRC-003` (no catalog search index present).
- **Clustered & Jump-Host Support**:
  - Every probed service can be pointed anywhere: `--varnish`, `--storefront-url`, `--fpm-status`, `--fpm-conf`, `--nginx-status`, `--redis-cache`, `--redis-session`, `--redis-page-cache`, `--opensearch`.
  - An `mdoctor.toml` in the Magento root (or `--config <file>`) describes the whole topology once; flags override it per run. See `mdoctor.toml.example`.
  - Credentials via `MDOCTOR_REDIS_PASSWORD` and `MDOCTOR_OPENSEARCH_AUTH`, never serialized into a report, snapshot or baseline.
  - New `mdoctor nginx` telemetry via `stub_status` for correlating web-tier pressure with PHP-FPM.
  - Malformed or unreachable endpoints are reported explicitly; mdoctor never silently falls back to probing localhost.

### 🩺 Diagnostic Accuracy

Measurements that were never taken are now `None` rather than a default, and every probe records why it failed. This removes several classes of confidently-wrong finding:

- **Varnish is no longer inferred from an open TCP port.** The previous probe treated any accepted connection on 6081 *or port 80* as a live Varnish, so every host running nginx or Apache was reported as a Varnish tier. Detection now requires a Varnish response header, and "configured for Varnish" comes from `env.php` `http_cache_hosts` rather than from the probe.
- **PHP-FPM metrics are no longer invented.** `pm.max_children` previously defaulted to 20 when no pool config existed, so `is_detected` was always true and hosts with no PHP-FPM at all reported a pool — and, on hosts under ~3.7GB of RAM, a critical OOM risk for software that was not installed. Detection now requires a real pool config or a live process.
- **Saturation findings require the FPM scoreboard.** A `/proc` scan counts a worker blocked on MySQL as idle, so `MD-FPM-001` no longer fires on `/proc`-derived numbers; the reported metric source says which is in use. `listen_queue` is read from the status page instead of being hardcoded to 0.
- **`MD-RDS-001` no longer flags Adobe's documented session policy.** Any policy other than exactly `noeviction` previously raised a Critical, including `volatile-lru`. Magento TTLs every session key, so only `allkeys-*` can discard a live session. Eviction counts are attributed to sessions only on a dedicated instance, since `evicted_keys` is server-wide.
- **Replication threads are no longer reported as lock waits.** The processlist sweep matched `TIME > 3`, and `Binlog Dump` / `Daemon` / event-scheduler threads sit at `TIME` = server uptime, so every replica reported a multi-day lock wait. Those commands and system users are now excluded, along with mdoctor's own connection.
- **Single-node OpenSearch is no longer permanently "degraded".** A one-node cluster is always yellow because replica shards cannot be assigned; that is now `MD-SRC-002` (informational) rather than a standing warning.
- **A failed probe is no longer read as a negative result.** HTTP probes check the status code and read the full response under one overall deadline, with chunked-encoding support. A `401` from a secured cluster, or a slow first byte, previously produced an empty body that was parsed as "no data" while still being marked reachable — reporting a healthy cluster as degraded with a missing index.
- **Digests are scoped to the store's schema**, and `performance_schema`/lock collection failures are recorded, so an empty result from a disabled `performance_schema` or a missing grant is no longer indistinguishable from a clean system.
- `EXPLAIN` verification commands no longer paste a digest containing `?` placeholders, which is not runnable SQL.
- `explain` now covers every rule the forensics engine can emit (`MD-SQL-003`, `MD-RDS-002`, `MD-RDS-003`, `MD-FPM-002`, `MD-SRC-002`, `MD-SRC-003` were missing), and the false-positive notes describe the real limits of each rule.

### 🐛 Fixes

- **CI**: the GitHub composite action aborted on mdoctor's own exit codes. Composite steps run under `bash -e`, so a scan that found critical issues killed the step before the `fail-on` threshold was evaluated, making `fail-on: none` fail the job with exit code 2.
- `parse_php_fpm_conf` no longer merges every `[pool]` section into one map (an admin pool's `pm.max_children` could masquerade as the web pool's) and now strips inline comments, so `pm.max_children = 50 ; peak` parses.
- `/proc` worker counting excludes the PHP-FPM master process and reads process state from after the final `)` in `stat`, so a comm field containing spaces cannot corrupt it.
- Causal-chain column alignment: `{:<15}` padding was applied to an already-coloured string, counting the ANSI escape bytes.
- `mdoctor redis` prints configuration issues as prose rather than `{:?}` struct debug output, and names the endpoint probed plus the reason any probe failed.

### ⚠️ Behaviour Changes

- `mdoctor why` previously always exited 0. It now runs the investigation engine and exits 1 when results are found, or 2 when one reaches critical impact. Scripts that ignored its exit code should be checked.
- `PhpWorkerMetrics`, `FpcProbeStatus`, `RedisStatus`, `OpenSearchStatus` and `ActiveLockWait` gained fields and changed several to `Option`. Baselines and snapshots from v2026.09.06 still load; newly-optional fields read as absent.

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
