# Magento Doctor (`mdoctor`)

<p align="center">
  <strong>Deep diagnostics, static analysis and performance forensics for Magento 2.</strong>
</p>

<p align="center">
  <a href="https://github.com/nemke82/magento-doctor/actions/workflows/ci.yml"><img src="https://github.com/nemke82/magento-doctor/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://nemke82.github.io/magento-doctor/"><img src="https://img.shields.io/badge/docs-interactive_site-00f0ff.svg" alt="Documentation" /></a>
  <a href="https://github.com/nemke82/magento-doctor/releases"><img src="https://img.shields.io/badge/release-v2026.09.12-blue.svg" alt="Release" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/Rust-1.75+-orange.svg" alt="Rust 1.75+" />
  <img src="https://img.shields.io/badge/Magento-2.4.4_--_2.4.9-orange.svg" alt="Magento 2.4.4 - 2.4.9" />
</p>

<p align="center">
  🌐 <strong>Interactive Web Showcase & Rule Explorer</strong>: <a href="https://nemke82.github.io/magento-doctor/">https://nemke82.github.io/magento-doctor/</a>
</p>

> [!TIP]
> **Live Interactive Documentation & Forensics Simulator**:  
> Explore live terminal command outputs, search the diagnostic rule catalog, and view the certified stack matrix on our GitHub Pages site:  
> 👉 **[https://nemke82.github.io/magento-doctor/](https://nemke82.github.io/magento-doctor/)**

---

Magento Doctor is much more than a health checker. Rather than dumping 150 disconnected warnings, Magento Doctor understands how a Magento installation is assembled and correlates code, configuration, database schema, runtime state, logs, cron/indexer behavior, and third-party modules into an **engineer-grade diagnosis**.

```text
Collectors
    ↓
Normalized Installation Model (MagentoInstallation)
    ↓
Cross-Analysis Correlation Engine & Investigation Matrix
    ↓
Evidence-First Diagnosis, Causal Chains & Prescriptions
```

Every analyzer operates against a normalized internal representation of the store rather than grep heuristics. This allows Magento Doctor to correlate facts across different subsystems to answer critical questions:

- *Does this third-party module define an around plugin on a checkout hot path that makes synchronous HTTP calls?*
- *Does a vendor cron job run every minute while having an observed median runtime of 74 seconds, creating an overlap storm?*
- *Does a collection loop execute N+1 repository loads (`$repo->getById()`) inside a loop?*
- *Which storefront layout files declare `cacheable="false"` and silently destroy Full Page Caching across the store?*
- *Is the Redis session store configured with an eviction policy that silently drops customer shopping carts?*

---

## Example Output

```text
Magento Doctor v2026.09.12

Magento Open Source 2.4.7-p3
Mode: production
PHP: 8.3.26
Database Host: 127.0.0.1
Modules: 312 enabled / 17 disabled
Third-party modules: 84

Overall Health: 71 / 100

CRITICAL   3
WARNING   14
INFO      22

Primary concerns

[CRITICAL] Cron backlog and overlap storm detected (MD-CRON-010)
  18,431 rows in cron_schedule
  1,922 jobs are pending beyond their expected execution window.
  87 jobs are stuck in "running".
  Oldest running job: vendor_export_feed — 3h 17m

  Evidence / Correlation:
    Vendor_Feed defines vendor_export_feed in etc/crontab.xml.
    Schedule interval: 60 seconds.
    Median runtime observed: 74 seconds.
    Overlap ratio: 1.23 (HIGH probability of overlapping executions)
    AST static analysis detected costly operations inside this job:
      - Repository Load at line 21 ($this->productRepository->getById())
      - Synchronous HTTP Request at line 28 (curl_exec())

  Impact:
    Jobs overlap faster than they complete, compounding MySQL load,
    exhausting PHP workers, and delaying core Magento indexer cron jobs.

  Recommendation:
    Reduce frequency in etc/crontab.xml, prevent overlap, move remote calls
    to queue, or optimize Vendor\Feed\Cron\Export::execute().

[CRITICAL] Around plugin on checkout hot path (MD-PLG-001)
  Plugin 'vendor_payment_quote_around' intercepts hot path 'Magento\Quote\Model\QuoteManagement'
  using an around wrapper in module 'Vendor_Payment'.

  Evidence / Correlation:
    Plugin class: Vendor\Payment\Plugin\QuoteManagement
    Intercepts: Magento\Quote\Model\QuoteManagement::submit()
    Plugin type: around (sortOrder: 10)
    Source: app/code/Vendor/Payment/etc/di.xml:4
    AST static analysis detected costly operations inside this plugin:
      - Synchronous HTTP Request at line 13 ($this->client->request())

  Impact:
    Blocking external HTTP requests during order placement directly degrades
    checkout conversion and locks customer quotes.

  Recommendation:
    Refactor around plugin to 'before' or 'after' plugin, avoid synchronous network calls,
    and ensure $proceed() is called cleanly.
```

---

## Installation

### Option 1: Download Standalone Binary (Recommended)

Pre-compiled standalone binaries are available for Linux, macOS, and Windows. No PHP, Composer, or runtime dependencies required:

```bash
# Linux (x86_64)
curl -sSL https://github.com/nemke82/magento-doctor/releases/latest/download/mdoctor-linux-amd64 -o /usr/local/bin/mdoctor
chmod +x /usr/local/bin/mdoctor

# Linux (musl static binary)
curl -sSL https://github.com/nemke82/magento-doctor/releases/latest/download/mdoctor-linux-amd64-musl -o /usr/local/bin/mdoctor
chmod +x /usr/local/bin/mdoctor

# macOS (Apple Silicon arm64)
curl -sSL https://github.com/nemke82/magento-doctor/releases/latest/download/mdoctor-macos-arm64 -o /usr/local/bin/mdoctor
chmod +x /usr/local/bin/mdoctor
```

Verify installation:
```bash
mdoctor --version
# Output: mdoctor v2026.09.12
```

### Option 2: Cargo Install

```bash
cargo install --git https://github.com/nemke82/magento-doctor mdoctor-cli
```

### Option 3: Build From Source

```bash
git clone https://github.com/nemke82/magento-doctor.git
cd magento-doctor
cargo build --release
sudo cp target/release/mdoctor /usr/local/bin/
```

---

## Zero-Configuration Discovery

Magento Doctor automatically discovers the root directory by searching upward from your current working directory for `app/etc/env.php`, `config.php`, `composer.json`, and `bin/magento`:

```bash
cd /var/www/html/magento
mdoctor scan
```

This covers a single-server install. For a clustered store, or a run from a jump host, point mdoctor at each service explicitly — see [Clustered Stores & Jump-Host Runs](#clustered-stores--jump-host-runs).

You can also specify an explicit directory via `--root` or the `MAGENTO_ROOT` environment variable:
```bash
mdoctor --root /var/www/magento scan
# or
MAGENTO_ROOT=/var/www/magento mdoctor scan
```

---

## Commands & Usage

| Command | Description |
|---|---|
| `mdoctor investigate [symptom]` | Multi-dimensional root cause engine synthesizing telemetry into causal failure chains |
| `mdoctor scan` | Run full comprehensive scan across code, configuration, database schema, and cron |
| `mdoctor doctor` | Fast operational health check highlighting critical blockages |
| `mdoctor fpc` | Full Page Cache (FPC), Varnish reachability, and layout `cacheable="false"` audit |
| `mdoctor redis` | Redis & Valkey deep internals: memory, fragmentation, eviction policy & hit ratios |
| `mdoctor fpm` | PHP-FPM worker saturation gauge, process manager, listen queue & OOM risk |
| `mdoctor opensearch` | OpenSearch cluster health, shard allocation, and catalog search index status |
| `mdoctor nginx` | Nginx web-tier active connections, request rate, and dropped connections via `stub_status` |
| `mdoctor baseline create` | Export current store state as a baseline for drift comparison |
| `mdoctor compare <baseline>` | Compare store against baseline to detect configuration drift and regressions |
| `mdoctor modules` | Module inventory, classification, and integration footprint metrics |
| `mdoctor modules --impact` | Rank installed extensions by architectural risk and performance impact |
| `mdoctor impact` | Fast alias to rank installed extensions by architectural risk and performance impact |
| `mdoctor module <Vendor_Module>` | Deep inspection of a specific module's plugins, observers, crons, and schema |
| `mdoctor module <Name> --uninstall-impact` | Forensic blast-radius check for sequence breaks and orphaned DB tables |
| `mdoctor module <Name> --graph mermaid` | Export visual architecture diagram in Mermaid.js flowchart syntax |
| `mdoctor cron` | Cron forensics, schedule frequency, overlap risk, and backlog analysis |
| `mdoctor indexers` | Indexer and MView changelog status, backlog, and schedule mode |
| `mdoctor db` | Declarative schema reconciliation, missing/redundant indexes, table sizes |
| `mdoctor explain <RULE_ID>` | In-depth engineering explanation with manual verification commands |
| `mdoctor snapshot create` | Export sanitized store snapshot safe for sharing in GitHub issues |
| `mdoctor snapshot analyze <file>` | Analyze an exported snapshot offline |
| `mdoctor why [symptom]` | Fast triage alias for `mdoctor investigate` |

---

### Root Cause Investigation Engine (`mdoctor investigate`)

Unlike traditional scanners that emit dozens of isolated warnings, `mdoctor investigate` combines MySQL performance schema digests, Redis memory telemetry, PHP worker queue status, FPC layout punctures, and AST code analysis to produce **actionable causal chains**:

```bash
# Auto-diagnose primary production failure modes
mdoctor investigate

# Focus on specific symptoms
mdoctor investigate 504
mdoctor investigate checkout
mdoctor investigate fpc
mdoctor investigate search
```

```text
═══ MAGENTO DOCTOR: ROOT CAUSE INVESTIGATION ═══
Multi-dimensional root-cause correlation across Runtime, Database, Cache, and Code

┌──────────────────────────────────────────────────────────────────────────────┐
│ [ROOT CAUSE #1] Synchronous External Network Calls Intercepting Checkout Hot Path
│ HIGH CONFIDENCE | IMPACT: 96/100 (CRITICAL)
├──────────────────────────────────────────────────────────────────────────────┤
│ Summary:
│   A custom extension intercepts the Magento order placement transaction with
│   an around plugin that executes synchronous external HTTP requests, freezing checkout.
│
│ Causal Chain (Observed Symptom ➔ Culprit):
│   [Symptom]   Storefront Checkout Slow or timing out quote submission during checkout
│        ⬇
│   [Culprit]   Vendor_Payment  Around plugin 'vendor_payment_quote_around' makes
│                               synchronous HTTP call ($this->client->request()) at di.xml:13
│
│ Implicated Modules: Vendor_Payment
│
│ Recommended Action Plan:
│   1. Refactor around plugin 'vendor_payment_quote_around' to execute network calls asynchronously.
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│ [ROOT CAUSE #2] Storefront Full Page Cache Punctured by Custom Layout XML Declarations
│ HIGH CONFIDENCE | IMPACT: 95/100 (CRITICAL)
├──────────────────────────────────────────────────────────────────────────────┤
│ Summary:
│   A third-party extension includes cacheable="false" in a catalog layout file,
│   destroying edge caching and forcing full PHP compilation on every page hit.
│
│ Causal Chain (Observed Symptom ➔ Culprit):
│   [Symptom]   Full Page Cache 1 storefront layout block(s) explicitly declare cacheable="false"
│        ⬇
│   [Culprit]   Vendor_Feed     Block 'vendor.feed.tracker' in catalog_product_view disables page caching
│
│ Implicated Modules: Vendor_Feed
│
│ Recommended Action Plan:
│   1. Remove cacheable="false" from vendor.feed.tracker in catalog_product_view.xml.
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### Deep Runtime Diagnostics

Inspect each layer of your Magento 2 infrastructure with dedicated forensic tools:

```bash
# Full Page Cache & Varnish layout puncture audit
mdoctor fpc

# Redis & Valkey deep internals (memory fragmentation, eviction policy, keyspace hits)
mdoctor redis

# PHP-FPM worker pool pressure, listen queues, and host OOM risk
mdoctor fpm

# OpenSearch cluster health, shard unallocations, and catalog index presence
mdoctor opensearch

# Nginx web-tier active connections, request rate, and dropped connections
mdoctor nginx
```

### Clustered Stores & Jump-Host Runs

On a single-server install, mdoctor finds everything itself from `app/etc/env.php` and the local host. On a cluster — or when you run from a jump host — PHP-FPM, Varnish, Nginx, Redis and OpenSearch each live somewhere else, so tell mdoctor where to look:

```bash
mdoctor investigate \
  --varnish       varnish-1.internal:6081 \
  --fpm-status    http://web-1.internal/status \
  --nginx-status  http://web-1.internal/nginx_status \
  --redis-cache   cache-1.internal:6379 \
  --redis-session session-1.internal:6379 \
  --opensearch    search-1.internal:9200
```

Rather than repeating those flags, commit an `mdoctor.toml` to the Magento root (see [`mdoctor.toml.example`](mdoctor.toml.example)). It is picked up automatically, and individual flags still override it for a one-off run:

```toml
[endpoints]
varnish          = { host = "varnish-1.internal", port = 6081 }
fpm_status_url   = { host = "web-1.internal", port = 80, path = "/status?json" }
nginx_status_url = { host = "web-1.internal", port = 80, path = "/nginx_status" }
redis_cache      = { host = "cache-1.internal", port = 6379 }
redis_session    = { host = "session-1.internal", port = 6379 }
opensearch       = { host = "search-1.internal", port = 9200 }
```

```bash
mdoctor fpm --config /etc/mdoctor/prod.toml
```

**Credentials** come from the environment so they stay out of shell history and out of the repo. mdoctor never writes them into a report, snapshot or baseline:

```bash
export MDOCTOR_REDIS_PASSWORD='...'
export MDOCTOR_OPENSEARCH_AUTH='admin:...'
mdoctor redis
```

Notes on what each endpoint buys you:

| Flag | Why it matters |
|---|---|
| `--fpm-status` | The PHP-FPM status page is the **only** source of a true active-worker count and listen queue depth, so `MD-FPM-001` needs it. Set `pm.status_path` in the pool config and expose it to your management network. A `/proc` scan counts a worker blocked on MySQL as idle, so mdoctor deliberately will not raise a saturation finding from one. |
| `--varnish` / `--storefront-url` | Varnish is identified from the `Via`, `X-Varnish` and `Server` response headers, never from an open port — port 80 on a Magento host is nginx or Apache. If only the public storefront is reachable, `--storefront-url` reads the same headers through it. |
| `--redis-cache` / `--redis-session` | Probed separately so `evicted_keys`, a **server-wide** counter, is only attributed to sessions when they have their own instance. |
| `--opensearch-auth` | Without credentials a secured cluster answers `401`, which mdoctor reports as a failed probe rather than as a degraded or empty cluster. |
| `--nginx-status` | `stub_status` counters (active connections, dropped connections) for correlating web-tier pressure with PHP-FPM. |

mdoctor speaks plain HTTP only; tunnel TLS endpoints over SSH rather than pointing it at `https://`. A malformed or unreachable endpoint is reported explicitly — it never silently falls back to probing localhost.

### Configuration Drift & Baseline Comparison

Track store evolution, detect unauthorized configuration drift, and catch regressions before and after production deployments:

```bash
# 1. Create a baseline snapshot before deploying or upgrading
mdoctor baseline create --output mdoctor-baseline.json

# 2. Deploy your changes or update extensions...

# 3. Compare current state against baseline
mdoctor compare mdoctor-baseline.json

# Exit code 2 is returned on critical regressions / severe health drop; exit code 0 on pass!
```

---

### Extension Architectural Risk & Impact Scoring

Rank extensions by runtime drag, checkout hot-path interception, around plugin stack depth, minutely crons, and AST cost indicators:

```bash
mdoctor modules --impact
```

---

### Forensic Uninstall Blast-Radius Analysis

Before disabling or removing an extension, check whether other active modules depend on it via `<sequence>`, and see which custom tables or columns will be orphaned:

```bash
mdoctor module Vendor_Feed --uninstall-impact
```

---

### Architecture Diagram Export (Mermaid.js)

Generate visual diagrams of any extension's touchpoints, plugins, observers, and tables directly into GitHub Markdown or Mermaid Live Editor:

```bash
mdoctor module Vendor_Feed --graph mermaid
```

---

### GitHub Action & CI Integration

Automate Magento health checks and pull request reviews using the official GitHub Action:

```yaml
name: Magento Doctor Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: nemke82/magento-doctor@main
        with:
          command: scan
          format: sarif
          output-file: results.sarif
          fail-on: critical

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

### Deep Scans & CI Reporting

```bash
# Offline mode (CI / Source repos without live MySQL)
mdoctor scan --offline

# Deep scan with extended budget for larger stores
mdoctor scan --deep --budget 120

# Machine-readable JSON output
mdoctor scan --format json

# Markdown report
mdoctor scan --format markdown

# GitHub Code Scanning SARIF format
mdoctor scan --format sarif > results.sarif
```

### Investigating Rules (`mdoctor explain`)

Every diagnosis is backed by factual evidence and transparent heuristics. View the complete engineering explanation and manual verification SQL queries:

```bash
mdoctor explain MD-PERF-021
```

```text
N+1 Repository Access in Collection Loop [MD-PERF-021]

WHAT IS THIS?
A repository load (e.g. $productRepository->getById()) is executed inside a foreach/while loop over a collection.

WHY DOES IT MATTER?
Calling getById() inside a loop causes Magento to execute a fresh database query (and multiple EAV joins) for every single item in the collection. For 1,000 items, this triggers 1,000 distinct SQL queries instead of 1 batched query.

HOW DETECTION WORKS
Tree-sitter PHP AST analysis walks the syntax tree, tracks loop depth, and flags member call expressions on repository instances within loop blocks.

POTENTIAL FALSE POSITIVES
Very low. In rare cases, a loop with a hardcoded limit of 1 or 2 iterations might trigger a warning.

MANUAL VERIFICATION
Inspect the flagged source file and line number. Enable MySQL query logging or Magento DB profiler during that execution.

REMEDIATION
Add required attributes directly to the parent collection using ->addAttributeToSelect(), or use SearchCriteriaBuilder with an 'in' filter to load all required entities in one round-trip.
```

---

## Diagnostic Snapshots

Need to share diagnostic state with team members, hosting support, or attached to a GitHub issue? `mdoctor snapshot create` exports a complete, sanitized representation of the store:

```bash
mdoctor snapshot create --output customer_audit.mdoctor
```

You can then inspect the snapshot on any machine without access to the customer's server:
```bash
mdoctor snapshot analyze customer_audit.mdoctor
```

---

## Safety & Confidentiality Guarantees

- **Zero Exposure of Secrets**: Database passwords, crypt keys, Redis passwords, RabbitMQ credentials, and authorization headers are never logged, printed, or saved. The normalized model maps them strictly as `SecretValue::Present` or `SecretValue::Missing`.
- **Safe Read-Only Operations**: All default collectors run non-locking, read-only queries with strict timeouts. Intrusive operations (`EXPLAIN ANALYZE`) require explicit opt-in.
- **100% Local & Air-Gapped**: Zero telemetry, zero external network calls, zero AI API dependencies. Your code and database metadata never leave your infrastructure.

---

## Rule Catalog Taxonomy

| Category | Prefix | Focus Area |
|---|---|---|
| **Environment** | `MD-ENV-*` | PHP version compatibility, CLI vs Web version mismatches |
| **Magento Core**| `MD-MAG-*` | Core integrity, deployment mode |
| **Modules**     | `MD-MOD-*` | Inconsistent modules, sequence circularities |
| **Dependency Injection** | `MD-DI-*` | Core concrete class replacement, direct `ObjectManager` |
| **Plugins**     | `MD-PLG-*` | Around plugins on hot paths, duplicate `sortOrder` |
| **Events**      | `MD-EVT-*` | Heavy observers on critical storefront events |
| **Cron**        | `MD-CRON-*`| Schedule backlog, overlap storms, stuck running jobs |
| **Indexers**    | `MD-IDX-*` | Realtime vs scheduled indexer modes, changelog backlog |
| **Database**    | `MD-DB-*`  | Missing declared indexes, redundant left-prefix indexes, orphan tables, volatile bloat |
| **SQL Forensics**| `MD-SQL-001` | High latency query digest (performance_schema, scoped to the store's schema) |
| | `MD-SQL-002` | Confirmed transaction lock wait, with the blocking transaction named |
| | `MD-SQL-003` | Long-running statement holding a connection (not a lock wait) |
| **Cache & Redis**| `MD-CACHE-*` | Redis database collisions between sessions, cache and page cache |
| | `MD-RDS-001` | Session store can evict live sessions (`allkeys-*` policy, or attributable evictions) |
| | `MD-RDS-002` | Cache instance memory pressure or severe fragmentation |
| | `MD-RDS-003` | Low cache hit ratio (cache thrashing) |
| **FPC & Varnish**| `MD-FPC-001` | Storefront layout puncture (`cacheable="false"`), modules and theme overrides |
| **PHP Workers** | `MD-FPM-001` | Worker pool saturation / listen queue buildup (requires the FPM status page) |
| | `MD-FPM-002` | `pm.max_children` x worker footprint exceeds host RAM (OOM risk) |
| **Search Engine**| `MD-SRC-001` | Cluster health degraded (single-node yellow excluded — see `MD-SRC-002`) |
| | `MD-SRC-002` | Single-node cluster has no replica redundancy (informational) |
| | `MD-SRC-003` | No catalog search index present, prefix-agnostic |
| **Performance** | `MD-PERF-*`| N+1 repository loops, synchronous HTTP calls, loop logging |
| **Security**    | `MD-SEC-*` | Developer mode in production, world-writable directories |

---

## Supported Versions

Magento Doctor ships with built-in version matrices, compatibility rules, and hot-path databases covering:
- **Magento Open Source & Adobe Commerce**: `2.4.4`, `2.4.5`, `2.4.6`, `2.4.7`, `2.4.8`, and `2.4.9`
- **PHP**: `8.1`, `8.2`, `8.3`, `8.4`, and `8.5` (certified for Magento 2.4.9)
- **Database**: MariaDB `10.4`, `10.6`, `10.11`, `11.x` (11.0–11.4 LTS) & MySQL `8.0`, `8.4 LTS`, `9.x` (latest)
- **Search**: OpenSearch `1.2`, `2.5`, `2.12`, `2.19`, and `3.0` (actively supported)
- **Cache**: Redis `6.2`, `7.0`, `7.2`, `8.0` & Valkey `7.2`, `8.0` (actively supported drop-in replacement)

---

## Quick Links & Resources

- 🌐 **Interactive Documentation & Showcase**: [https://nemke82.github.io/magento-doctor/](https://nemke82.github.io/magento-doctor/)
- 💻 **Terminal Forensics Simulator**: [https://nemke82.github.io/magento-doctor/#simulator](https://nemke82.github.io/magento-doctor/#simulator)
- 📋 **Searchable Diagnostic Rule Catalog**: [https://nemke82.github.io/magento-doctor/#rules](https://nemke82.github.io/magento-doctor/#rules)
- 📦 **Releases & Pre-compiled Standalone Binaries**: [https://github.com/nemke82/magento-doctor/releases](https://github.com/nemke82/magento-doctor/releases)

---

## License

MIT © 2026 nemke82 and Magento Doctor Contributors.
