//! Safe live MySQL inspector.

use mdoctor_core::{CronScheduleSummary, DatabaseMetrics, ProbeOutcome, TableSizeStat};
use mysql_async::prelude::*;
use mysql_async::{Opts, OptsBuilder, Pool};
use std::time::Duration;
use tracing::info;

pub async fn inspect_live_database(
    host: &str,
    dbname: &str,
    user: &str,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<DatabaseMetrics, Box<dyn std::error::Error + Send + Sync>> {
    let mut opts_builder = OptsBuilder::default();
    opts_builder = opts_builder
        .ip_or_hostname(host)
        .db_name(Some(dbname))
        .user(Some(user))
        .pass(password);

    let opts: Opts = opts_builder.into();
    let pool = Pool::new(opts);
    let mut conn = tokio::time::timeout(Duration::from_secs(timeout_secs), pool.get_conn()).await??;

    info!("Connected to MySQL database '{}' on '{}'", dbname, host);

    let mut metrics = DatabaseMetrics {
        is_connected: true,
        ..Default::default()
    };

    // 1. Server version
    let query_timeout = Duration::from_secs(timeout_secs.clamp(1, 5));

    if let Ok(Ok(version_rows)) = tokio::time::timeout(
        query_timeout,
        conn.query_map("SELECT VERSION()", |v: String| v),
    )
    .await
    {
        if let Some(v) = version_rows.into_iter().next() {
            metrics.server_version = Some(v);
        }
    }

    // 2. Buffer pool size
    if let Ok(Ok(var_rows)) = tokio::time::timeout(
        query_timeout,
        conn.query_map(
            "SHOW VARIABLES LIKE 'innodb_buffer_pool_size'",
            |(_name, val): (String, String)| val,
        ),
    )
    .await
    {
        if let Some(val_str) = var_rows.into_iter().next() {
            if let Ok(bytes) = val_str.parse::<u64>() {
                metrics.innodb_buffer_pool_bytes = Some(bytes);
            }
        }
    }

    // 3. Top tables by size from information_schema
    let table_query = r#"
        SELECT table_name, IFNULL(table_rows, 0), IFNULL(data_length, 0), IFNULL(index_length, 0)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        ORDER BY (IFNULL(data_length, 0) + IFNULL(index_length, 0)) DESC
        LIMIT 50
    "#;

    if let Ok(Ok(rows)) = tokio::time::timeout(
        query_timeout,
        conn.query_map(
            table_query,
            |(name, rows, data_len, idx_len): (String, u64, u64, u64)| TableSizeStat {
                table_name: name,
                row_count: rows,
                data_bytes: data_len,
                index_bytes: idx_len,
                total_bytes: data_len + idx_len,
            },
        ),
    )
    .await
    {
        let total_bytes = rows.iter().map(|t| t.total_bytes).sum();
        metrics.total_data_and_index_bytes = Some(total_bytes);
        metrics.table_sizes = rows;
    }

    // 4. Cron schedule summary
    let cron_summary_query = r#"
        SELECT status, COUNT(*)
        FROM cron_schedule
        GROUP BY status
    "#;

    let mut cron_summary = CronScheduleSummary::default();
    if let Ok(Ok(status_counts)) = tokio::time::timeout(
        query_timeout,
        conn.query_map(cron_summary_query, |(status, count): (String, u64)| {
            (status, count)
        }),
    )
    .await
    {
        for (status, count) in status_counts {
            cron_summary.total_rows += count;
            match status.to_lowercase().as_str() {
                "pending" => cron_summary.pending_rows += count,
                "running" => cron_summary.running_rows += count,
                "success" => cron_summary.success_rows += count,
                "missed" => cron_summary.missed_rows += count,
                "error" => cron_summary.error_rows += count,
                _ => {}
            }
        }
    }

    // Oldest running job
    let oldest_running_query = r#"
        SELECT job_code, TIMESTAMPDIFF(SECOND, executed_at, NOW())
        FROM cron_schedule
        WHERE status = 'running' AND executed_at IS NOT NULL
        ORDER BY executed_at ASC
        LIMIT 1
    "#;

    if let Ok(Ok(oldest_rows)) = tokio::time::timeout(
        query_timeout,
        conn.query_map(
            oldest_running_query,
            |(job_code, secs): (String, Option<i64>)| {
                (job_code, secs.unwrap_or(0).max(0) as u64)
            },
        ),
    )
    .await
    {
        if let Some((job, secs)) = oldest_rows.into_iter().next() {
            cron_summary.oldest_running_job = Some(job);
            cron_summary.oldest_running_seconds = Some(secs);
        }
    }

    metrics.cron_schedule = cron_summary;

    // 5. Active connection count
    if let Ok(Ok(threads_rows)) = tokio::time::timeout(
        query_timeout,
        conn.query_map(
            "SHOW STATUS LIKE 'Threads_connected'",
            |(_name, val): (String, String)| val.parse::<u64>().unwrap_or(0),
        ),
    )
    .await
    {
        if let Some(t) = threads_rows.into_iter().next() {
            metrics.active_connections = Some(t);
        }
    }

    // 6. Query digests from performance_schema, scoped to this store's schema so a
    // shared MySQL server's other workloads are not blamed on Magento modules.
    let digest_query = r#"
        SELECT
            IFNULL(DIGEST, ''),
            IFNULL(DIGEST_TEXT, ''),
            IFNULL(COUNT_STAR, 0),
            IFNULL(SUM_TIMER_WAIT, 0),
            IFNULL(AVG_TIMER_WAIT, 0),
            IFNULL(MAX_TIMER_WAIT, 0),
            IFNULL(SUM_ROWS_EXAMINED, 0),
            IFNULL(SUM_ROWS_SENT, 0),
            IFNULL(DATE_FORMAT(FIRST_SEEN, '%Y-%m-%d %H:%i:%s'), ''),
            IFNULL(DATE_FORMAT(LAST_SEEN, '%Y-%m-%d %H:%i:%s'), '')
        FROM performance_schema.events_statements_summary_by_digest
        WHERE DIGEST_TEXT IS NOT NULL
          AND SCHEMA_NAME = DATABASE()
          AND DIGEST_TEXT NOT LIKE '%performance_schema%'
          AND DIGEST_TEXT NOT LIKE 'SHOW %'
          AND DIGEST_TEXT NOT LIKE 'SELECT VERSION%'
        ORDER BY SUM_TIMER_WAIT DESC
        LIMIT 15
    "#;

    match tokio::time::timeout(
        query_timeout,
        conn.query_map(
            digest_query,
            |(digest_id, text, count, sum_time, avg_time, max_time, rows_exam, rows_sent, first, last): (
                String,
                String,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                String,
                String,
            )| {
                // performance_schema timers are picoseconds; 1 ms is 1e9 ps.
                let total_ms = sum_time as f64 / 1_000_000_000.0;
                let avg_ms = avg_time as f64 / 1_000_000_000.0;
                let max_ms = max_time as f64 / 1_000_000_000.0;
                let tables = crate::correlation::extract_tables_from_sql(&text);
                mdoctor_core::QueryDigest {
                    digest_id,
                    fingerprint: text,
                    execution_count: count,
                    total_time_ms: total_ms,
                    avg_time_ms: avg_ms,
                    max_time_ms: max_ms,
                    avg_rows_examined: rows_exam.checked_div(count).unwrap_or(0),
                    avg_rows_sent: rows_sent.checked_div(count).unwrap_or(0),
                    tables_involved: tables,
                    first_seen: if first.is_empty() { None } else { Some(first) },
                    last_seen: if last.is_empty() { None } else { Some(last) },
                }
            },
        ),
    )
    .await
    {
        Ok(Ok(digest_rows)) => {
            metrics.query_digests = digest_rows;
            metrics.digest_collection = ProbeOutcome::Succeeded;
        }
        // An empty digest list from a disabled performance_schema or a missing SELECT
        // grant would otherwise be indistinguishable from a store with no slow queries.
        Ok(Err(e)) => {
            metrics.digest_collection =
                ProbeOutcome::failed(format!("performance_schema digest query failed: {}", e))
        }
        Err(_) => {
            metrics.digest_collection =
                ProbeOutcome::failed("performance_schema digest query timed out")
        }
    }

    // 7. Genuine lock waits, from performance_schema's blocker/blocked pairs.
    //
    // MySQL 8 exposes data_lock_waits; 5.7 has innodb_lock_waits under sys. Only these
    // name a real blocker, so a hit here is a confirmed lock wait rather than an
    // inference from a query merely being slow.
    let lock_wait_query = r#"
        SELECT
            r.trx_mysql_thread_id,
            IFNULL(r.trx_query, ''),
            b.trx_mysql_thread_id,
            IFNULL(b.trx_query, ''),
            IFNULL(TIMESTAMPDIFF(SECOND, r.trx_wait_started, NOW()), 0)
        FROM performance_schema.data_lock_waits w
        JOIN information_schema.innodb_trx r ON r.trx_id = w.requesting_engine_transaction_id
        JOIN information_schema.innodb_trx b ON b.trx_id = w.blocking_engine_transaction_id
        LIMIT 10
    "#;

    let mut lock_probe;
    match tokio::time::timeout(
        query_timeout,
        conn.query_map(
            lock_wait_query,
            |(waiting_id, waiting_query, blocking_id, blocking_query, wait_secs): (
                Option<u64>,
                String,
                Option<u64>,
                String,
                i64,
            )| {
                let tables = crate::correlation::extract_tables_from_sql(&waiting_query);
                mdoctor_core::ActiveLockWait {
                    waiting_query_id: waiting_id.unwrap_or(0),
                    waiting_query,
                    blocking_query_id: blocking_id,
                    blocking_query: if blocking_query.is_empty() {
                        None
                    } else {
                        Some(blocking_query)
                    },
                    wait_time_secs: wait_secs.max(0) as u64,
                    table_name: tables.into_iter().next(),
                    is_confirmed_lock_wait: true,
                    command: None,
                    user: None,
                }
            },
        ),
    )
    .await
    {
        Ok(Ok(rows)) => {
            metrics.active_lock_waits = rows;
            lock_probe = ProbeOutcome::Succeeded;
        }
        Ok(Err(e)) => lock_probe = ProbeOutcome::failed(format!("data_lock_waits unavailable: {}", e)),
        Err(_) => lock_probe = ProbeOutcome::failed("lock wait query timed out"),
    }

    // 8. Long-running statements from the processlist, as context rather than as lock
    // waits. Replication, daemon and event-scheduler threads sit at TIME = uptime, so
    // they must be excluded or every replica reports a multi-day "lock wait".
    let long_query_sql = r#"
        SELECT
            ID,
            IFNULL(INFO, ''),
            IFNULL(TIME, 0),
            IFNULL(COMMAND, ''),
            IFNULL(USER, ''),
            IFNULL(STATE, '')
        FROM information_schema.processlist
        WHERE ID <> CONNECTION_ID()
          AND COMMAND NOT IN ('Sleep', 'Binlog Dump', 'Binlog Dump GTID', 'Daemon', 'Connect')
          AND USER NOT IN ('system user', 'event_scheduler')
          AND DB = DATABASE()
          AND INFO IS NOT NULL
          AND TIME BETWEEN 3 AND 86400
        ORDER BY TIME DESC
        LIMIT 10
    "#;

    if let Ok(Ok(rows)) = tokio::time::timeout(
        query_timeout,
        conn.query_map(
            long_query_sql,
            |(id, info, time_sec, command, user, state): (u64, String, i64, String, String, String)| {
                let tables = crate::correlation::extract_tables_from_sql(&info);
                // A processlist STATE mentioning a lock is suggestive, but only
                // performance_schema can confirm a blocker, so never claim one here.
                let looks_like_lock = state.to_lowercase().contains("lock");
                mdoctor_core::ActiveLockWait {
                    waiting_query_id: id,
                    waiting_query: info,
                    blocking_query_id: None,
                    blocking_query: None,
                    wait_time_secs: time_sec.max(0) as u64,
                    table_name: tables.into_iter().next(),
                    is_confirmed_lock_wait: false,
                    command: Some(if looks_like_lock {
                        format!("{} ({})", command, state)
                    } else {
                        command
                    }),
                    user: Some(user),
                }
            },
        ),
    )
    .await
    {
        // Confirmed lock waits take precedence; long queries only supplement them.
        for row in rows {
            if !metrics
                .active_lock_waits
                .iter()
                .any(|existing| existing.waiting_query_id == row.waiting_query_id)
            {
                metrics.active_lock_waits.push(row);
            }
        }
        if lock_probe.is_inconclusive() {
            lock_probe = ProbeOutcome::Succeeded;
        }
    }

    metrics.lock_collection = lock_probe;

    // CRITICAL: Drop active connection back into pool before disconnecting!
    // mysql_async::Pool::disconnect() waits indefinitely for active checked-out
    // connections to be dropped, causing a deadlock if conn is still in scope.
    drop(conn);
    let _ = tokio::time::timeout(Duration::from_secs(1), pool.disconnect()).await;
    Ok(metrics)
}
