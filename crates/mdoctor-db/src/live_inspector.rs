//! Safe live MySQL inspector.

use mdoctor_core::{CronScheduleSummary, DatabaseMetrics, TableSizeStat};
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

    // 6. Query digests from performance_schema
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
          AND DIGEST_TEXT NOT LIKE '%performance_schema%'
          AND DIGEST_TEXT NOT LIKE 'SHOW %'
          AND DIGEST_TEXT NOT LIKE 'SELECT VERSION%'
        ORDER BY SUM_TIMER_WAIT DESC
        LIMIT 15
    "#;

    if let Ok(Ok(digest_rows)) = tokio::time::timeout(
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
        metrics.query_digests = digest_rows;
    }

    // 7. Active lock contention / slow processlist queries
    let locks_query = r#"
        SELECT
            ID,
            IFNULL(INFO, ''),
            TIME
        FROM information_schema.processlist
        WHERE COMMAND != 'Sleep' AND (TIME > 3 OR STATE LIKE '%lock%')
        ORDER BY TIME DESC
        LIMIT 10
    "#;

    if let Ok(Ok(lock_rows)) = tokio::time::timeout(
        query_timeout,
        conn.query_map(locks_query, |(id, info, time_sec): (u64, String, u64)| {
            let tables = crate::correlation::extract_tables_from_sql(&info);
            mdoctor_core::ActiveLockWait {
                waiting_query_id: id,
                waiting_query: info,
                blocking_query_id: None,
                blocking_query: None,
                wait_time_secs: time_sec,
                table_name: tables.into_iter().next(),
            }
        }),
    )
    .await
    {
        metrics.active_lock_waits = lock_rows;
    }

    // CRITICAL: Drop active connection back into pool before disconnecting!
    // mysql_async::Pool::disconnect() waits indefinitely for active checked-out
    // connections to be dropped, causing a deadlock if conn is still in scope.
    drop(conn);
    let _ = tokio::time::timeout(Duration::from_secs(1), pool.disconnect()).await;
    Ok(metrics)
}
