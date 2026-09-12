//! OpenSearch and Elasticsearch cluster health and Magento catalog index inspection.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use mdoctor_core::OpenSearchStatus;

/// Connects to OpenSearch/Elasticsearch to verify cluster health and catalog indices.
pub async fn inspect_opensearch(
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<OpenSearchStatus, Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_secs(timeout_secs.clamp(1, 5));

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await??;

    // 1. GET /_cluster/health
    let req = format!(
        "GET /_cluster/health HTTP/1.1\r\nHost: {}\r\nUser-Agent: mdoctor\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        host
    );
    tokio::time::timeout(timeout, stream.write_all(req.as_bytes())).await??;

    let mut resp_bytes = Vec::with_capacity(4096);
    let mut temp = [0u8; 1024];
    loop {
        match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut temp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                resp_bytes.extend_from_slice(&temp[..n]);
                if resp_bytes.len() > 32768 {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }

    let resp_str = String::from_utf8_lossy(&resp_bytes);
    let body = if let Some((_headers, b)) = resp_str.split_once("\r\n\r\n") {
        b
    } else {
        &resp_str
    };

    let mut status = parse_opensearch_health_json(body);
    status.is_configured = true;
    status.is_reachable = true;

    // 2. Check catalog index presence via second connection
    if let Ok(Ok(mut idx_stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        let cat_req = format!(
            "GET /_cat/indices?format=json HTTP/1.1\r\nHost: {}\r\nUser-Agent: mdoctor\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            host
        );
        if tokio::time::timeout(timeout, idx_stream.write_all(cat_req.as_bytes())).await.is_ok() {
            let mut cat_bytes = Vec::with_capacity(8192);
            let mut cat_temp = [0u8; 1024];
            loop {
                match tokio::time::timeout(Duration::from_millis(300), idx_stream.read(&mut cat_temp)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => cat_bytes.extend_from_slice(&cat_temp[..n]),
                    Ok(Err(_)) => break,
                }
            }
            let cat_str = String::from_utf8_lossy(&cat_bytes);
            let cat_body = cat_str.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&cat_str);
            if cat_body.contains("magento2_product") || cat_body.contains("catalogsearch_fulltext") {
                status.has_catalog_index = true;
            }
        }
    }

    Ok(status)
}

/// Parses OpenSearch /_cluster/health JSON output.
pub fn parse_opensearch_health_json(json_str: &str) -> OpenSearchStatus {
    let mut status = OpenSearchStatus {
        is_configured: true,
        is_reachable: true,
        ..Default::default()
    };

    let v: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(val) => val,
        Err(_) => return status,
    };

    status.cluster_name = v.get("cluster_name").and_then(|s| s.as_str()).map(|s| s.to_string());
    status.status = v.get("status").and_then(|s| s.as_str()).map(|s| s.to_string());
    status.number_of_nodes = v.get("number_of_nodes").and_then(|n| n.as_u64()).map(|n| n as u32);
    status.active_primary_shards = v.get("active_primary_shards").and_then(|n| n.as_u64()).map(|n| n as u32);
    status.active_shards = v.get("active_shards").and_then(|n| n.as_u64()).map(|n| n as u32);
    status.unassigned_shards = v.get("unassigned_shards").and_then(|n| n.as_u64()).map(|n| n as u32);

    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_opensearch_health() {
        let json = r#"{
  "cluster_name": "magento-search-prod",
  "status": "green",
  "timed_out": false,
  "number_of_nodes": 3,
  "number_of_data_nodes": 3,
  "active_primary_shards": 12,
  "active_shards": 24,
  "relocating_shards": 0,
  "initializing_shards": 0,
  "unassigned_shards": 0
}"#;

        let status = parse_opensearch_health_json(json);
        assert_eq!(status.status.as_deref(), Some("green"));
        assert_eq!(status.cluster_name.as_deref(), Some("magento-search-prod"));
        assert_eq!(status.number_of_nodes, Some(3));
        assert_eq!(status.active_primary_shards, Some(12));
        assert_eq!(status.unassigned_shards, Some(0));
    }
}
