//! OpenSearch and Elasticsearch cluster health and Magento catalog index inspection.

use std::time::Duration;

use mdoctor_core::{Endpoint, OpenSearchStatus, ProbeOutcome};

use crate::http_probe::{http_probe, HttpProbeRequest};

/// Default OpenSearch/Elasticsearch HTTP port.
pub const DEFAULT_OPENSEARCH_PORT: u16 = 9200;

/// Connects to OpenSearch/Elasticsearch to verify cluster health and catalog indices.
///
/// `basic_auth` is `user:password` for a secured cluster. Without it, a secured
/// cluster answers 401 and is reported as an explicit probe failure rather than being
/// mistaken for an unhealthy or empty one.
pub async fn inspect_opensearch(
    endpoint: &Endpoint,
    basic_auth: Option<&str>,
    timeout: Duration,
) -> OpenSearchStatus {
    let mut status = OpenSearchStatus {
        is_configured: true,
        ..Default::default()
    };

    if endpoint.is_unix_socket {
        status.probe = ProbeOutcome::failed("unix socket endpoints are not supported");
        return status;
    }

    let health_req = HttpProbeRequest::get(&endpoint.host, endpoint.port, "/_cluster/health", timeout)
        .with_basic_auth(basic_auth);

    match http_probe(health_req).await {
        Ok(resp) if resp.is_success() => {
            status = parse_opensearch_health_json(&resp.body);
            status.is_configured = true;
            if status.status.is_none() {
                // 200 but no parseable health document: do not claim reachability.
                status.is_reachable = false;
                status.probe = ProbeOutcome::failed("cluster health response was not valid JSON");
                return status;
            }
            status.is_reachable = true;
            status.probe = ProbeOutcome::Succeeded;
        }
        Ok(resp) => {
            let hint = if resp.status == 401 || resp.status == 403 {
                format!("HTTP {} (cluster requires credentials; pass --opensearch-auth)", resp.status)
            } else {
                format!("HTTP {}", resp.status)
            };
            status.probe = ProbeOutcome::failed(hint);
            return status;
        }
        Err(e) => {
            status.probe = ProbeOutcome::failed(e.to_string());
            return status;
        }
    }

    // Version, for completeness; a failure here does not change cluster health.
    let root_req = HttpProbeRequest::get(&endpoint.host, endpoint.port, "/", timeout)
        .with_basic_auth(basic_auth);
    if let Ok(resp) = http_probe(root_req).await {
        if resp.is_success() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                status.version = v
                    .get("version")
                    .and_then(|ver| ver.get("number"))
                    .and_then(|n| n.as_str())
                    .map(str::to_string);
            }
        }
    }

    // Catalog index presence.
    let indices_req =
        HttpProbeRequest::get(&endpoint.host, endpoint.port, "/_cat/indices?format=json", timeout)
            .with_basic_auth(basic_auth);
    match http_probe(indices_req).await {
        Ok(resp) if resp.is_success() => {
            let names = parse_index_names(&resp.body);
            status.catalog_index_names = catalog_index_names(&names);
            status.has_catalog_index = !status.catalog_index_names.is_empty();
            status.catalog_index_probe = ProbeOutcome::Succeeded;
        }
        Ok(resp) => {
            status.catalog_index_probe = ProbeOutcome::failed(format!("HTTP {}", resp.status));
        }
        Err(e) => status.catalog_index_probe = ProbeOutcome::failed(e.to_string()),
    }

    status
}

/// Parses OpenSearch /_cluster/health JSON output.
pub fn parse_opensearch_health_json(json_str: &str) -> OpenSearchStatus {
    let mut status = OpenSearchStatus {
        is_configured: true,
        ..Default::default()
    };

    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return status;
    };

    let u32_field = |key: &str| v.get(key).and_then(|n| n.as_u64()).map(|n| n as u32);

    status.cluster_name = v.get("cluster_name").and_then(|s| s.as_str()).map(str::to_string);
    status.status = v.get("status").and_then(|s| s.as_str()).map(str::to_string);
    status.number_of_nodes = u32_field("number_of_nodes");
    status.number_of_data_nodes = u32_field("number_of_data_nodes");
    status.active_primary_shards = u32_field("active_primary_shards");
    status.active_shards = u32_field("active_shards");
    status.unassigned_shards = u32_field("unassigned_shards");

    status
}

/// Extracts index names from a `_cat/indices?format=json` response.
pub fn parse_index_names(json_str: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return Vec::new();
    };
    v.as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.get("index").and_then(|i| i.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Filters index names down to Magento catalog search indices.
///
/// Magento's index prefix is configurable (`elasticsearch_index_prefix`, default
/// `magento2`), so matching a hardcoded `magento2_product` reports a healthy catalog
/// as missing on every store that changed it. Match on the suffix Magento controls.
pub fn catalog_index_names(all_indices: &[String]) -> Vec<String> {
    all_indices
        .iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            // Magento names catalog indices "<prefix>_product_<storeId>_v<n>" and
            // creates "catalogsearch_fulltext" style aliases.
            lower.contains("catalogsearch_fulltext")
                || lower.contains("_product_")
                || lower.ends_with("_product")
                || lower.contains("_category_")
        })
        .cloned()
        .collect()
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
        assert_eq!(status.number_of_data_nodes, Some(3));
        assert_eq!(status.active_primary_shards, Some(12));
        assert_eq!(status.unassigned_shards, Some(0));
    }

    #[test]
    fn test_parse_index_names() {
        let json = r#"[{"health":"green","index":"magento2_product_1_v3","docs.count":"120"},
                       {"health":"green","index":".kibana_1"}]"#;
        assert_eq!(
            parse_index_names(json),
            vec!["magento2_product_1_v3".to_string(), ".kibana_1".to_string()]
        );
    }

    #[test]
    fn test_catalog_index_detection_is_prefix_agnostic() {
        // A store that set elasticsearch_index_prefix to something other than the
        // default must not be told its catalog index is missing.
        let indices = vec![
            "mystore_product_1_v7".to_string(),
            "mystore_category_1_v7".to_string(),
            ".opendistro_security".to_string(),
        ];
        let found = catalog_index_names(&indices);
        assert_eq!(found.len(), 2);
        assert!(found.contains(&"mystore_product_1_v7".to_string()));
    }

    #[test]
    fn test_catalog_index_detection_finds_default_prefix() {
        let indices = vec!["magento2_product_1_v1".to_string(), ".kibana".to_string()];
        assert_eq!(catalog_index_names(&indices), vec!["magento2_product_1_v1".to_string()]);
    }

    #[test]
    fn test_catalog_index_detection_empty_when_no_catalog() {
        let indices = vec![".kibana_1".to_string(), "logs-2026.09".to_string()];
        assert!(catalog_index_names(&indices).is_empty());
    }

    #[tokio::test]
    async fn test_inspect_reports_auth_failure_not_degradation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut discard = [0u8; 1024];
            let _ = sock.read(&mut discard).await;
            sock.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let endpoint = Endpoint::parse(&format!("127.0.0.1:{}", port), DEFAULT_OPENSEARCH_PORT).unwrap();
        let status = inspect_opensearch(&endpoint, None, Duration::from_secs(2)).await;

        assert!(!status.is_reachable, "a 401 is not a reachable healthy cluster");
        assert!(matches!(status.probe, ProbeOutcome::Failed { .. }));
        assert!(!status.has_catalog_index);
        assert!(
            status.catalog_index_probe.is_inconclusive(),
            "index presence is unknown, not missing"
        );
    }

    #[tokio::test]
    async fn test_inspect_healthy_cluster_with_custom_prefix() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            // One connection per request: health, root, then _cat/indices.
            let bodies = [
                r#"{"cluster_name":"os-prod","status":"green","number_of_nodes":3,"number_of_data_nodes":3,"active_primary_shards":10,"active_shards":20,"unassigned_shards":0}"#,
                r#"{"version":{"number":"2.13.0"}}"#,
                r#"[{"index":"mystore_product_1_v4"}]"#,
            ];
            for body in bodies {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut discard = [0u8; 2048];
                let _ = sock.read(&mut discard).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let endpoint = Endpoint::parse(&format!("127.0.0.1:{}", port), DEFAULT_OPENSEARCH_PORT).unwrap();
        let status = inspect_opensearch(&endpoint, None, Duration::from_secs(3)).await;

        assert!(status.is_reachable);
        assert!(status.probe.is_success());
        assert_eq!(status.status.as_deref(), Some("green"));
        assert_eq!(status.version.as_deref(), Some("2.13.0"));
        assert!(status.has_catalog_index, "custom index prefix must still be found");
        assert!(status.catalog_index_probe.is_success());
    }

    #[tokio::test]
    async fn test_inspect_unreachable_cluster() {
        let endpoint = Endpoint::parse("127.0.0.1:1", DEFAULT_OPENSEARCH_PORT).unwrap();
        let status = inspect_opensearch(&endpoint, None, Duration::from_millis(400)).await;

        assert!(!status.is_reachable);
        assert!(status.probe.is_inconclusive());
        assert_eq!(status.status, None);
    }
}
