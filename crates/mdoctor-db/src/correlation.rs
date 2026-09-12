//! Correlation between SQL queries/digests, database schema, and Magento code assets.

use std::collections::HashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use mdoctor_core::{MagentoInstallation, QueryDigest, TableSchema};

/// Detailed correlation between a query digest and Magento code/module assets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCorrelation {
    pub digest_fingerprint: String,
    pub tables_involved: Vec<String>,
    pub candidate_modules: Vec<String>,
    pub matched_code_references: Vec<String>,
    pub is_hot_path: bool,
    pub correlation_notes: String,
}

/// Extracts table names referenced in an SQL statement.
pub fn extract_tables_from_sql(sql: &str) -> Vec<String> {
    let mut tables = Vec::new();

    // Regex to match table tokens after FROM, JOIN, UPDATE, INTO
    let re = Regex::new(r#"(?i)\b(?:from|join|update|into)\s+[`"]?([a-zA-Z0-9_]+)[`"]?"#).unwrap();

    for cap in re.captures_iter(sql) {
        if let Some(m) = cap.get(1) {
            let table = m.as_str().to_lowercase();
            // Skip common SQL keywords that might follow clauses
            let ignored = ["select", "where", "set", "values", "dual", "table", "null", "case"];
            if !ignored.contains(&table.as_str()) && !tables.contains(&table) {
                tables.push(table);
            }
        }
    }

    tables
}

/// Maps a table name to the most likely owning Magento module.
pub fn map_table_to_module(
    table_name: &str,
    declared_tables: &HashMap<String, TableSchema>,
) -> Option<String> {
    let t_lower = table_name.to_lowercase();

    // 1. Exact match in declarative schema
    if let Some(schema) = declared_tables.get(table_name) {
        if let Some(m) = &schema.owning_module {
            return Some(m.clone());
        }
    }

    // Check case-insensitive
    for (name, schema) in declared_tables {
        if name.eq_ignore_ascii_case(&t_lower) {
            if let Some(m) = &schema.owning_module {
                return Some(m.clone());
            }
        }
    }

    // 2. Known Core Magento Table Prefix Mappings
    if t_lower.starts_with("catalog_") || t_lower.starts_with("cataloginventory_") {
        return Some("Magento_Catalog".to_string());
    }
    if t_lower.starts_with("sales_") || t_lower.starts_with("sales_order") {
        return Some("Magento_Sales".to_string());
    }
    if t_lower.starts_with("quote") {
        return Some("Magento_Quote".to_string());
    }
    if t_lower.starts_with("customer_") {
        return Some("Magento_Customer".to_string());
    }
    if t_lower == "url_rewrite" {
        return Some("Magento_UrlRewrite".to_string());
    }
    if t_lower.starts_with("eav_") {
        return Some("Magento_Eav".to_string());
    }
    if t_lower.starts_with("cms_") {
        return Some("Magento_Cms".to_string());
    }
    if t_lower.starts_with("newsletter_") {
        return Some("Magento_Newsletter".to_string());
    }
    if t_lower == "cron_schedule" {
        return Some("Magento_Cron".to_string());
    }
    if t_lower == "core_config_data" {
        return Some("Magento_Config".to_string());
    }
    if t_lower.starts_with("inventory_") {
        return Some("Magento_Inventory".to_string());
    }
    if t_lower.starts_with("search_query") || t_lower.starts_with("catalogsearch_") {
        return Some("Magento_CatalogSearch".to_string());
    }

    // 3. Fallback: custom module tables often use Vendor_Module prefix (e.g. vendor_feed_queue -> Vendor_Feed)
    None
}

/// Correlates a query digest with Magento installation modules and touchpoints.
pub fn correlate_query(
    digest: &QueryDigest,
    installation: &MagentoInstallation,
) -> QueryCorrelation {
    let mut candidate_modules = Vec::new();
    let mut code_refs = Vec::new();
    let mut is_hot_path = false;

    for table in &digest.tables_involved {
        if let Some(module_name) = map_table_to_module(table, &installation.declared_schema.tables) {
            if !candidate_modules.contains(&module_name) {
                candidate_modules.push(module_name.clone());
            }

            if module_name == "Magento_Quote" || module_name == "Magento_Sales" || module_name == "Magento_Catalog" {
                is_hot_path = true;
            }
        } else {
            // Check if any installed custom module name matches the table prefix
            for m in &installation.modules {
                let slug = m.name.replace('_', "").to_lowercase();
                let snake = m.name.to_lowercase();
                if (table.replace('_', "").starts_with(&slug) || table.starts_with(&snake))
                    && !candidate_modules.contains(&m.name)
                {
                    candidate_modules.push(m.name.clone());
                }
            }
        }
    }

    // Match against hot-path plugins in the installation
    for plg in &installation.plugins {
        for m in &candidate_modules {
            if &plg.module == m && (plg.target_class.contains("Quote") || plg.target_class.contains("Product") || plg.target_class.contains("Order")) {
                code_refs.push(format!("Plugin: {} ({})", plg.plugin_class, plg.source_file.display()));
            }
        }
    }

    let notes = if candidate_modules.is_empty() {
        "Query operates on dynamic or untracked tables.".to_string()
    } else {
        format!(
            "Query touches tables managed by: {}. Hot path: {}.",
            candidate_modules.join(", "),
            if is_hot_path { "YES" } else { "NO" }
        )
    };

    QueryCorrelation {
        digest_fingerprint: digest.fingerprint.clone(),
        tables_involved: digest.tables_involved.clone(),
        candidate_modules,
        matched_code_references: code_refs,
        is_hot_path,
        correlation_notes: notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tables_from_complex_sql() {
        let sql = "SELECT p.entity_id, c.value FROM catalog_product_entity p JOIN catalog_product_entity_varchar c ON p.entity_id = c.entity_id WHERE p.sku = ? ORDER BY p.entity_id";
        let tables = extract_tables_from_sql(sql);
        assert_eq!(tables.len(), 2);
        assert!(tables.contains(&"catalog_product_entity".to_string()));
        assert!(tables.contains(&"catalog_product_entity_varchar".to_string()));
    }

    #[test]
    fn test_map_core_tables() {
        let map = HashMap::new();
        assert_eq!(map_table_to_module("catalog_product_entity", &map), Some("Magento_Catalog".to_string()));
        assert_eq!(map_table_to_module("sales_order_grid", &map), Some("Magento_Sales".to_string()));
        assert_eq!(map_table_to_module("quote_item", &map), Some("Magento_Quote".to_string()));
    }
}
