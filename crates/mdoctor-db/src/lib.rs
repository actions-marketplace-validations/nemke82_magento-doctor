//! mdoctor_db: Database schema reconciliation, index rules, and MySQL live inspector.

pub mod correlation;
pub mod fingerprint;
pub mod index_rules;
pub mod live_inspector;
pub mod schema_diff;

pub use correlation::{correlate_query, extract_tables_from_sql, map_table_to_module, QueryCorrelation};
pub use fingerprint::fingerprint_query;
pub use index_rules::{find_redundant_indexes, RedundantIndex};
pub use live_inspector::inspect_live_database;
pub use schema_diff::{reconcile_schemas, SchemaDiffReport};
