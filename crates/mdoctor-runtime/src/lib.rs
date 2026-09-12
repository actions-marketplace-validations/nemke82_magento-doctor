//! mdoctor_runtime: Environment, PHP, Redis, and filesystem inspection.

pub mod filesystem;
pub mod fpc_inspector;
pub mod opensearch_inspector;
pub mod php_check;
pub mod php_fpm_inspector;
pub mod redis_check;
pub mod redis_inspector;

pub use filesystem::{inspect_filesystem, FsCheckResult};
pub use fpc_inspector::{evaluate_fpc, probe_varnish};
pub use opensearch_inspector::{inspect_opensearch, parse_opensearch_health_json};
pub use php_check::{check_php_runtime, PhpRuntimeIssue};
pub use php_fpm_inspector::{calculate_pool_metrics, inspect_php_fpm, parse_php_fpm_conf};
pub use redis_check::{check_redis_config, RedisIssue};
pub use redis_inspector::{inspect_redis, parse_redis_info};
