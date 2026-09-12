//! mdoctor_runtime: Environment, PHP, Redis, and filesystem inspection.

pub mod filesystem;
pub mod fpc_inspector;
pub mod http_probe;
pub mod nginx_inspector;
pub mod opensearch_inspector;
pub mod php_check;
pub mod php_fpm_inspector;
pub mod redis_check;
pub mod redis_inspector;

pub use filesystem::{inspect_filesystem, FsCheckResult};
pub use fpc_inspector::{
    evaluate_fpc, probe_storefront_cache, probe_varnish, DEFAULT_VARNISH_PORT,
};
pub use http_probe::{http_probe, HttpProbeError, HttpProbeRequest, HttpResponse};
pub use nginx_inspector::{inspect_nginx, parse_stub_status};
pub use opensearch_inspector::{
    catalog_index_names, inspect_opensearch, parse_index_names, parse_opensearch_health_json,
    DEFAULT_OPENSEARCH_PORT,
};
pub use php_check::{check_php_runtime, PhpRuntimeIssue};
pub use php_fpm_inspector::{
    inspect_php_fpm, inspect_php_fpm_remote, merge_local_sizing, parse_fpm_status,
    parse_php_fpm_conf,
};
pub use redis_check::{check_redis_config, RedisIssue};
pub use redis_inspector::{
    inspect_redis, parse_config_get, parse_redis_info, DEFAULT_REDIS_PORT,
};
