//! Redis configuration and database collision inspection.

use mdoctor_core::SanitizedEnvConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisIssue {
    SameDatabaseForSessionAndCache { session_db: String, cache_db: String },
    SameDatabaseForSessionAndPageCache { session_db: String, fpc_db: String },
    SameDatabaseForCacheAndPageCache { cache_db: String, fpc_db: String },
}

/// Determine if two Redis endpoints point to the same Redis instance.
/// Returns false if both hosts/instances are specified and are clearly distinct.
fn is_same_redis_instance(host_a: Option<&str>, host_b: Option<&str>) -> bool {
    match (host_a, host_b) {
        (Some(a), Some(b)) => {
            let norm_a = normalize_redis_host(a);
            let norm_b = normalize_redis_host(b);
            norm_a == norm_b
        }
        // If one or both are omitted, in standard Magento setup they default to the local default instance
        _ => true,
    }
}

fn normalize_redis_host(h: &str) -> String {
    let trimmed = h.trim().to_lowercase();
    if trimmed == "localhost" {
        "127.0.0.1".to_string()
    } else if trimmed.starts_with("localhost:") {
        trimmed.replacen("localhost", "127.0.0.1", 1)
    } else {
        trimmed
    }
}

/// Analyze Redis configuration for collision bugs.
pub fn check_redis_config(config: &SanitizedEnvConfig) -> Vec<RedisIssue> {
    let mut issues = Vec::new();

    let session_db = config.redis_session_db.as_deref();
    let cache_db = config.redis_cache_db.as_deref();
    let fpc_db = config.redis_page_cache_db.as_deref();

    let session_host = config.redis_session_host.as_deref();
    let cache_host = config.redis_cache_host.as_deref();
    let fpc_host = config.redis_page_cache_host.as_deref();

    if let (Some(s), Some(c)) = (session_db, cache_db) {
        if s == c && is_same_redis_instance(session_host, cache_host) {
            issues.push(RedisIssue::SameDatabaseForSessionAndCache {
                session_db: s.to_string(),
                cache_db: c.to_string(),
            });
        }
    }

    if let (Some(s), Some(f)) = (session_db, fpc_db) {
        if s == f && is_same_redis_instance(session_host, fpc_host) {
            issues.push(RedisIssue::SameDatabaseForSessionAndPageCache {
                session_db: s.to_string(),
                fpc_db: f.to_string(),
            });
        }
    }

    if let (Some(c), Some(f)) = (cache_db, fpc_db) {
        if c == f && is_same_redis_instance(cache_host, fpc_host) {
            issues.push(RedisIssue::SameDatabaseForCacheAndPageCache {
                cache_db: c.to_string(),
                fpc_db: f.to_string(),
            });
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_collision_detection_same_host() {
        let config = SanitizedEnvConfig {
            redis_session_host: Some("127.0.0.1:6379".to_string()),
            redis_cache_host: Some("localhost:6379".to_string()),
            redis_session_db: Some("0".to_string()),
            redis_cache_db: Some("0".to_string()),
            redis_page_cache_db: Some("1".to_string()),
            ..Default::default()
        };

        let issues = check_redis_config(&config);
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            issues[0],
            RedisIssue::SameDatabaseForSessionAndCache { .. }
        ));
    }

    #[test]
    fn test_redis_no_collision_when_different_hosts() {
        let config = SanitizedEnvConfig {
            redis_session_host: Some("redis-session:6379".to_string()),
            redis_cache_host: Some("redis-cache:6379".to_string()),
            redis_page_cache_host: Some("redis-fpc:6379".to_string()),
            redis_session_db: Some("0".to_string()),
            redis_cache_db: Some("0".to_string()),
            redis_page_cache_db: Some("0".to_string()),
            ..Default::default()
        };

        let issues = check_redis_config(&config);
        assert!(issues.is_empty(), "Different hostnames must not be reported as collision");
    }

    #[test]
    fn test_redis_no_collision_when_different_ports() {
        let config = SanitizedEnvConfig {
            redis_session_host: Some("127.0.0.1:6379".to_string()),
            redis_cache_host: Some("127.0.0.1:6380".to_string()),
            redis_session_db: Some("0".to_string()),
            redis_cache_db: Some("0".to_string()),
            ..Default::default()
        };

        let issues = check_redis_config(&config);
        assert!(issues.is_empty(), "Different ports on same host must not be reported as collision");
    }
}
