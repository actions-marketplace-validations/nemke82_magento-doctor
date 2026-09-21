//! Parser for app/etc/env.php safely redacting all secrets.

use std::path::Path;
use mdoctor_core::{MagentoMode, SanitizedEnvConfig, SecretValue};
use regex::Regex;

/// Result of parsing app/etc/env.php.
#[derive(Debug, Default)]
pub struct ParsedEnv {
    pub mode: MagentoMode,
    pub config: SanitizedEnvConfig,
    pub raw_db_password: Option<String>, // Only used for live connection in mdoctor_db, never serialized or exposed!
    /// Redis `requirepass` from env.php, for live probes only. Never serialized.
    pub raw_redis_password: Option<String>,
}

/// Parse app/etc/env.php safely.
pub fn parse_env_php(env_file_path: &Path) -> ParsedEnv {
    let mut parsed = ParsedEnv::default();
    let content = match std::fs::read_to_string(env_file_path) {
        Ok(c) => c,
        Err(_) => return parsed,
    };

    // 1. Parse MAGE_MODE
    let mode_re = Regex::new(r#"['"]MAGE_MODE['"]\s*=>\s*['"]([a-zA-Z0-9_-]+)['"]"#).unwrap();
    if let Some(caps) = mode_re.captures(&content) {
        parsed.mode = match caps[1].to_lowercase().as_str() {
            "production" => MagentoMode::Production,
            "developer" => MagentoMode::Developer,
            "default" => MagentoMode::DefaultMode,
            "maintenance" => MagentoMode::Maintenance,
            _ => MagentoMode::Unknown,
        };
    }

    // 2. Parse Crypt key presence
    let crypt_re = Regex::new(r#"['"]crypt['"]\s*=>\s*\[[^\]]*['"]key['"]\s*=>\s*['"]([^'"]*)['"]"#).unwrap();
    if let Some(caps) = crypt_re.captures(&content) {
        let key_str = &caps[1];
        parsed.config.crypt_key_secret = if !key_str.trim().is_empty() {
            SecretValue::Present
        } else {
            SecretValue::Missing
        };
    }

    // 3. Parse Database connection
    let db_host_re = Regex::new(r#"['"]host['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap();
    if let Some(caps) = db_host_re.captures(&content) {
        parsed.config.db_host = Some(caps[1].to_string());
    }

    let db_name_re = Regex::new(r#"['"]dbname['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap();
    if let Some(caps) = db_name_re.captures(&content) {
        parsed.config.db_name = Some(caps[1].to_string());
    }

    let db_user_re = Regex::new(r#"['"]username['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap();
    if let Some(caps) = db_user_re.captures(&content) {
        parsed.config.db_user = Some(caps[1].to_string());
    }

    let db_pass_re = Regex::new(r#"['"]password['"]\s*=>\s*['"]([^'"]*)['"]"#).unwrap();
    if let Some(caps) = db_pass_re.captures(&content) {
        let pass = caps[1].to_string();
        if !pass.trim().is_empty() {
            parsed.config.db_password_secret = SecretValue::Present;
            parsed.raw_db_password = Some(pass);
        } else {
            parsed.config.db_password_secret = SecretValue::Missing;
        }
    }

    // Helper to extract host/server/path and port
    fn extract_redis_host_port(slice: &str) -> Option<String> {
        let host_re = Regex::new(r#"['"](?:host|server|path)['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap();
        let port_re = Regex::new(r#"['"]port['"]\s*=>\s*['"]?([0-9]+)['"]?"#).unwrap();

        let host = host_re.captures(slice).map(|c| c[1].to_string());
        let port = port_re.captures(slice).map(|c| c[1].to_string());

        match (host, port) {
            (Some(h), Some(p)) => {
                if h.starts_with('/') || h.contains(':') {
                    Some(h)
                } else {
                    Some(format!("{}:{}", h, p))
                }
            }
            (Some(h), None) => Some(h),
            (None, Some(p)) => Some(format!("127.0.0.1:{}", p)),
            (None, None) => None,
        }
    }

    /// Returns the contents of the first bracketed array in `slice`, brackets matched.
    fn matching_bracket_slice(slice: &str) -> Option<&str> {
        let open = slice.find('[')?;
        let mut depth = 0usize;
        for (offset, ch) in slice[open..].char_indices() {
            match ch {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&slice[open + 1..open + offset]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    // 4. Redis session database & host
    if let Some(session_pos) = content.find("'session'").or_else(|| content.find("\"session\"")) {
        let session_slice = &content[session_pos..];
        let redis_session_db_re = Regex::new(r#"['"]database['"]\s*=>\s*['"]?([0-9]+)['"]?"#).unwrap();
        if let Some(caps) = redis_session_db_re.captures(session_slice) {
            parsed.config.redis_session_db = Some(caps[1].to_string());
        }
        parsed.config.redis_session_host = extract_redis_host_port(session_slice);
    }

    // 5. Redis cache & page cache database & host
    if let Some(cache_pos) = content.find("'cache'").or_else(|| content.find("\"cache\"")) {
        let cache_slice = &content[cache_pos..];

        // Default cache
        if let Some(def_match) = Regex::new(r#"['"]default['"]\s*=>\s*\[([\s\S]*?)(?:['"]page_cache['"]|\]\s*\])"#).unwrap().captures(cache_slice) {
            let def_slice = &def_match[1];
            let redis_cache_db_re = Regex::new(r#"['"]database['"]\s*=>\s*['"]?([0-9]+)['"]?"#).unwrap();
            if let Some(caps) = redis_cache_db_re.captures(def_slice) {
                parsed.config.redis_cache_db = Some(caps[1].to_string());
            }
            parsed.config.redis_cache_host = extract_redis_host_port(def_slice);
        } else {
            let redis_cache_db_re = Regex::new(r#"['"]default['"]\s*=>\s*\[[\s\S]*?['"]database['"]\s*=>\s*['"]?([0-9]+)['"]?"#).unwrap();
            if let Some(caps) = redis_cache_db_re.captures(cache_slice) {
                parsed.config.redis_cache_db = Some(caps[1].to_string());
            }
        }

        // Page cache
        if let Some(fpc_match) = Regex::new(r#"['"]page_cache['"]\s*=>\s*\[([\s\S]*?)(?:\]\s*,\s*['"]|\]\s*\]\s*\])"#).unwrap().captures(cache_slice) {
            let fpc_slice = &fpc_match[1];
            let redis_fpc_db_re = Regex::new(r#"['"]database['"]\s*=>\s*['"]?([0-9]+)['"]?"#).unwrap();
            if let Some(caps) = redis_fpc_db_re.captures(fpc_slice) {
                parsed.config.redis_page_cache_db = Some(caps[1].to_string());
            }
            parsed.config.redis_page_cache_host = extract_redis_host_port(fpc_slice);
        } else {
            let redis_fpc_db_re = Regex::new(r#"['"]page_cache['"]\s*=>\s*\[[\s\S]*?['"]database['"]\s*=>\s*['"]?([0-9]+)['"]?"#).unwrap();
            if let Some(caps) = redis_fpc_db_re.captures(cache_slice) {
                parsed.config.redis_page_cache_db = Some(caps[1].to_string());
            }
        }
    }

    // 6. http_cache_hosts: the only reliable signal that Magento is configured to
    // front the store with Varnish (or another purgeable proxy tier).
    if let Some(hosts_pos) = content
        .find("'http_cache_hosts'")
        .or_else(|| content.find("\"http_cache_hosts\""))
    {
        let slice = &content[hosts_pos..];
        // Each host is its own nested array, so the first "]," closes only the first
        // entry: walk brackets to find where the http_cache_hosts array really ends.
        let block = match matching_bracket_slice(slice) {
            Some(inner) => inner,
            None => slice,
        };

        let host_re = Regex::new(r#"['"]host['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap();
        let port_re = Regex::new(r#"['"]port['"]\s*=>\s*['"]?([0-9]+)['"]?"#).unwrap();
        let ports: Vec<&str> = port_re.captures_iter(block).map(|c| c.get(1).unwrap().as_str()).collect();

        for (idx, caps) in host_re.captures_iter(block).enumerate() {
            let host = caps[1].to_string();
            parsed.config.http_cache_hosts.push(match ports.get(idx) {
                Some(port) if !host.contains(':') => format!("{}:{}", host, port),
                _ => host,
            });
        }
    }

    // 7. Redis password, shared across cache and session backends in practice.
    let redis_pass_re = Regex::new(r#"['"]password['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap();
    for caps in redis_pass_re.captures_iter(&content) {
        let candidate = caps[1].to_string();
        // The db password is captured separately; anything else is a backend secret.
        if parsed.raw_db_password.as_deref() != Some(candidate.as_str()) {
            parsed.raw_redis_password = Some(candidate);
            break;
        }
    }

    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_php_sample() {
        let sample = r#"<?php
return [
    'backend' => ['frontName' => 'admin'],
    'crypt' => ['key' => 'topsecretkey123'],
    'db' => [
        'connection' => [
            'default' => [
                'host' => '127.0.0.1',
                'dbname' => 'magento_test',
                'username' => 'db_user',
                'password' => 'super_secret_db_pass',
            ]
        ]
    ],
    'MAGE_MODE' => 'production',
    'session' => [
        'save' => 'redis',
        'redis' => [
            'host' => '127.0.0.1',
            'database' => '2'
        ]
    ],
    'cache' => [
        'frontend' => [
            'default' => ['backend_options' => ['database' => '0']],
            'page_cache' => ['backend_options' => ['database' => '1']]
        ]
    ]
];
"#;
        let temp = std::env::temp_dir().join("test_env.php");
        std::fs::write(&temp, sample).unwrap();

        let parsed = parse_env_php(&temp);
        assert_eq!(parsed.mode, MagentoMode::Production);
        assert_eq!(parsed.config.db_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(parsed.config.db_name.as_deref(), Some("magento_test"));
        assert_eq!(parsed.config.db_user.as_deref(), Some("db_user"));
        assert_eq!(parsed.config.db_password_secret, SecretValue::Present);
        assert_eq!(parsed.config.crypt_key_secret, SecretValue::Present);
        assert_eq!(parsed.config.redis_session_db.as_deref(), Some("2"));
        assert_eq!(parsed.config.redis_cache_db.as_deref(), Some("0"));
        assert_eq!(parsed.config.redis_page_cache_db.as_deref(), Some("1"));

        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn test_parse_http_cache_hosts() {
        let sample = r#"<?php
return [
    'http_cache_hosts' => [
        ['host' => 'varnish-1.internal', 'port' => '6081'],
        ['host' => 'varnish-2.internal', 'port' => '6081'],
    ],
    'MAGE_MODE' => 'production',
];
"#;
        let temp = std::env::temp_dir().join("test_env_varnish.php");
        std::fs::write(&temp, sample).unwrap();

        let parsed = parse_env_php(&temp);
        assert_eq!(
            parsed.config.http_cache_hosts,
            vec!["varnish-1.internal:6081".to_string(), "varnish-2.internal:6081".to_string()]
        );

        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn test_no_http_cache_hosts_means_not_configured_for_varnish() {
        let temp = std::env::temp_dir().join("test_env_no_varnish.php");
        std::fs::write(&temp, "<?php\nreturn ['MAGE_MODE' => 'production'];\n").unwrap();

        let parsed = parse_env_php(&temp);
        assert!(parsed.config.http_cache_hosts.is_empty());

        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn test_parse_redis_password_distinct_from_db_password() {
        let sample = r#"<?php
return [
    'db' => ['connection' => ['default' => [
        'host' => 'db-1', 'dbname' => 'm2', 'username' => 'm2', 'password' => 'db_secret',
    ]]],
    'cache' => ['frontend' => ['default' => ['backend_options' => [
        'server' => 'cache-1', 'port' => '6379', 'database' => '0', 'password' => 'redis_secret',
    ]]]],
];
"#;
        let temp = std::env::temp_dir().join("test_env_redis_pass.php");
        std::fs::write(&temp, sample).unwrap();

        let parsed = parse_env_php(&temp);
        assert_eq!(parsed.raw_db_password.as_deref(), Some("db_secret"));
        assert_eq!(parsed.raw_redis_password.as_deref(), Some("redis_secret"));

        let _ = std::fs::remove_file(temp);
    }
}
