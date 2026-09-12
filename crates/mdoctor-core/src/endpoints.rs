//! User-supplied service endpoints for clustered and jump-host deployments.
//!
//! When `mdoctor` runs on the same box as the store it can discover most services
//! from `app/etc/env.php` and `/proc`. On a jump host, or on a cluster where PHP-FPM,
//! Varnish, Nginx, Redis and OpenSearch live on separate nodes, the operator has to
//! tell us where to look. [`RemoteTargets`] carries those overrides; every field is
//! optional and falls back to local discovery when absent.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Error raised while parsing an endpoint or loading an endpoint config file.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("empty endpoint")]
    Empty,
    #[error("invalid port in '{0}'")]
    InvalidPort(String),
    #[error("unsupported URL scheme '{0}' (only http is supported; tunnel TLS endpoints over SSH)")]
    UnsupportedScheme(String),
    #[error("cannot read endpoint config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse endpoint config {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// A `host:port` service address, or a unix domain socket path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    /// True when `host` is a filesystem path to a unix socket rather than a hostname.
    #[serde(default)]
    pub is_unix_socket: bool,
}

impl Endpoint {
    /// Parses `host`, `host:port`, `[::1]:port`, or a `/path/to.sock` unix socket.
    ///
    /// A bare host uses `default_port`. Any URL scheme and trailing path are stripped,
    /// so `redis://cache-1.internal:6380/2` parses as `cache-1.internal:6380`.
    pub fn parse(raw: &str, default_port: u16) -> Result<Self, EndpointError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(EndpointError::Empty);
        }

        // Unix sockets are passed through untouched; they carry no port.
        if trimmed.starts_with('/') {
            return Ok(Self {
                host: trimmed.to_string(),
                port: 0,
                is_unix_socket: true,
            });
        }

        // Strip any scheme prefix and anything from the first path separator onwards.
        let without_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
        let authority = without_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(without_scheme);
        if authority.is_empty() {
            return Err(EndpointError::Empty);
        }

        // Bracketed IPv6 literal, optionally followed by :port.
        if let Some(rest) = authority.strip_prefix('[') {
            let (host, after) = rest.split_once(']').ok_or_else(|| EndpointError::InvalidPort(raw.to_string()))?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| EndpointError::InvalidPort(raw.to_string()))?,
                None => default_port,
            };
            return Ok(Self {
                host: host.to_string(),
                port,
                is_unix_socket: false,
            });
        }

        // A bare IPv6 literal has several colons and no port; only split on the last
        // colon when exactly one is present.
        match authority.split_once(':') {
            Some((host, port_str)) if !port_str.contains(':') => Ok(Self {
                host: host.to_string(),
                port: port_str
                    .parse()
                    .map_err(|_| EndpointError::InvalidPort(raw.to_string()))?,
                is_unix_socket: false,
            }),
            _ => Ok(Self {
                host: authority.to_string(),
                port: default_port,
                is_unix_socket: false,
            }),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_unix_socket {
            write!(f, "{}", self.host)
        } else if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// An `http://host:port/path` target for a status page or storefront probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl HttpTarget {
    /// Parses an `http://` URL, or a bare `host[:port][/path]` using `default_port`.
    ///
    /// `https://` is rejected: mdoctor speaks plain HTTP only, and silently probing
    /// the wrong port would be worse than saying so.
    pub fn parse(raw: &str, default_port: u16) -> Result<Self, EndpointError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(EndpointError::Empty);
        }

        let (scheme, rest) = match trimmed.split_once("://") {
            Some((s, rest)) => (s.to_ascii_lowercase(), rest),
            None => ("http".to_string(), trimmed),
        };
        if scheme != "http" {
            return Err(EndpointError::UnsupportedScheme(scheme));
        }

        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        let endpoint = Endpoint::parse(authority, default_port)?;
        Ok(Self {
            host: endpoint.host,
            port: endpoint.port,
            path: if path.is_empty() { "/".to_string() } else { path.to_string() },
        })
    }
}

impl std::fmt::Display for HttpTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "http://[{}]:{}{}", self.host, self.port, self.path)
        } else {
            write!(f, "http://{}:{}{}", self.host, self.port, self.path)
        }
    }
}

/// Where each service actually lives, for cluster and jump-host runs.
///
/// Secrets are never serialized, so a `RemoteTargets` embedded in a snapshot or
/// JSON report cannot leak the credentials it was built with.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteTargets {
    /// Varnish admin/listen address, probed over HTTP (default port 6081).
    pub varnish: Option<Endpoint>,
    /// PHP-FPM status page, e.g. `http://web-1.internal/status`.
    pub fpm_status_url: Option<HttpTarget>,
    /// Explicit PHP-FPM pool config path, when it is not in a standard location.
    pub fpm_conf: Option<PathBuf>,
    /// Nginx `stub_status` page, e.g. `http://web-1.internal/nginx_status`.
    pub nginx_status_url: Option<HttpTarget>,
    /// Default/cache Redis or Valkey instance.
    pub redis_cache: Option<Endpoint>,
    /// Session Redis or Valkey instance.
    pub redis_session: Option<Endpoint>,
    /// Page-cache Redis or Valkey instance.
    pub redis_page_cache: Option<Endpoint>,
    /// OpenSearch or Elasticsearch coordinating node (default port 9200).
    pub opensearch: Option<Endpoint>,
    /// Storefront base URL used for cache-header probes.
    pub storefront_url: Option<HttpTarget>,

    /// Redis `requirepass` value. Never serialized.
    #[serde(skip_serializing)]
    pub redis_password: Option<String>,
    /// OpenSearch basic-auth credentials as `user:password`. Never serialized.
    #[serde(skip_serializing)]
    pub opensearch_auth: Option<String>,
}

/// Default filename looked up in the Magento root and the working directory.
pub const ENDPOINTS_FILE: &str = "mdoctor.toml";

impl RemoteTargets {
    /// Loads endpoint overrides from a TOML file.
    pub fn load(path: &Path) -> Result<Self, EndpointError> {
        let content = std::fs::read_to_string(path).map_err(|source| EndpointError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&content).map_err(|source| EndpointError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Parses endpoint overrides from TOML content.
    ///
    /// Accepts both a bare table and an `[endpoints]` section so a future
    /// `mdoctor.toml` can grow other sections without breaking existing files.
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        #[derive(Deserialize)]
        struct Wrapper {
            endpoints: RemoteTargets,
        }

        match toml::from_str::<Wrapper>(content) {
            Ok(w) => Ok(w.endpoints),
            Err(_) => toml::from_str(content),
        }
    }

    /// Looks for `mdoctor.toml` in the Magento root, then the working directory.
    pub fn discover(magento_root: Option<&Path>) -> Option<(PathBuf, Result<Self, EndpointError>)> {
        let mut candidates = Vec::new();
        if let Some(root) = magento_root {
            candidates.push(root.join(ENDPOINTS_FILE));
        }
        candidates.push(PathBuf::from(ENDPOINTS_FILE));

        candidates
            .into_iter()
            .find(|p| p.is_file())
            .map(|p| (p.clone(), Self::load(&p)))
    }

    /// Overlays `other` on top of `self`; every value present in `other` wins.
    ///
    /// Used to let command-line flags override an `mdoctor.toml` file.
    pub fn overlay(&mut self, other: Self) {
        macro_rules! take {
            ($($field:ident),+ $(,)?) => {
                $(if other.$field.is_some() { self.$field = other.$field; })+
            };
        }
        take!(
            varnish,
            fpm_status_url,
            fpm_conf,
            nginx_status_url,
            redis_cache,
            redis_session,
            redis_page_cache,
            opensearch,
            storefront_url,
            redis_password,
            opensearch_auth,
        );
    }

    /// True when no override at all was supplied.
    pub fn is_empty(&self) -> bool {
        self.varnish.is_none()
            && self.fpm_status_url.is_none()
            && self.fpm_conf.is_none()
            && self.nginx_status_url.is_none()
            && self.redis_cache.is_none()
            && self.redis_session.is_none()
            && self.redis_page_cache.is_none()
            && self.opensearch.is_none()
            && self.storefront_url.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_endpoint_forms() {
        assert_eq!(
            Endpoint::parse("cache-1.internal", 6379).unwrap(),
            Endpoint { host: "cache-1.internal".into(), port: 6379, is_unix_socket: false }
        );
        assert_eq!(Endpoint::parse("10.0.0.5:6380", 6379).unwrap().port, 6380);
        assert_eq!(Endpoint::parse("  10.0.0.5:6380  ", 6379).unwrap().port, 6380);
    }

    #[test]
    fn test_parse_endpoint_strips_scheme_and_path() {
        let ep = Endpoint::parse("redis://cache-1.internal:6380/2", 6379).unwrap();
        assert_eq!(ep.host, "cache-1.internal");
        assert_eq!(ep.port, 6380);
    }

    #[test]
    fn test_parse_endpoint_ipv6() {
        let bracketed = Endpoint::parse("[2001:db8::1]:9200", 9200).unwrap();
        assert_eq!(bracketed.host, "2001:db8::1");
        assert_eq!(bracketed.port, 9200);
        assert_eq!(bracketed.to_string(), "[2001:db8::1]:9200");

        // A bare IPv6 literal has no port to split off.
        let bare = Endpoint::parse("2001:db8::1", 9200).unwrap();
        assert_eq!(bare.host, "2001:db8::1");
        assert_eq!(bare.port, 9200);
    }

    #[test]
    fn test_parse_endpoint_unix_socket() {
        let ep = Endpoint::parse("/var/run/redis/redis.sock", 6379).unwrap();
        assert!(ep.is_unix_socket);
        assert_eq!(ep.to_string(), "/var/run/redis/redis.sock");
    }

    #[test]
    fn test_parse_endpoint_rejects_bad_port() {
        assert!(Endpoint::parse("host:notaport", 6379).is_err());
        assert!(Endpoint::parse("host:99999", 6379).is_err());
        assert!(Endpoint::parse("   ", 6379).is_err());
    }

    #[test]
    fn test_parse_http_target() {
        let t = HttpTarget::parse("http://web-1.internal:8080/status?json", 80).unwrap();
        assert_eq!(t.host, "web-1.internal");
        assert_eq!(t.port, 8080);
        assert_eq!(t.path, "/status?json");

        let bare = HttpTarget::parse("web-1.internal", 80).unwrap();
        assert_eq!(bare.port, 80);
        assert_eq!(bare.path, "/");
    }

    #[test]
    fn test_http_target_rejects_https() {
        let err = HttpTarget::parse("https://shop.example.com/", 80).unwrap_err();
        assert!(matches!(err, EndpointError::UnsupportedScheme(_)));
    }

    #[test]
    fn test_load_targets_from_toml_section() {
        let toml_src = r#"
[endpoints]
varnish = { host = "varnish-1.internal", port = 6081 }
redis_cache = { host = "cache-1.internal", port = 6379 }
fpm_status_url = { host = "web-1.internal", port = 80, path = "/status?json" }
"#;
        let targets = RemoteTargets::from_toml(toml_src).unwrap();
        assert_eq!(targets.varnish.unwrap().host, "varnish-1.internal");
        assert_eq!(targets.redis_cache.unwrap().port, 6379);
        assert_eq!(targets.fpm_status_url.unwrap().path, "/status?json");
    }

    #[test]
    fn test_load_targets_from_bare_toml() {
        let targets = RemoteTargets::from_toml(
            r#"opensearch = { host = "search-1.internal", port = 9200 }"#,
        )
        .unwrap();
        assert_eq!(targets.opensearch.unwrap().host, "search-1.internal");
    }

    #[test]
    fn test_secrets_are_not_serialized() {
        let targets = RemoteTargets {
            redis_password: Some("hunter2".into()),
            opensearch_auth: Some("admin:hunter2".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&targets).unwrap();
        assert!(!json.contains("hunter2"), "secrets must never be serialized: {}", json);
    }

    #[test]
    fn test_overlay_prefers_other() {
        let mut base = RemoteTargets {
            redis_cache: Some(Endpoint::parse("from-file", 6379).unwrap()),
            opensearch: Some(Endpoint::parse("search-file", 9200).unwrap()),
            ..Default::default()
        };
        base.overlay(RemoteTargets {
            redis_cache: Some(Endpoint::parse("from-cli", 6379).unwrap()),
            ..Default::default()
        });

        assert_eq!(base.redis_cache.unwrap().host, "from-cli");
        assert_eq!(base.opensearch.unwrap().host, "search-file", "untouched values survive");
    }
}
