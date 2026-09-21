//! Version constants and CalVer utilities for Magento Doctor.

/// CalVer formatted release version string, e.g. "v2026.09.12".
pub const CALVER_VERSION: &str = "v2026.09.12";

/// Raw SemVer package version from Cargo.toml.
pub const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Formatted full banner string.
pub fn banner() -> String {
    format!("Magento Doctor {}", CALVER_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_banner() {
        assert_eq!(banner(), "Magento Doctor v2026.09.12");
    }
}
