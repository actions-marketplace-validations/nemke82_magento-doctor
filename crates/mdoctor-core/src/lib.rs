//! mdoctor_core: Fundamental types, normalized models, health scores, and findings.

pub mod drift;
pub mod endpoints;
pub mod finding;
pub mod health;
pub mod impact;
pub mod investigate;
pub mod model;
pub mod safety;
pub mod snapshot;
pub mod uninstall;
pub mod version;

pub use drift::{
    compare_installations, DriftChangeType, DriftReport, FindingsDrift, HealthDrift, MetadataDrift,
    ModuleDrift, PluginDrift, PreferenceDrift, SchemaDrift,
};
pub use endpoints::{Endpoint, EndpointError, HttpTarget, RemoteTargets, ENDPOINTS_FILE};
pub use finding::{Category, Confidence, Finding, Severity};
pub use health::HealthScore;
pub use impact::{ImpactLevel, ModuleImpactScore, RiskDriver};
pub use investigate::{CausalChain, CausalNode, CausalNodeType, InvestigationResult};
pub use model::*;
pub use safety::{SafetyLevel, ScanBudget};
pub use snapshot::DiagnosticSnapshot;
pub use uninstall::{
    calculate_uninstall_impact, DependentModule, TableImpact, UninstallAnalysis, UninstallSafety,
};
pub use version::{banner, CALVER_VERSION, CARGO_PKG_VERSION};
