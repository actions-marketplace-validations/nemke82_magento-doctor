//! mdoctor_rules: Cross-analysis correlation engine and rule implementations.

pub mod engine;
pub mod explanations;
pub mod impact;
pub mod investigate;
pub mod rules;

pub use engine::{scan_php_sources, CrossAnalysisEngine};
pub use explanations::{get_rule_explanation, RuleExplanation};
pub use impact::{calculate_all_modules_impact, calculate_module_impact};
pub use investigate::investigate_installation;
