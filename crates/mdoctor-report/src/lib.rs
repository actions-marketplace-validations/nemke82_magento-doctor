//! mdoctor_report: Terminal, JSON, Markdown, and SARIF output renderers.

pub mod drift_fmt;
pub mod graph_fmt;
pub mod impact_fmt;
pub mod investigate_fmt;
pub mod json_fmt;
pub mod markdown_fmt;
pub mod sarif_fmt;
pub mod terminal;
pub mod uninstall_fmt;

pub use drift_fmt::{render_drift_json, render_drift_markdown, render_drift_terminal};
pub use graph_fmt::render_mermaid_graph;
pub use impact_fmt::render_impact_table;
pub use investigate_fmt::{render_investigate_json, render_investigate_terminal};
pub use json_fmt::render_json_report;
pub use markdown_fmt::render_markdown_report;
pub use sarif_fmt::render_sarif_report;
pub use terminal::render_terminal_report;
pub use uninstall_fmt::render_uninstall_terminal;
