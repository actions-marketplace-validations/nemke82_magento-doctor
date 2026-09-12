//! Root cause forensics investigation data structures and causal chains.

use serde::{Deserialize, Serialize};
use crate::finding::Confidence;

/// Classification of a causal step in the diagnostic chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CausalNodeType {
    /// High-level observable symptom (e.g., 504 gateway timeout, slow storefront TTFB).
    Symptom,
    /// System-level manifestation (e.g., PHP worker pool exhausted, MySQL lock wait).
    Mechanism,
    /// Operational trigger (e.g., minutely cron run, high concurrency traffic).
    Trigger,
    /// Concrete architectural or code flaw (e.g., unindexed query, cacheable="false" layout).
    Culprit,
}

impl std::fmt::Display for CausalNodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CausalNodeType::Symptom => write!(f, "Symptom"),
            CausalNodeType::Mechanism => write!(f, "Mechanism"),
            CausalNodeType::Trigger => write!(f, "Trigger"),
            CausalNodeType::Culprit => write!(f, "Culprit"),
        }
    }
}

/// A discrete step within an evidence-backed causal chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalNode {
    pub node_type: CausalNodeType,
    pub subsystem: String,
    pub description: String,
    pub metric: Option<String>,
}

impl CausalNode {
    pub fn new(node_type: CausalNodeType, subsystem: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            node_type,
            subsystem: subsystem.into(),
            description: description.into(),
            metric: None,
        }
    }

    pub fn with_metric(mut self, metric: impl Into<String>) -> Self {
        self.metric = Some(metric.into());
        self
    }
}

/// Ordered sequence of causes from observable symptom to root culprit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CausalChain {
    pub symptom: String,
    pub nodes: Vec<CausalNode>,
}

impl CausalChain {
    pub fn new(symptom: impl Into<String>) -> Self {
        Self {
            symptom: symptom.into(),
            nodes: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: CausalNode) {
        self.nodes.push(node);
    }
}

/// Synthesized root-cause diagnosis produced by mdoctor investigate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationResult {
    /// Focus area or symptom keyword (e.g. "slow", "checkout", "504", "locks", "cache").
    pub target: String,
    /// Human-readable diagnosis title.
    pub title: String,
    /// Confidence rating based on multi-factor correlation.
    pub confidence: Confidence,
    /// Impact severity score (0 to 100).
    pub impact_score: u32,
    /// Executive summary.
    pub summary: String,
    /// Step-by-step causal chain explaining the mechanics.
    pub causal_chain: CausalChain,
    /// Responsible or implicated Magento modules.
    pub culprit_modules: Vec<String>,
    /// Offending SQL query fingerprints or digests.
    pub culprit_queries: Vec<String>,
    /// Concrete actionable remediation steps.
    pub remediation_steps: Vec<String>,
    /// Safe verification CLI or MySQL commands.
    pub verification_commands: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_causal_chain_building() {
        let mut chain = CausalChain::new("504 Gateway Timeout");
        chain.add_node(CausalNode::new(CausalNodeType::Symptom, "PHP-FPM", "Pool 95% saturated"));
        chain.add_node(CausalNode::new(CausalNodeType::Mechanism, "MySQL", "Lock wait on sales_order_grid").with_metric("wait_time: 14s"));
        chain.add_node(CausalNode::new(CausalNodeType::Culprit, "Vendor_OrderSync", "Missing index on created_at"));

        assert_eq!(chain.nodes.len(), 3);
        assert_eq!(chain.nodes[0].node_type, CausalNodeType::Symptom);
        assert_eq!(chain.nodes[2].node_type, CausalNodeType::Culprit);
    }
}
