//! Terminal and JSON renderers for Root Cause Investigation results.

use colored::*;
use mdoctor_core::{CausalNodeType, Confidence, InvestigationResult};

/// Renders a rich terminal report detailing synthesized root-cause diagnoses and causal chains.
pub fn render_investigate_terminal(results: &[InvestigationResult], target_symptom: Option<&str>) -> String {
    let mut out = String::new();

    out.push_str(&format!("\n{}\n", "═══ MAGENTO DOCTOR: ROOT CAUSE INVESTIGATION ═══".cyan().bold()));
    if let Some(target) = target_symptom {
        out.push_str(&format!("Focused symptom query: {}\n\n", target.yellow().bold()));
    } else {
        out.push_str("Multi-dimensional root-cause correlation across Runtime, Database, Cache, and Code\n\n");
    }

    if results.is_empty() {
        out.push_str(&format!(
            "{}\n\n",
            "✓ No critical root-cause bottlenecks identified for this query!".green().bold()
        ));
        out.push_str("All examined subsystems (MySQL query latency, Redis session safety, PHP-FPM queues, FPC layouts, and OpenSearch shards) are within operational thresholds.\n");
        return out;
    }

    out.push_str(&format!(
        "Discovered {} potential root-cause failure pattern(s) ranked by impact:\n\n",
        results.len().to_string().bold()
    ));

    for (idx, res) in results.iter().enumerate() {
        let conf_str = match res.confidence {
            Confidence::High => "HIGH CONFIDENCE".green().bold(),
            Confidence::Medium => "MEDIUM CONFIDENCE".yellow().bold(),
            Confidence::Low => "LOW CONFIDENCE".white(),
        };

        let impact_badge = if res.impact_score >= 90 {
            format!("IMPACT: {}/100 (CRITICAL)", res.impact_score).red().bold()
        } else if res.impact_score >= 70 {
            format!("IMPACT: {}/100 (HIGH)", res.impact_score).yellow().bold()
        } else {
            format!("IMPACT: {}/100 (MODERATE)", res.impact_score).cyan()
        };

        out.push_str("┌──────────────────────────────────────────────────────────────────────────────┐\n");
        out.push_str(&format!("│ [ROOT CAUSE #{}] {}\n", idx + 1, res.title.bold()));
        out.push_str(&format!("│ {} | {}\n", conf_str, impact_badge));
        out.push_str("├──────────────────────────────────────────────────────────────────────────────┤\n");
        out.push_str(&format!("│ Summary:\n│   {}\n│\n", res.summary));

        // Causal Chain
        out.push_str("│ Causal Chain (Observed Symptom ➔ Culprit):\n");
        for (n_idx, node) in res.causal_chain.nodes.iter().enumerate() {
            let type_str = match node.node_type {
                CausalNodeType::Symptom => "[Symptom]  ".red().bold(),
                CausalNodeType::Mechanism => "[Mechanism]".yellow().bold(),
                CausalNodeType::Trigger => "[Trigger]  ".cyan().bold(),
                CausalNodeType::Culprit => "[Culprit]  ".magenta().bold(),
            };

            let metric_str = node
                .metric
                .as_ref()
                .map(|m| format!(" ({})", m.dimmed()))
                .unwrap_or_default();

            // Pad the plain subsystem name before colouring it: `{:<15}` counts the
            // ANSI escape bytes, so padding a coloured string misaligns the column.
            let subsystem = format!("{:<15}", node.subsystem);
            out.push_str(&format!(
                "│   {} {} {}{}\n",
                type_str,
                subsystem.bold(),
                node.description,
                metric_str
            ));
            if n_idx + 1 < res.causal_chain.nodes.len() {
                out.push_str("│        ⬇\n");
            }
        }

        // What the diagnosis is actually built on.
        if !res.evidence_basis.is_empty() {
            out.push_str("│ Evidence Measured:\n");
            for item in &res.evidence_basis {
                out.push_str(&format!("│   • {}\n", item));
            }
        }

        // Culprit Modules
        if !res.culprit_modules.is_empty() {
            out.push_str(&format!("│\n│ Implicated Modules: {}\n", res.culprit_modules.join(", ").cyan().bold()));
        }
        if res.culprit_modules.is_empty() && !res.evidence_basis.is_empty() {
            out.push_str("│\n");
        }

        // Culprit Queries
        if !res.culprit_queries.is_empty() {
            out.push_str("│ Culprit Query Digests:\n");
            for q in &res.culprit_queries {
                out.push_str(&format!("│   • {}\n", q.dimmed()));
            }
        }

        // Remediation
        if !res.remediation_steps.is_empty() {
            out.push_str("│\n│ Recommended Action Plan:\n");
            for (r_idx, rem) in res.remediation_steps.iter().enumerate() {
                out.push_str(&format!("│   {}. {}\n", r_idx + 1, rem.green()));
            }
        }

        // Verification Commands
        if !res.verification_commands.is_empty() {
            out.push_str("│\n│ Verification Commands:\n");
            for cmd in &res.verification_commands {
                out.push_str(&format!("│   $ {}\n", cmd.cyan()));
            }
        }

        out.push_str("└──────────────────────────────────────────────────────────────────────────────┘\n\n");
    }

    out
}

/// Serializes investigation results to formatted JSON.
pub fn render_investigate_json(results: &[InvestigationResult]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdoctor_core::{CausalChain, CausalNode};

    #[test]
    fn test_render_investigate_terminal() {
        let mut chain = CausalChain::new("Test");
        chain.add_node(CausalNode::new(CausalNodeType::Symptom, "MySQL", "Lock wait"));
        chain.add_node(CausalNode::new(CausalNodeType::Culprit, "Vendor_Test", "Missing index"));

        let res = InvestigationResult {
            target: "test".to_string(),
            title: "Test Bottleneck".to_string(),
            confidence: Confidence::High,
            impact_score: 95,
            summary: "Test summary description".to_string(),
            evidence_basis: vec!["Measured signal A".to_string(), "Measured signal B".to_string()],
            causal_chain: chain,
            culprit_modules: vec!["Vendor_Test".to_string()],
            culprit_queries: vec!["SELECT * FROM test".to_string()],
            remediation_steps: vec!["Add index".to_string()],
            verification_commands: vec!["EXPLAIN test".to_string()],
        };

        let output = render_investigate_terminal(&[res], Some("slow"));
        assert!(output.contains("Test Bottleneck"));
        assert!(output.contains("Vendor_Test"));
        assert!(output.contains("[Culprit]"));
        assert!(output.contains("Evidence Measured"));
        assert!(output.contains("Measured signal A"));
    }
}
