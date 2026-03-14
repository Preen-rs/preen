mod plugin_status;

use preen_core::Command;
use preen_core::config::AppConfig;
use preen_core::plugin::{PluginCheckId, PluginCheckStatus, PluginRunSummary};

fn main() {
    let app_config = AppConfig::default();
    println!(
        "Preen TUI is starting up... (Core Command: {:?})",
        Command::StartScan(Vec::new())
    );
    let sample = PluginRunSummary {
        overall_passed: true,
        duration_ms: 18,
        checks: vec![
            PluginCheckStatus::new(PluginCheckId::SignatureVerified, true),
            PluginCheckStatus::new(PluginCheckId::TrustVerified, true),
        ],
        detail_code: None,
    };
    for line in plugin_status::render_summary_lines_with_language(&sample, &app_config.language) {
        println!("{line}");
    }
    for line in plugin_status::render_summary_lines(&sample) {
        println!("{line}");
    }
    for line in plugin_status::render_summary_lines_with_language(&sample, "de-DE") {
        println!("{line}");
    }

    let sample_json = r#"{
  "schema_version": 1,
  "kind": "plugin.test",
  "data": {
    "overall_passed": true,
    "duration_ms": 18,
    "checks": [
      { "check": "signature_verified", "passed": true },
      { "check": "trust_verified", "passed": true }
    ]
  }
}"#;
    if let Ok(parsed) = plugin_status::parse_summary_from_cli_json(sample_json) {
        for line in plugin_status::render_summary_lines_with_language(&parsed, &app_config.language)
        {
            println!("{line}");
        }
    }
}
