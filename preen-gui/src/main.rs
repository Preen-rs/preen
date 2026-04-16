mod dashboard_runtime;
mod dashboard_status;
mod plugin_status;

use preen_core::config::AppConfig;
use preen_core::plugin::{PluginCheckId, PluginCheckStatus, PluginRunSummary};

fn main() {
    let app_config = AppConfig::default();
    let sample = PluginRunSummary {
        overall_passed: false,
        duration_ms: 27,
        checks: vec![
            PluginCheckStatus::new(PluginCheckId::SignatureVerified, true),
            PluginCheckStatus::new(PluginCheckId::TrustVerified, false),
        ],
        detail_code: Some("preflight_signature_or_trust_failed".to_string()),
    };
    println!("Preen GUI is starting up...");
    match dashboard_runtime::load_view_model() {
        Ok(view) => {
            println!(
                "dashboard view loaded: health={} cpu={:?} mem={:?}",
                view.header.health_score, view.cpu.total_usage_pct, view.memory.used_pct
            );
        }
        Err(error) => {
            println!("dashboard_snapshot_error: {error}");
        }
    }
    println!("{}", plugin_status::summary_title(&sample));
    for item in plugin_status::failed_checks(&sample) {
        println!("failed_check_default: {item}");
    }
    for item in plugin_status::failed_checks_with_language(&sample, &app_config.language) {
        println!("failed_check: {item}");
    }
    for item in plugin_status::failed_checks_with_language(&sample, "de-DE") {
        println!("failed_check_de: {item}");
    }

    let sample_json = r#"{
  "schema_version": 1,
  "kind": "plugin.test_spec",
  "data": {
    "overall_passed": false,
    "duration_ms": 27,
    "checks": [
      { "check": "signature_verified", "passed": true },
      { "check": "trust_verified", "passed": false }
    ]
  }
}"#;
    if let Ok(parsed) = plugin_status::parse_summary_from_cli_json(sample_json) {
        println!("{}", plugin_status::summary_title(&parsed));
        for item in plugin_status::failed_checks_with_language(&parsed, &app_config.language) {
            println!("failed_check: {item}");
        }
    }
}
