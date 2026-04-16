use chrono::Local;
use preen_core::dashboard::{
    DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
    DashboardSnapshot, RegistrySummary,
};
use serde_json::Value;
use std::path::PathBuf;

fn sample_snapshot() -> DashboardSnapshot {
    DashboardSnapshot {
        schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
        contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
        collected_at: Local::now(),
        os: "macos".to_string(),
        arch: "aarch64".to_string(),
        state_dir: PathBuf::from("/tmp/preen"),
        health_score: 95,
        overall_passed: true,
        plugin_count: 0,
        installed_plugins_on_disk: 0,
        checks: Vec::new(),
        warnings: Vec::new(),
        suggested_actions: Vec::new(),
        registry: RegistrySummary::default(),
        metrics: DashboardMetrics::default(),
        plugins: Vec::new(),
    }
}

#[test]
fn dashboard_snapshot_defaults_contract_fields_for_older_payloads() {
    let mut value = serde_json::to_value(sample_snapshot()).expect("serialize snapshot");
    let map = value.as_object_mut().expect("snapshot json must be object");
    map.remove("schema_version");
    map.remove("contract");

    let decoded: DashboardSnapshot =
        serde_json::from_value(Value::Object(map.clone())).expect("deserialize old payload");
    assert_eq!(
        decoded.schema_version, DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
        "older payload must default schema version"
    );
    assert_eq!(
        decoded.contract, DASHBOARD_SNAPSHOT_CONTRACT,
        "older payload must default contract id"
    );
    assert!(
        decoded.supports_known_contract(),
        "defaulted payload must be accepted as known contract"
    );
}
