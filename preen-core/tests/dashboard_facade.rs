use chrono::Local;
use preen_core::dashboard::{
    DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
    DashboardSnapshot, RegistrySummary,
};
use preen_core::dashboard_facade::DashboardFacade;
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
        plugin_count: 1,
        installed_plugins_on_disk: 1,
        checks: Vec::new(),
        warnings: Vec::new(),
        suggested_actions: Vec::new(),
        registry: RegistrySummary::default(),
        metrics: DashboardMetrics {
            disk_free_pct: Some(43.9),
            network_rx_rate_mbps: Some(0.2),
            network_tx_rate_mbps: Some(1.3),
            power_capacity_pct: None,
            power_health: Some("Normal".to_string()),
            network_proxy: Some("TUN".to_string()),
            network_primary_ip: Some("192.168.4.165".to_string()),
            ..DashboardMetrics::default()
        },
        plugins: Vec::new(),
    }
}

#[test]
fn derive_builds_expected_shared_fields() {
    let snapshot = sample_snapshot();
    let derived = DashboardFacade::derive(&snapshot);
    assert_eq!(derived.disk_used_pct, Some(56.1));
    assert_eq!(derived.network_peak_rate_mbps, 1.3);
    assert_eq!(derived.power_health_pct, Some(80.0));
    assert_eq!(derived.proxy_line, "Proxy    TUN · 192.168.4.165");
}

#[test]
fn resolve_battery_health_prefers_capacity_when_present() {
    let value = DashboardFacade::resolve_battery_health_percent(Some(89.0), Some("Fair"));
    assert_eq!(value, Some(89.0));
}

#[test]
fn charging_status_detection_supports_charging_and_charged() {
    assert!(DashboardFacade::is_power_status_charging("charging"));
    assert!(DashboardFacade::is_power_status_charging("Charged"));
    assert!(!DashboardFacade::is_power_status_charging("discharging"));
}
