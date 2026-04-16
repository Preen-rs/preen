use chrono::Local;
use preen_core::dashboard::{
    DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
    DashboardSnapshot, RegistrySummary,
};
use preen_core::dashboard_view::DashboardViewModel;
use std::path::PathBuf;

fn sample_snapshot() -> DashboardSnapshot {
    DashboardSnapshot {
        schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
        contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
        collected_at: Local::now(),
        os: "macos".to_string(),
        arch: "aarch64".to_string(),
        state_dir: PathBuf::from("/tmp/preen"),
        health_score: 91,
        overall_passed: true,
        plugin_count: 0,
        installed_plugins_on_disk: 0,
        checks: Vec::new(),
        warnings: Vec::new(),
        suggested_actions: Vec::new(),
        registry: RegistrySummary::default(),
        metrics: DashboardMetrics {
            host_name: Some("Daniz-MacBook-Pro.local".to_string()),
            cpu_model: Some("Apple M2".to_string()),
            os_version: Some("macOS 26.4.1".to_string()),
            cpu_core_usage: vec![12.0, 62.0, 28.0, 51.0],
            disk_free_pct: Some(43.9),
            network_rx_rate_mbps: Some(0.5),
            network_tx_rate_mbps: Some(3.4),
            power_capacity_pct: None,
            power_health: Some("Normal".to_string()),
            power_status: Some("Charging".to_string()),
            network_proxy: Some("TUN".to_string()),
            network_primary_ip: Some("192.168.4.165".to_string()),
            ..DashboardMetrics::default()
        },
        plugins: Vec::new(),
    }
}

#[test]
fn view_model_derives_shared_fields() {
    let snapshot = sample_snapshot();
    let view = DashboardViewModel::from_snapshot(&snapshot);
    assert_eq!(view.header.health_score, 91);
    assert_eq!(
        view.header.host_name.as_deref(),
        Some("Daniz-MacBook-Pro.local")
    );
    assert_eq!(view.header.cpu_model.as_deref(), Some("Apple M2"));
    assert_eq!(view.header.os_label.as_deref(), Some("macOS 26.4.1"));
    assert_eq!(view.disk.used_pct, Some(56.1));
    assert_eq!(view.network.peak_rate_mbps, 3.4);
    assert_eq!(view.power.health_pct, Some(80.0));
    assert!(view.power.status_is_charging);
    assert_eq!(view.network.proxy_line, "Proxy    TUN · 192.168.4.165");
}

#[test]
fn view_model_sorts_cpu_cores_descending() {
    let snapshot = sample_snapshot();
    let view = DashboardViewModel::from_snapshot(&snapshot);
    let indexes = view
        .cpu
        .top_cores
        .iter()
        .map(|entry| entry.core_index)
        .collect::<Vec<_>>();
    assert_eq!(indexes, vec![2, 4, 3, 1]);
}
