use chrono::Local;
use preen_core::dashboard::{
    CheckSeverity, DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
    DashboardMetrics, DashboardSnapshot, PluginRow, RegistrySummary, StatusCheck,
};
use preen_core::plugin_list_view::PluginListView;
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
        plugin_count: 2,
        installed_plugins_on_disk: 2,
        checks: vec![StatusCheck {
            id: "state_dir_exists".to_string(),
            label: "State directory exists".to_string(),
            severity: CheckSeverity::Critical,
            passed: true,
            message: "ok".to_string(),
        }],
        warnings: Vec::new(),
        suggested_actions: Vec::new(),
        registry: RegistrySummary::default(),
        metrics: DashboardMetrics::default(),
        plugins: vec![
            PluginRow {
                pack_id: "preen-rs.homebrew".to_string(),
                version: "1.0.7".to_string(),
                source: "registry".to_string(),
                rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
                installed: true,
                trusted_identity: "https://github.com/Preen-rs/preen-rulepack-homebrew/.github/workflows/release-manual.yml@refs/heads/main".to_string(),
            },
            PluginRow {
                pack_id: "preen-rs.sample".to_string(),
                version: "0.2.0".to_string(),
                source: "git".to_string(),
                rev: "abcdef1234567890".to_string(),
                installed: false,
                trusted_identity: "https://github.com/Preen-rs/preen-rulepack-sample/.github/workflows/release-manual.yml@refs/heads/main".to_string(),
            },
        ],
    }
}

#[test]
fn plugin_list_view_copies_plugin_rows() {
    let snapshot = sample_snapshot();
    let view = PluginListView::from_snapshot(&snapshot);

    assert_eq!(view.total_plugins, 2);
    assert_eq!(view.items[0].pack_id, "preen-rs.homebrew");
    assert_eq!(view.items[0].version, "1.0.7");
    assert_eq!(view.items[0].source, "registry");
    assert!(view.items[0].installed);
    assert_eq!(view.items[1].pack_id, "preen-rs.sample");
    assert!(!view.items[1].installed);
}
