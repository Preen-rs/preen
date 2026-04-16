use chrono::Local;
use preen_core::check_list_view::CheckListView;
use preen_core::dashboard::{
    CheckSeverity, DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
    DashboardMetrics, DashboardSnapshot, RegistrySummary, StatusCheck,
};
use std::path::PathBuf;

fn sample_snapshot() -> DashboardSnapshot {
    DashboardSnapshot {
        schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
        contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
        collected_at: Local::now(),
        os: "macos".to_string(),
        arch: "aarch64".to_string(),
        state_dir: PathBuf::from("/tmp/preen"),
        health_score: 93,
        overall_passed: false,
        plugin_count: 0,
        installed_plugins_on_disk: 0,
        checks: vec![
            StatusCheck {
                id: "state_dir_exists".to_string(),
                label: "State directory exists".to_string(),
                severity: CheckSeverity::Critical,
                passed: true,
                message: "state dir exists".to_string(),
            },
            StatusCheck {
                id: "registry_readable".to_string(),
                label: "Registry index readable".to_string(),
                severity: CheckSeverity::Warning,
                passed: false,
                message: "registry index missing".to_string(),
            },
        ],
        warnings: vec!["registry index is missing".to_string()],
        suggested_actions: vec!["run registry update".to_string()],
        registry: RegistrySummary::default(),
        metrics: DashboardMetrics::default(),
        plugins: Vec::new(),
    }
}

#[test]
fn check_list_view_maps_labels_and_messages() {
    let snapshot = sample_snapshot();
    let view = CheckListView::from_snapshot(&snapshot);

    assert_eq!(view.total_checks, 2);
    assert!(view.items[0].passed);
    assert_eq!(view.items[0].severity_label, "critical");
    assert!(!view.items[1].passed);
    assert_eq!(view.items[1].severity_label, "warning");
    assert_eq!(view.items[1].message, "registry index missing");
}
