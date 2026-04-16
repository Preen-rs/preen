use chrono::Local;
use preen_core::dashboard::{
    DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
    DashboardSnapshot, RegistrySummary,
};
use preen_core::dashboard_provider::DashboardProvider;
use std::collections::VecDeque;
use std::path::PathBuf;

struct StubProvider {
    responses: VecDeque<Result<DashboardSnapshot, String>>,
}

impl StubProvider {
    fn new(responses: Vec<Result<DashboardSnapshot, String>>) -> Self {
        Self {
            responses: responses.into(),
        }
    }
}

impl DashboardProvider for StubProvider {
    fn next_snapshot(&mut self) -> Result<DashboardSnapshot, String> {
        self.responses
            .pop_front()
            .unwrap_or_else(|| Err("no response queued".to_string()))
    }
}

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
fn checked_snapshot_accepts_known_contract() {
    let snapshot = sample_snapshot();
    let mut provider = StubProvider::new(vec![Ok(snapshot.clone())]);
    let actual = provider
        .next_snapshot_checked()
        .expect("known contract must pass");
    assert_eq!(actual.contract, snapshot.contract);
}

#[test]
fn checked_snapshot_rejects_unknown_contract() {
    let mut snapshot = sample_snapshot();
    snapshot.contract = "preen.dashboard.snapshot.v2".to_string();
    let mut provider = StubProvider::new(vec![Ok(snapshot)]);
    let error = provider
        .next_snapshot_checked()
        .expect_err("unknown contract must fail");
    assert!(error.contains("unsupported dashboard snapshot contract"));
}

#[test]
fn checked_snapshot_propagates_provider_error() {
    let mut provider = StubProvider::new(vec![Err("provider failed".to_string())]);
    let error = provider
        .next_snapshot_checked()
        .expect_err("provider errors must be forwarded");
    assert_eq!(error, "provider failed");
}
