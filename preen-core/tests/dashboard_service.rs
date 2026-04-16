use chrono::Local;
use preen_core::dashboard::{
    DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
    DashboardSnapshot, RegistrySummary,
};
use preen_core::dashboard_provider::DashboardProvider;
use preen_core::dashboard_service::DashboardApplicationService;
use preen_core::error::CoreError;
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
        health_score: 100,
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
fn service_returns_snapshot_for_known_contract() {
    let mut service =
        DashboardApplicationService::new(Box::new(StubProvider::new(vec![Ok(sample_snapshot())])));
    let snapshot = service.next_snapshot().expect("must return snapshot");
    assert!(snapshot.supports_known_contract());
}

#[test]
fn service_maps_unknown_contract_to_compat_error() {
    let mut unknown = sample_snapshot();
    unknown.contract = "preen.dashboard.snapshot.v999".to_string();
    let mut service =
        DashboardApplicationService::new(Box::new(StubProvider::new(vec![Ok(unknown)])));
    let error = service
        .next_snapshot()
        .expect_err("unknown contract must fail");
    match error {
        CoreError::Compat { message } => {
            assert!(message.contains("unsupported dashboard snapshot contract"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn service_maps_provider_failures_to_os_error() {
    let mut service = DashboardApplicationService::new(Box::new(StubProvider::new(vec![Err(
        "collector unavailable".to_string(),
    )])));
    let error = service
        .next_snapshot()
        .expect_err("must map provider error");
    match error {
        CoreError::Os { message } => {
            assert!(message.contains("dashboard provider failed"));
            assert!(message.contains("collector unavailable"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}
