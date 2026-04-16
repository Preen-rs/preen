use crate::dashboard_status;
use preen_core::dashboard::DashboardSnapshot;
use preen_core::dashboard_provider::DashboardProvider;
use preen_core::dashboard_service::DashboardApplicationService;
use preen_core::dashboard_view::DashboardViewModel;
use preen_os::dashboard::SnapshotCollector;

pub fn load_snapshot() -> Result<DashboardSnapshot, String> {
    load_snapshot_from_provider(Box::new(SnapshotCollector::new()))
}

pub fn load_view_model() -> Result<DashboardViewModel, String> {
    let snapshot = load_snapshot()?;
    Ok(DashboardViewModel::from_snapshot(&snapshot))
}

pub fn load_snapshot_from_provider(
    provider: Box<dyn DashboardProvider>,
) -> Result<DashboardSnapshot, String> {
    let mut service = DashboardApplicationService::new(provider);
    let snapshot = service.next_snapshot().map_err(|error| error.to_string())?;
    if let Some(error) = dashboard_status::contract_error(&snapshot) {
        return Err(error);
    }
    Ok(snapshot)
}

pub fn load_view_model_from_provider(
    provider: Box<dyn DashboardProvider>,
) -> Result<DashboardViewModel, String> {
    let snapshot = load_snapshot_from_provider(provider)?;
    Ok(DashboardViewModel::from_snapshot(&snapshot))
}

#[cfg(test)]
mod tests {
    use super::{load_snapshot_from_provider, load_view_model_from_provider};
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
    fn gui_runtime_accepts_known_snapshot_contract() {
        let snapshot = sample_snapshot();
        let actual = load_snapshot_from_provider(Box::new(StubProvider::new(vec![Ok(snapshot)])))
            .expect("known contract must pass");
        assert!(actual.supports_known_contract());
    }

    #[test]
    fn gui_runtime_forwards_contract_failure() {
        let mut snapshot = sample_snapshot();
        snapshot.contract = "preen.dashboard.snapshot.v2".to_string();
        let error = load_snapshot_from_provider(Box::new(StubProvider::new(vec![Ok(snapshot)])))
            .expect_err("unknown contract must fail");
        assert!(error.contains("unsupported dashboard snapshot contract"));
    }

    #[test]
    fn gui_runtime_builds_shared_dashboard_view_model() {
        let mut snapshot = sample_snapshot();
        snapshot.metrics.cpu_usage_pct = Some(42.0);
        snapshot.metrics.power_level_pct = Some(55.0);
        let view = load_view_model_from_provider(Box::new(StubProvider::new(vec![Ok(snapshot)])))
            .expect("view model must build from valid snapshot");
        assert_eq!(view.cpu.total_usage_pct, Some(42.0));
        assert_eq!(view.power.level_pct, Some(55.0));
    }
}
