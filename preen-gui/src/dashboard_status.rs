use preen_core::dashboard::{DashboardSnapshot, unsupported_contract_message};

pub fn contract_error(snapshot: &DashboardSnapshot) -> Option<String> {
    if snapshot.supports_known_contract() {
        return None;
    }
    Some(unsupported_contract_message(snapshot))
}

#[cfg(test)]
mod tests {
    use super::contract_error;
    use chrono::Local;
    use preen_core::dashboard::{
        DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
        DashboardSnapshot, RegistrySummary,
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
    fn contract_guard_accepts_known_snapshot() {
        let snapshot = sample_snapshot();
        assert!(contract_error(&snapshot).is_none());
    }

    #[test]
    fn contract_guard_rejects_unknown_snapshot() {
        let mut snapshot = sample_snapshot();
        snapshot.schema_version = 2;
        let error = contract_error(&snapshot).expect("must fail contract guard");
        assert!(error.contains("unsupported dashboard snapshot contract"));
    }
}
