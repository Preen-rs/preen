use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DASHBOARD_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
pub const DASHBOARD_SNAPSHOT_CONTRACT: &str = "preen.dashboard.snapshot.v1";

fn default_dashboard_snapshot_schema_version() -> u32 {
    DASHBOARD_SNAPSHOT_SCHEMA_VERSION
}

fn default_dashboard_snapshot_contract() -> String {
    DASHBOARD_SNAPSHOT_CONTRACT.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckSeverity {
    Critical,
    Warning,
}

impl CheckSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Warning => "warning",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusCheck {
    pub id: String,
    pub label: String,
    pub severity: CheckSeverity,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRow {
    pub pack_id: String,
    pub version: String,
    pub source: String,
    pub rev: String,
    pub installed: bool,
    pub trusted_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RegistrySummary {
    pub present: bool,
    pub generated_at: Option<String>,
    pub age_days: Option<i64>,
    pub entry_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProcessMetric {
    pub name: String,
    pub cpu_pct: f64,
    pub memory_pct: f64,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DashboardMetrics {
    pub host_name: Option<String>,
    pub os_version: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<usize>,
    pub cpu_usage_pct: Option<f64>,
    pub cpu_core_usage: Vec<f64>,
    pub load_avg_1m: Option<f64>,
    pub load_avg_5m: Option<f64>,
    pub load_avg_15m: Option<f64>,
    pub uptime_seconds: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_used_pct: Option<f64>,
    pub memory_pressure: Option<String>,
    pub disk_total_bytes: Option<u64>,
    pub disk_available_bytes: Option<u64>,
    pub disk_free_pct: Option<f64>,
    pub disk_filesystem: Option<String>,
    pub disk_read_rate_mbps: Option<f64>,
    pub disk_write_rate_mbps: Option<f64>,
    pub process_count: Option<u64>,
    pub top_processes: Vec<ProcessMetric>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub network_rx_rate_mbps: Option<f64>,
    pub network_tx_rate_mbps: Option<f64>,
    pub network_rx_history_mbps: Vec<f64>,
    pub network_tx_history_mbps: Vec<f64>,
    pub network_proxy: Option<String>,
    pub network_primary_ip: Option<String>,
    pub power_level_pct: Option<f64>,
    pub power_status: Option<String>,
    pub power_time_left: Option<String>,
    pub power_health: Option<String>,
    pub power_cycle_count: Option<u64>,
    pub power_capacity_pct: Option<f64>,
    pub cpu_temperature_c: Option<f64>,
    pub battery_temperature_c: Option<f64>,
    pub fan_speed_rpm: Option<u64>,
    pub system_power_watts: Option<f64>,
    pub adapter_power_watts: Option<f64>,
    pub battery_power_watts: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    #[serde(default = "default_dashboard_snapshot_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_dashboard_snapshot_contract")]
    pub contract: String,
    pub collected_at: DateTime<Local>,
    pub os: String,
    pub arch: String,
    pub state_dir: PathBuf,
    pub health_score: u8,
    pub overall_passed: bool,
    pub plugin_count: usize,
    pub installed_plugins_on_disk: usize,
    pub checks: Vec<StatusCheck>,
    pub warnings: Vec<String>,
    pub suggested_actions: Vec<String>,
    pub registry: RegistrySummary,
    pub metrics: DashboardMetrics,
    pub plugins: Vec<PluginRow>,
}

impl DashboardSnapshot {
    pub fn supports_known_contract(&self) -> bool {
        self.schema_version == DASHBOARD_SNAPSHOT_SCHEMA_VERSION
            && self.contract == DASHBOARD_SNAPSHOT_CONTRACT
    }
}

pub fn unsupported_contract_message(snapshot: &DashboardSnapshot) -> String {
    format!(
        "unsupported dashboard snapshot contract: got {} (schema v{}), expected {} (schema v{})",
        snapshot.contract,
        snapshot.schema_version,
        DASHBOARD_SNAPSHOT_CONTRACT,
        DASHBOARD_SNAPSHOT_SCHEMA_VERSION
    )
}
