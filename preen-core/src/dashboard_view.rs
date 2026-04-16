use crate::dashboard::DashboardSnapshot;
use crate::dashboard_facade::DashboardFacade;

#[derive(Debug, Clone, PartialEq)]
pub struct CpuCoreUsageRow {
    pub core_index: usize,
    pub usage_pct: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessUsageRow {
    pub name: String,
    pub cpu_pct: f64,
    pub memory_pct: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HeaderSectionView {
    pub health_score: u8,
    pub host_name: Option<String>,
    pub cpu_model: Option<String>,
    pub os_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CpuSectionView {
    pub total_usage_pct: Option<f64>,
    pub temperature_c: Option<f64>,
    pub core_count: Option<usize>,
    pub load_avg_1m: Option<f64>,
    pub load_avg_5m: Option<f64>,
    pub load_avg_15m: Option<f64>,
    pub top_cores: Vec<CpuCoreUsageRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemorySectionView {
    pub used_pct: Option<f64>,
    pub total_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub uptime_seconds: Option<u64>,
    pub process_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiskSectionView {
    pub used_pct: Option<f64>,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub filesystem: Option<String>,
    pub read_rate_mbps: Option<f64>,
    pub write_rate_mbps: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PowerSectionView {
    pub level_pct: Option<f64>,
    pub health_pct: Option<f64>,
    pub status: Option<String>,
    pub time_left: Option<String>,
    pub health_word: Option<String>,
    pub cycle_count: Option<u64>,
    pub battery_temperature_c: Option<f64>,
    pub system_power_watts: Option<f64>,
    pub adapter_power_watts: Option<f64>,
    pub battery_power_watts: Option<f64>,
    pub status_is_charging: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkSectionView {
    pub peak_rate_mbps: f64,
    pub rx_rate_mbps: Option<f64>,
    pub tx_rate_mbps: Option<f64>,
    pub rx_history_mbps: Vec<f64>,
    pub tx_history_mbps: Vec<f64>,
    pub proxy_line: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessesSectionView {
    pub rows: Vec<ProcessUsageRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DashboardViewModel {
    pub header: HeaderSectionView,
    pub cpu: CpuSectionView,
    pub memory: MemorySectionView,
    pub disk: DiskSectionView,
    pub power: PowerSectionView,
    pub network: NetworkSectionView,
    pub processes: ProcessesSectionView,
}

impl DashboardViewModel {
    pub fn from_snapshot(snapshot: &DashboardSnapshot) -> Self {
        let derived = DashboardFacade::derive(snapshot);
        let mut top_cpu_cores = snapshot
            .metrics
            .cpu_core_usage
            .iter()
            .copied()
            .enumerate()
            .map(|(index, usage_pct)| CpuCoreUsageRow {
                core_index: index + 1,
                usage_pct,
            })
            .collect::<Vec<_>>();
        top_cpu_cores.sort_by(|left, right| {
            right
                .usage_pct
                .partial_cmp(&left.usage_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let power_status = snapshot.metrics.power_status.clone();
        let power_status_is_charging =
            DashboardFacade::is_power_status_charging(power_status.as_deref().unwrap_or("unknown"));
        let process_rows = snapshot
            .metrics
            .top_processes
            .iter()
            .map(|process| ProcessUsageRow {
                name: process.name.clone(),
                cpu_pct: process.cpu_pct,
                memory_pct: process.memory_pct,
            })
            .collect::<Vec<_>>();

        Self {
            header: HeaderSectionView {
                health_score: snapshot.health_score,
                host_name: snapshot.metrics.host_name.clone(),
                cpu_model: snapshot
                    .metrics
                    .cpu_model
                    .clone()
                    .or_else(|| Some(snapshot.arch.clone())),
                os_label: snapshot
                    .metrics
                    .os_version
                    .clone()
                    .or_else(|| Some(snapshot.os.to_uppercase())),
            },
            cpu: CpuSectionView {
                total_usage_pct: snapshot.metrics.cpu_usage_pct,
                temperature_c: snapshot.metrics.cpu_temperature_c,
                core_count: snapshot.metrics.cpu_cores,
                load_avg_1m: snapshot.metrics.load_avg_1m,
                load_avg_5m: snapshot.metrics.load_avg_5m,
                load_avg_15m: snapshot.metrics.load_avg_15m,
                top_cores: top_cpu_cores,
            },
            memory: MemorySectionView {
                used_pct: snapshot.metrics.memory_used_pct,
                total_bytes: snapshot.metrics.memory_total_bytes,
                used_bytes: snapshot.metrics.memory_used_bytes,
                uptime_seconds: snapshot.metrics.uptime_seconds,
                process_count: snapshot.metrics.process_count,
            },
            disk: DiskSectionView {
                used_pct: derived.disk_used_pct,
                total_bytes: snapshot.metrics.disk_total_bytes,
                available_bytes: snapshot.metrics.disk_available_bytes,
                filesystem: snapshot.metrics.disk_filesystem.clone(),
                read_rate_mbps: snapshot.metrics.disk_read_rate_mbps,
                write_rate_mbps: snapshot.metrics.disk_write_rate_mbps,
            },
            power: PowerSectionView {
                level_pct: snapshot.metrics.power_level_pct,
                health_pct: derived.power_health_pct,
                status: power_status,
                time_left: snapshot.metrics.power_time_left.clone(),
                health_word: snapshot.metrics.power_health.clone(),
                cycle_count: snapshot.metrics.power_cycle_count,
                battery_temperature_c: snapshot.metrics.battery_temperature_c,
                system_power_watts: snapshot.metrics.system_power_watts,
                adapter_power_watts: snapshot.metrics.adapter_power_watts,
                battery_power_watts: snapshot.metrics.battery_power_watts,
                status_is_charging: power_status_is_charging,
            },
            network: NetworkSectionView {
                peak_rate_mbps: derived.network_peak_rate_mbps,
                rx_rate_mbps: snapshot.metrics.network_rx_rate_mbps,
                tx_rate_mbps: snapshot.metrics.network_tx_rate_mbps,
                rx_history_mbps: snapshot.metrics.network_rx_history_mbps.clone(),
                tx_history_mbps: snapshot.metrics.network_tx_history_mbps.clone(),
                proxy_line: derived.proxy_line,
            },
            processes: ProcessesSectionView { rows: process_rows },
        }
    }
}
