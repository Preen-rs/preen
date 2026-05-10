use crate::dashboard::{DashboardSnapshot, ProcessMetric};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PerformanceLevel {
    Normal,
    Elevated,
    High,
}

impl PerformanceLevel {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceTopProcess {
    pub name: String,
    pub cpu_pct: f64,
    pub memory_pct: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformanceTaskKind {
    Inspect,
    SafeMaintenance,
    AdminMaintenance,
}

impl PerformanceTaskKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::SafeMaintenance => "safe",
            Self::AdminMaintenance => "admin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PerformanceTaskRisk {
    Low,
    Medium,
    High,
}

impl PerformanceTaskRisk {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceOptimizationTask {
    pub id: String,
    pub label: String,
    pub description: String,
    pub kind: PerformanceTaskKind,
    pub risk: PerformanceTaskRisk,
    pub recommended: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceViewModel {
    pub overall_level: PerformanceLevel,
    pub primary_bottleneck: String,
    pub cpu_usage_pct: Option<f64>,
    pub cpu_temperature_c: Option<f64>,
    pub load_per_core: Option<f64>,
    pub memory_used_pct: Option<f64>,
    pub memory_pressure: Option<String>,
    pub process_count: Option<u64>,
    pub disk_io_rate_mbps: Option<f64>,
    pub top_processes: Vec<PerformanceTopProcess>,
    pub optimization_tasks: Vec<PerformanceOptimizationTask>,
    pub recommendations: Vec<String>,
}

impl PerformanceViewModel {
    pub fn from_snapshot(snapshot: &DashboardSnapshot) -> Self {
        let metrics = &snapshot.metrics;
        let cpu_level = classify_percent(metrics.cpu_usage_pct, 60.0, 85.0);
        let memory_level = classify_percent(metrics.memory_used_pct, 70.0, 85.0);
        let load_per_core = load_per_core(metrics.load_avg_1m, metrics.cpu_cores);
        let load_level = classify_optional(load_per_core, 0.70, 1.00);
        let temperature_level = classify_optional(metrics.cpu_temperature_c, 75.0, 85.0);
        let disk_io_rate_mbps = Some(
            metrics.disk_read_rate_mbps.unwrap_or(0.0)
                + metrics.disk_write_rate_mbps.unwrap_or(0.0),
        );
        let disk_level = classify_optional(disk_io_rate_mbps, 50.0, 120.0);
        let overall_level = [
            cpu_level,
            memory_level,
            load_level,
            temperature_level,
            disk_level,
        ]
        .into_iter()
        .max()
        .unwrap_or(PerformanceLevel::Normal);

        let primary_bottleneck = primary_bottleneck([
            ("CPU", cpu_level),
            ("Memory", memory_level),
            ("Load", load_level),
            ("Temperature", temperature_level),
            ("Disk I/O", disk_level),
        ]);

        Self {
            overall_level,
            primary_bottleneck,
            cpu_usage_pct: metrics.cpu_usage_pct,
            cpu_temperature_c: metrics.cpu_temperature_c,
            load_per_core,
            memory_used_pct: metrics.memory_used_pct,
            memory_pressure: metrics.memory_pressure.clone(),
            process_count: metrics.process_count,
            disk_io_rate_mbps,
            top_processes: top_processes(&metrics.top_processes),
            optimization_tasks: optimization_tasks(
                cpu_level,
                memory_level,
                load_level,
                temperature_level,
                disk_level,
                metrics,
            ),
            recommendations: recommendations(
                cpu_level,
                memory_level,
                load_level,
                temperature_level,
                disk_level,
            ),
        }
    }
}

fn classify_percent(value: Option<f64>, elevated: f64, high: f64) -> PerformanceLevel {
    classify_optional(value.map(|item| item.clamp(0.0, 100.0)), elevated, high)
}

fn classify_optional(value: Option<f64>, elevated: f64, high: f64) -> PerformanceLevel {
    match value {
        Some(item) if item >= high => PerformanceLevel::High,
        Some(item) if item >= elevated => PerformanceLevel::Elevated,
        _ => PerformanceLevel::Normal,
    }
}

fn load_per_core(load_avg_1m: Option<f64>, cores: Option<usize>) -> Option<f64> {
    let cores = cores.filter(|value| *value > 0)? as f64;
    load_avg_1m.map(|load| load / cores)
}

fn primary_bottleneck(levels: [(&str, PerformanceLevel); 5]) -> String {
    for target in [PerformanceLevel::High, PerformanceLevel::Elevated] {
        if let Some((label, level)) = levels.iter().find(|(_, level)| *level == target) {
            return format!("{label} ({})", level.label());
        }
    }
    "none".to_string()
}

fn top_processes(processes: &[ProcessMetric]) -> Vec<PerformanceTopProcess> {
    let mut rows = processes
        .iter()
        .map(|process| PerformanceTopProcess {
            name: process.name.clone(),
            cpu_pct: process.cpu_pct,
            memory_pct: process.memory_pct,
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .cpu_pct
            .partial_cmp(&left.cpu_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                right
                    .memory_pct
                    .partial_cmp(&left.memory_pct)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    rows.truncate(5);
    rows
}

fn optimization_tasks(
    cpu: PerformanceLevel,
    memory: PerformanceLevel,
    load: PerformanceLevel,
    temperature: PerformanceLevel,
    disk: PerformanceLevel,
    metrics: &crate::dashboard::DashboardMetrics,
) -> Vec<PerformanceOptimizationTask> {
    let mut tasks = vec![
        PerformanceOptimizationTask {
            id: "inspect_top_processes".to_string(),
            label: "Inspect top processes".to_string(),
            description: "Review the highest CPU and memory processes before applying changes"
                .to_string(),
            kind: PerformanceTaskKind::Inspect,
            risk: PerformanceTaskRisk::Low,
            recommended: cpu >= PerformanceLevel::Elevated
                || memory >= PerformanceLevel::Elevated
                || load >= PerformanceLevel::Elevated,
            reason: process_pressure_reason(cpu, memory, load),
        },
        PerformanceOptimizationTask {
            id: "flush_dns_cache".to_string(),
            label: "Flush DNS cache".to_string(),
            description: "Refresh local DNS cache when network state looks stale or proxy settings changed"
                .to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: metrics
                .network_proxy
                .as_deref()
                .map(|proxy| !proxy.trim().is_empty() && proxy != "none")
                .unwrap_or(false),
            reason: "network maintenance only; does not change user data".to_string(),
        },
        PerformanceOptimizationTask {
            id: "sync_filesystem_buffers".to_string(),
            label: "Sync filesystem buffers".to_string(),
            description: "Ask the OS to flush filesystem buffers before heavy cleanup or shutdown"
                .to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: disk >= PerformanceLevel::Elevated,
            reason: if disk >= PerformanceLevel::Elevated {
                "disk I/O is elevated".to_string()
            } else {
                "optional before long cleanup runs".to_string()
            },
        },
        PerformanceOptimizationTask {
            id: "memory_pressure_relief".to_string(),
            label: "Relieve memory pressure".to_string(),
            description: "Use OS-native memory pressure relief only after inspecting memory-heavy apps"
                .to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: memory >= PerformanceLevel::High
                || memory_pressure_is_elevated(metrics.memory_pressure.as_deref()),
            reason: memory_pressure_reason(memory, metrics.memory_pressure.as_deref()),
        },
        PerformanceOptimizationTask {
            id: "defer_heavy_maintenance".to_string(),
            label: "Defer heavy maintenance".to_string(),
            description: "Avoid long-running cleanup while temperature, CPU, or disk pressure is high"
                .to_string(),
            kind: PerformanceTaskKind::Inspect,
            risk: PerformanceTaskRisk::Low,
            recommended: temperature >= PerformanceLevel::Elevated
                || cpu >= PerformanceLevel::High
                || disk >= PerformanceLevel::High,
            reason: defer_reason(cpu, temperature, disk),
        },
    ];

    tasks.sort_by(|left, right| {
        right
            .recommended
            .cmp(&left.recommended)
            .then_with(|| task_priority(&left.id).cmp(&task_priority(&right.id)))
            .then_with(|| left.risk.cmp(&right.risk))
            .then_with(|| left.id.cmp(&right.id))
    });
    tasks
}

fn task_priority(id: &str) -> u8 {
    match id {
        "inspect_top_processes" => 0,
        "memory_pressure_relief" => 1,
        "flush_dns_cache" => 2,
        "sync_filesystem_buffers" => 3,
        "defer_heavy_maintenance" => 4,
        _ => 9,
    }
}

fn process_pressure_reason(
    cpu: PerformanceLevel,
    memory: PerformanceLevel,
    load: PerformanceLevel,
) -> String {
    if cpu >= PerformanceLevel::Elevated {
        return format!("CPU pressure is {}", cpu.label());
    }
    if load >= PerformanceLevel::Elevated {
        return format!("load per core is {}", load.label());
    }
    if memory >= PerformanceLevel::Elevated {
        return format!("memory pressure is {}", memory.label());
    }
    "baseline visibility task".to_string()
}

fn memory_pressure_is_elevated(value: Option<&str>) -> bool {
    matches!(
        value.map(str::to_ascii_lowercase).as_deref(),
        Some("warn" | "warning" | "elevated" | "critical" | "high")
    )
}

fn memory_pressure_reason(level: PerformanceLevel, pressure: Option<&str>) -> String {
    if memory_pressure_is_elevated(pressure) {
        return format!(
            "OS reports memory pressure {}",
            pressure.unwrap_or("elevated")
        );
    }
    if level >= PerformanceLevel::High {
        return "memory usage is high".to_string();
    }
    "only useful when memory pressure is elevated".to_string()
}

fn defer_reason(
    cpu: PerformanceLevel,
    temperature: PerformanceLevel,
    disk: PerformanceLevel,
) -> String {
    if temperature >= PerformanceLevel::Elevated {
        return format!("temperature is {}", temperature.label());
    }
    if cpu >= PerformanceLevel::High {
        return "CPU is already saturated".to_string();
    }
    if disk >= PerformanceLevel::High {
        return "disk I/O is already saturated".to_string();
    }
    "system can run maintenance now".to_string()
}

fn recommendations(
    cpu: PerformanceLevel,
    memory: PerformanceLevel,
    load: PerformanceLevel,
    temperature: PerformanceLevel,
    disk: PerformanceLevel,
) -> Vec<String> {
    let mut items = Vec::new();
    if cpu >= PerformanceLevel::Elevated || load >= PerformanceLevel::Elevated {
        items.push("Review high CPU processes before running cleanup tasks".to_string());
    }
    if memory >= PerformanceLevel::Elevated {
        items.push("Close memory-heavy apps or inspect background services".to_string());
    }
    if temperature >= PerformanceLevel::Elevated {
        items.push("Let the machine cool down before long-running operations".to_string());
    }
    if disk >= PerformanceLevel::Elevated {
        items.push("Avoid heavy disk cleanup while I/O is already high".to_string());
    }
    if items.is_empty() {
        items.push("System load looks normal; performance actions are optional".to_string());
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::{
        DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
        RegistrySummary,
    };
    use std::path::PathBuf;

    fn snapshot(metrics: DashboardMetrics) -> DashboardSnapshot {
        DashboardSnapshot {
            schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
            contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
            collected_at: std::time::SystemTime::now().into(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            state_dir: PathBuf::from("/tmp/preen"),
            health_score: 88,
            overall_passed: true,
            plugin_count: 0,
            installed_plugins_on_disk: 0,
            checks: Vec::new(),
            warnings: Vec::new(),
            suggested_actions: Vec::new(),
            registry: RegistrySummary::default(),
            metrics,
            plugins: Vec::new(),
        }
    }

    #[test]
    fn performance_view_model_classifies_primary_bottleneck() {
        let model = PerformanceViewModel::from_snapshot(&snapshot(DashboardMetrics {
            cpu_usage_pct: Some(91.0),
            cpu_cores: Some(8),
            load_avg_1m: Some(9.2),
            memory_used_pct: Some(64.0),
            top_processes: vec![
                ProcessMetric {
                    name: "WindowServer".to_string(),
                    cpu_pct: 12.0,
                    memory_pct: 1.0,
                },
                ProcessMetric {
                    name: "Arc".to_string(),
                    cpu_pct: 55.0,
                    memory_pct: 6.0,
                },
            ],
            ..DashboardMetrics::default()
        }));

        assert_eq!(model.overall_level, PerformanceLevel::High);
        assert_eq!(model.primary_bottleneck, "CPU (high)");
        assert_eq!(model.load_per_core, Some(1.15));
        assert_eq!(model.top_processes[0].name, "Arc");
        assert_eq!(model.optimization_tasks[0].id, "inspect_top_processes");
        assert!(model.optimization_tasks[0].recommended);
        assert!(
            model
                .recommendations
                .iter()
                .any(|item| item.contains("high CPU"))
        );
    }

    #[test]
    fn performance_view_model_reports_normal_load() {
        let model = PerformanceViewModel::from_snapshot(&snapshot(DashboardMetrics {
            cpu_usage_pct: Some(12.0),
            cpu_cores: Some(8),
            load_avg_1m: Some(1.0),
            memory_used_pct: Some(35.0),
            ..DashboardMetrics::default()
        }));

        assert_eq!(model.overall_level, PerformanceLevel::Normal);
        assert_eq!(model.primary_bottleneck, "none");
        assert_eq!(
            model.recommendations,
            vec!["System load looks normal; performance actions are optional"]
        );
        assert!(
            model
                .optimization_tasks
                .iter()
                .any(|task| task.id == "flush_dns_cache" && !task.recommended)
        );
    }

    #[test]
    fn performance_view_model_recommends_memory_relief_for_pressure() {
        let model = PerformanceViewModel::from_snapshot(&snapshot(DashboardMetrics {
            memory_used_pct: Some(68.0),
            memory_pressure: Some("critical".to_string()),
            ..DashboardMetrics::default()
        }));

        let task = model
            .optimization_tasks
            .iter()
            .find(|task| task.id == "memory_pressure_relief")
            .expect("memory pressure task");
        assert!(task.recommended);
        assert_eq!(task.kind, PerformanceTaskKind::AdminMaintenance);
    }
}
