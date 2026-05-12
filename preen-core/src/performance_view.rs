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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerformanceTaskTarget {
    pub id: String,
    pub label: String,
    pub description: String,
    pub path: Option<String>,
    pub selected_by_default: bool,
    pub requires_admin: bool,
    pub risk: PerformanceTaskRisk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerformanceTaskDetail {
    pub task_id: String,
    pub title: String,
    pub summary: String,
    pub notes: Vec<String>,
    pub targets: Vec<PerformanceTaskTarget>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceAnalyzeOutput {
    pub model: PerformanceViewModel,
    pub details: Vec<PerformanceTaskDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerformanceOptimizeSelection {
    pub task_id: String,
    pub target_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerformanceOptimizeResult {
    pub lines: Vec<String>,
    pub completed_task_ids: Vec<String>,
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
                snapshot.os.as_str(),
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
    os: &str,
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
            description:
                "Refresh local DNS cache when network state looks stale or proxy settings changed"
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
            id: "refresh_finder_caches".to_string(),
            label: "Refresh Finder caches".to_string(),
            description: "Refresh QuickLook thumbnails and icon services caches".to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: false,
            reason: "useful when previews or icons look stale".to_string(),
        },
        PerformanceOptimizationTask {
            id: "cleanup_saved_states".to_string(),
            label: "Clean saved app states".to_string(),
            description: "Remove old saved application state folders after review".to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: false,
            reason: "resets stale window/session state for selected apps".to_string(),
        },
        PerformanceOptimizationTask {
            id: "repair_broken_preferences".to_string(),
            label: "Repair broken preferences".to_string(),
            description: "Detect corrupted plist preferences and move broken files to Trash"
                .to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: false,
            reason: "only targets invalid preference files after plist validation".to_string(),
        },
        PerformanceOptimizationTask {
            id: "optimize_app_databases".to_string(),
            label: "Optimize app databases".to_string(),
            description: "Compact selected Mail, Safari, and Messages SQLite databases safely"
                .to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: false,
            reason: "skips busy apps, large databases, and failed integrity checks".to_string(),
        },
        PerformanceOptimizationTask {
            id: "repair_launch_services".to_string(),
            label: "Repair LaunchServices".to_string(),
            description: "Rebuild app association metadata used by Open With and Finder"
                .to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: false,
            reason: "fixes stale app associations and duplicate Open With entries".to_string(),
        },
        PerformanceOptimizationTask {
            id: "rebuild_font_cache".to_string(),
            label: "Rebuild font cache".to_string(),
            description: "Clear font databases after browser safety checks".to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: false,
            reason: "skips when browsers are running to avoid cache conflicts".to_string(),
        },
        PerformanceOptimizationTask {
            id: "refresh_dock".to_string(),
            label: "Refresh Dock".to_string(),
            description: "Refresh Dock cache and restart Dock to fix stale icons".to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: false,
            reason: "Dock restarts automatically and rebuilds its visual cache".to_string(),
        },
        PerformanceOptimizationTask {
            id: "inspect_login_items".to_string(),
            label: "Inspect login items".to_string(),
            description:
                "Review startup agents and choose which items should stop launching at login"
                    .to_string(),
            kind: PerformanceTaskKind::Inspect,
            risk: PerformanceTaskRisk::Low,
            recommended: metrics.process_count.is_some_and(|count| count > 300),
            reason: if metrics.process_count.is_some_and(|count| count > 300) {
                "many processes are running; login items may contribute".to_string()
            } else {
                "optional startup review".to_string()
            },
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
            description:
                "Use OS-native memory pressure relief only after inspecting memory-heavy apps"
                    .to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: memory >= PerformanceLevel::High
                || memory_pressure_is_elevated(metrics.memory_pressure.as_deref()),
            reason: memory_pressure_reason(memory, metrics.memory_pressure.as_deref()),
        },
        PerformanceOptimizationTask {
            id: "thin_local_snapshots".to_string(),
            label: "Thin local snapshots".to_string(),
            description: "Review Time Machine local snapshots and free APFS purgeable space"
                .to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: false,
            reason: "uses tmutil only for selected local snapshots".to_string(),
        },
        PerformanceOptimizationTask {
            id: "purge_apfs_space".to_string(),
            label: "Purge APFS space".to_string(),
            description: "Ask APFS to reclaim purgeable local space after review".to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: false,
            reason: "uses diskutil purgePurgeable and may require administrator approval"
                .to_string(),
        },
        PerformanceOptimizationTask {
            id: "run_periodic_maintenance".to_string(),
            label: "Run periodic maintenance".to_string(),
            description: "Run macOS daily, weekly, and monthly maintenance scripts".to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: false,
            reason: "mirrors macOS periodic maintenance and may take time".to_string(),
        },
        PerformanceOptimizationTask {
            id: "reset_app_store_cache".to_string(),
            label: "Reset App Store cache".to_string(),
            description: "Quit App Store helpers and clear stuck update/download cache".to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: false,
            reason: "useful after failed or stuck Mac App Store updates".to_string(),
        },
        PerformanceOptimizationTask {
            id: "refresh_network_stack".to_string(),
            label: "Refresh network stack".to_string(),
            description: "Flush routing and ARP caches when network checks look stale".to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: false,
            reason: "only useful when DNS/default route checks fail".to_string(),
        },
        PerformanceOptimizationTask {
            id: "repair_user_permissions".to_string(),
            label: "Repair user permissions".to_string(),
            description:
                "Reset user directory permissions when ownership or write access is broken"
                    .to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: false,
            reason: "runs only when common user folders look mis-owned or unwritable".to_string(),
        },
        PerformanceOptimizationTask {
            id: "refresh_bluetooth".to_string(),
            label: "Refresh Bluetooth".to_string(),
            description: "Restart bluetoothd only when no active HID/audio dependency is detected"
                .to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: false,
            reason: "skips when Bluetooth keyboard, mouse, trackpad, or audio is active"
                .to_string(),
        },
        PerformanceOptimizationTask {
            id: "optimize_spotlight_index".to_string(),
            label: "Optimize Spotlight index".to_string(),
            description: "Verify Spotlight and rebuild the index only when search is slow"
                .to_string(),
            kind: PerformanceTaskKind::AdminMaintenance,
            risk: PerformanceTaskRisk::Medium,
            recommended: false,
            reason: "rebuild is gated by slow-search checks and AC power".to_string(),
        },
        PerformanceOptimizationTask {
            id: "defer_heavy_maintenance".to_string(),
            label: "Defer heavy maintenance".to_string(),
            description:
                "Avoid long-running cleanup while temperature, CPU, or disk pressure is high"
                    .to_string(),
            kind: PerformanceTaskKind::Inspect,
            risk: PerformanceTaskRisk::Low,
            recommended: temperature >= PerformanceLevel::Elevated
                || cpu >= PerformanceLevel::High
                || disk >= PerformanceLevel::High,
            reason: defer_reason(cpu, temperature, disk),
        },
        PerformanceOptimizationTask {
            id: "refresh_fontconfig_cache".to_string(),
            label: "Refresh fontconfig cache".to_string(),
            description: "Rebuild Linux fontconfig caches when font discovery looks stale"
                .to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: false,
            reason: "Linux font cache refresh; does not change user documents".to_string(),
        },
        PerformanceOptimizationTask {
            id: "refresh_user_systemd".to_string(),
            label: "Refresh user services".to_string(),
            description: "Reload the user systemd daemon after startup item changes".to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: false,
            reason: "Linux user service metadata reload".to_string(),
        },
        PerformanceOptimizationTask {
            id: "vacuum_user_journal".to_string(),
            label: "Vacuum user journal".to_string(),
            description: "Trim old user journal entries without touching system logs".to_string(),
            kind: PerformanceTaskKind::SafeMaintenance,
            risk: PerformanceTaskRisk::Low,
            recommended: false,
            reason: "Linux user journal maintenance with a time-based retention window".to_string(),
        },
    ];

    tasks.retain(|task| os_supports_task(os, &task.id));
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
        "refresh_finder_caches" => 3,
        "cleanup_saved_states" => 4,
        "repair_broken_preferences" => 5,
        "optimize_app_databases" => 6,
        "repair_launch_services" => 7,
        "rebuild_font_cache" => 8,
        "refresh_dock" => 9,
        "inspect_login_items" => 10,
        "sync_filesystem_buffers" => 11,
        "thin_local_snapshots" => 12,
        "purge_apfs_space" => 13,
        "run_periodic_maintenance" => 14,
        "reset_app_store_cache" => 15,
        "refresh_network_stack" => 16,
        "repair_user_permissions" => 17,
        "refresh_bluetooth" => 18,
        "optimize_spotlight_index" => 19,
        "refresh_fontconfig_cache" => 20,
        "refresh_user_systemd" => 21,
        "vacuum_user_journal" => 22,
        "defer_heavy_maintenance" => 23,
        _ => 99,
    }
}

fn os_supports_task(os: &str, id: &str) -> bool {
    let normalized = os.to_ascii_lowercase();
    let is_linux = normalized.contains("linux");
    let is_macos = normalized.contains("macos") || normalized.contains("darwin");
    match id {
        "inspect_top_processes"
        | "flush_dns_cache"
        | "inspect_login_items"
        | "sync_filesystem_buffers"
        | "defer_heavy_maintenance" => true,
        "refresh_fontconfig_cache" | "refresh_user_systemd" | "vacuum_user_journal" => is_linux,
        _ => is_macos,
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
    fn performance_view_model_reports_reference_optimization_tasks() {
        let model = PerformanceViewModel::from_snapshot(&snapshot(DashboardMetrics::default()));
        let task_ids = model
            .optimization_tasks
            .iter()
            .map(|task| task.id.as_str())
            .collect::<Vec<_>>();

        for expected in [
            "inspect_top_processes",
            "flush_dns_cache",
            "refresh_finder_caches",
            "cleanup_saved_states",
            "repair_broken_preferences",
            "optimize_app_databases",
            "repair_launch_services",
            "rebuild_font_cache",
            "refresh_dock",
            "inspect_login_items",
            "sync_filesystem_buffers",
            "memory_pressure_relief",
            "thin_local_snapshots",
            "purge_apfs_space",
            "run_periodic_maintenance",
            "reset_app_store_cache",
            "refresh_network_stack",
            "repair_user_permissions",
            "refresh_bluetooth",
            "optimize_spotlight_index",
            "defer_heavy_maintenance",
        ] {
            assert!(task_ids.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn performance_view_model_filters_linux_tasks() {
        let mut snapshot = snapshot(DashboardMetrics::default());
        snapshot.os = "linux".to_string();
        let model = PerformanceViewModel::from_snapshot(&snapshot);
        let task_ids = model
            .optimization_tasks
            .iter()
            .map(|task| task.id.as_str())
            .collect::<Vec<_>>();

        assert!(task_ids.contains(&"refresh_fontconfig_cache"));
        assert!(task_ids.contains(&"refresh_user_systemd"));
        assert!(task_ids.contains(&"vacuum_user_journal"));
        assert!(!task_ids.contains(&"repair_launch_services"));
        assert!(!task_ids.contains(&"purge_apfs_space"));
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
