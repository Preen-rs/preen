use chrono::{DateTime, Local, Utc};
use preen_core::dashboard::{
    CheckSeverity, DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
    DashboardMetrics, DashboardSnapshot, PluginRow, ProcessMetric, RegistrySummary, StatusCheck,
};
use preen_core::plugin_lock::PluginLockfile;
use preen_core::plugin_registry::RegistryIndex;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Duration, Instant};
use sysinfo::{Disks, MINIMUM_CPU_UPDATE_INTERVAL, Networks, ProcessesToUpdate, System};

const STATE_DIR_EXISTS_ID: &str = "state_dir_exists";
const STATE_DIR_WRITABLE_ID: &str = "state_dir_writable";
const LOCKFILE_READABLE_ID: &str = "lockfile_readable";
const REGISTRY_READABLE_ID: &str = "registry_readable";
const PLUGINS_DIR_READABLE_ID: &str = "plugins_dir_readable";
const DASHBOARD_HEALTH_MODE_ENV: &str = "PREEN_DASHBOARD_HEALTH_MODE";
const NETWORK_HISTORY_LIMIT: usize = 120;
const METRIC_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
struct NetworkTotalSample {
    captured_at: Instant,
    rx_total: u64,
    tx_total: u64,
}

#[derive(Debug, Default)]
struct NetworkAccumulator {
    previous: Option<NetworkTotalSample>,
    rx_history_mbps: VecDeque<f64>,
    tx_history_mbps: VecDeque<f64>,
}

impl NetworkAccumulator {
    fn capture(
        &mut self,
        rx_total: Option<u64>,
        tx_total: Option<u64>,
    ) -> (Option<f64>, Option<f64>, Vec<f64>, Vec<f64>) {
        let Some(rx_total) = rx_total else {
            return (None, None, self.rx_history_vec(), self.tx_history_vec());
        };
        let Some(tx_total) = tx_total else {
            return (None, None, self.rx_history_vec(), self.tx_history_vec());
        };

        let now = Instant::now();
        let mut rx_rate_mbps = None;
        let mut tx_rate_mbps = None;

        if let Some(previous) = self.previous {
            let elapsed = now.duration_since(previous.captured_at).as_secs_f64();
            if elapsed > 0.0 {
                rx_rate_mbps = Some(
                    (rx_total.saturating_sub(previous.rx_total) as f64)
                        / elapsed
                        / (1024.0 * 1024.0),
                );
                tx_rate_mbps = Some(
                    (tx_total.saturating_sub(previous.tx_total) as f64)
                        / elapsed
                        / (1024.0 * 1024.0),
                );
            }
        }

        if let Some(rx_rate) = rx_rate_mbps {
            push_limited(
                &mut self.rx_history_mbps,
                rx_rate.max(0.0),
                NETWORK_HISTORY_LIMIT,
            );
        }
        if let Some(tx_rate) = tx_rate_mbps {
            push_limited(
                &mut self.tx_history_mbps,
                tx_rate.max(0.0),
                NETWORK_HISTORY_LIMIT,
            );
        }

        self.previous = Some(NetworkTotalSample {
            captured_at: now,
            rx_total,
            tx_total,
        });
        (
            rx_rate_mbps,
            tx_rate_mbps,
            self.rx_history_vec(),
            self.tx_history_vec(),
        )
    }

    fn rx_history_vec(&self) -> Vec<f64> {
        self.rx_history_mbps.iter().copied().collect()
    }

    fn tx_history_vec(&self) -> Vec<f64> {
        self.tx_history_mbps.iter().copied().collect()
    }
}

fn push_limited(queue: &mut VecDeque<f64>, value: f64, max_len: usize) {
    queue.push_back(value);
    while queue.len() > max_len {
        let _ = queue.pop_front();
    }
}

#[derive(Debug, Clone, Copy)]
struct DiskIoSample {
    captured_at: Instant,
}

#[derive(Debug, Default)]
struct DiskIoAccumulator {
    previous: Option<DiskIoSample>,
}

impl DiskIoAccumulator {
    fn capture(
        &mut self,
        read_bytes: Option<u64>,
        write_bytes: Option<u64>,
    ) -> (Option<f64>, Option<f64>) {
        self.capture_at(read_bytes, write_bytes, Instant::now())
    }

    fn capture_at(
        &mut self,
        read_bytes: Option<u64>,
        write_bytes: Option<u64>,
        now: Instant,
    ) -> (Option<f64>, Option<f64>) {
        let Some(read_bytes) = read_bytes else {
            return (None, None);
        };
        let Some(write_bytes) = write_bytes else {
            return (None, None);
        };

        let mut read_rate_mbps = None;
        let mut write_rate_mbps = None;
        if let Some(previous) = self.previous {
            let elapsed = now.duration_since(previous.captured_at).as_secs_f64();
            if elapsed > 0.0 {
                read_rate_mbps = Some((read_bytes as f64) / elapsed / (1024.0 * 1024.0));
                write_rate_mbps = Some((write_bytes as f64) / elapsed / (1024.0 * 1024.0));
            }
        }

        self.previous = Some(DiskIoSample { captured_at: now });
        (
            read_rate_mbps.map(|value| value.max(0.0)),
            write_rate_mbps.map(|value| value.max(0.0)),
        )
    }
}

#[derive(Debug, Clone, Default)]
struct CachedPowerDetails {
    health: Option<String>,
    cycle_count: Option<u64>,
    capacity_pct: Option<f64>,
    cached_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DashboardHealthMode {
    MoleParity,
    PreenStrict,
}

impl Default for DashboardHealthMode {
    fn default() -> Self {
        Self::MoleParity
    }
}

impl DashboardHealthMode {
    fn from_env() -> Self {
        Self::from_str(std::env::var(DASHBOARD_HEALTH_MODE_ENV).ok().as_deref())
    }

    fn from_str(raw: Option<&str>) -> Self {
        match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("preen_strict") | Some("strict") => Self::PreenStrict,
            _ => Self::MoleParity,
        }
    }
}

#[derive(Debug, Default)]
pub struct SnapshotCollector {
    network: NetworkAccumulator,
    disk_io: DiskIoAccumulator,
    power_details: CachedPowerDetails,
    system: System,
    health_mode: DashboardHealthMode,
}

impl SnapshotCollector {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_cpu_usage();
        std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
        system.refresh_cpu_usage();
        Self {
            network: NetworkAccumulator::default(),
            disk_io: DiskIoAccumulator::default(),
            power_details: CachedPowerDetails::default(),
            system,
            health_mode: DashboardHealthMode::from_env(),
        }
    }

    pub fn collect_snapshot(&mut self) -> Result<DashboardSnapshot, String> {
        let state_dir = preen_state_dir()?;
        collect_snapshot_for_state_dir_with_accumulator(
            &state_dir,
            &mut self.network,
            &mut self.disk_io,
            &mut self.power_details,
            &mut self.system,
            self.health_mode,
        )
    }
}

impl preen_core::dashboard_provider::DashboardProvider for SnapshotCollector {
    fn next_snapshot(&mut self) -> Result<DashboardSnapshot, String> {
        self.collect_snapshot()
    }
}

#[cfg(test)]
pub fn collect_snapshot_for_state_dir(state_dir: &Path) -> Result<DashboardSnapshot, String> {
    let mut network = NetworkAccumulator::default();
    let mut disk_io = DiskIoAccumulator::default();
    let mut power_details = CachedPowerDetails::default();
    let mut system = System::new_all();
    system.refresh_cpu_usage();
    std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
    system.refresh_cpu_usage();
    collect_snapshot_for_state_dir_with_accumulator(
        state_dir,
        &mut network,
        &mut disk_io,
        &mut power_details,
        &mut system,
        DashboardHealthMode::from_env(),
    )
}

fn collect_snapshot_for_state_dir_with_accumulator(
    state_dir: &Path,
    network: &mut NetworkAccumulator,
    disk_io: &mut DiskIoAccumulator,
    power_details: &mut CachedPowerDetails,
    system: &mut System,
    health_mode: DashboardHealthMode,
) -> Result<DashboardSnapshot, String> {
    let mut warnings = Vec::new();
    let mut checks = Vec::new();

    let state_exists = state_dir.exists();
    checks.push(StatusCheck {
        id: STATE_DIR_EXISTS_ID.to_string(),
        label: "State directory exists".to_string(),
        severity: CheckSeverity::Critical,
        passed: state_exists,
        message: if state_exists {
            format!("state dir exists: {}", state_dir.display())
        } else {
            format!("state dir missing: {}", state_dir.display())
        },
    });

    let state_writable = probe_state_dir_writable(state_dir, state_exists);
    if !state_writable.0 {
        warnings.push(state_writable.1.clone());
    }
    checks.push(StatusCheck {
        id: STATE_DIR_WRITABLE_ID.to_string(),
        label: "State directory writable".to_string(),
        severity: CheckSeverity::Critical,
        passed: state_writable.0,
        message: state_writable.1,
    });

    let lockfile_path = state_dir.join("plugins.lock");
    let (plugins, lockfile_warning) = read_lockfile_plugins(&lockfile_path, state_dir);
    if let Some(warning) = &lockfile_warning {
        warnings.push(warning.clone());
    }
    checks.push(StatusCheck {
        id: LOCKFILE_READABLE_ID.to_string(),
        label: "Lockfile readable".to_string(),
        severity: CheckSeverity::Warning,
        passed: lockfile_warning.is_none(),
        message: if lockfile_warning.is_none() {
            format!("lockfile readable: {}", lockfile_path.display())
        } else {
            format!("lockfile read failed: {}", lockfile_path.display())
        },
    });

    let registry_path = state_dir.join("registry-index.toml");
    let (registry, registry_warning) = read_registry_summary(&registry_path);
    if let Some(warning) = &registry_warning {
        warnings.push(warning.clone());
    }
    checks.push(StatusCheck {
        id: REGISTRY_READABLE_ID.to_string(),
        label: "Registry index readable".to_string(),
        severity: CheckSeverity::Warning,
        passed: registry_warning.is_none(),
        message: if registry_warning.is_none() {
            format!("registry index readable: {}", registry_path.display())
        } else {
            format!("registry index read failed: {}", registry_path.display())
        },
    });

    let plugins_dir = state_dir.join("plugins");
    let (installed_plugins_on_disk, plugins_dir_warning) = plugin_dir_count(&plugins_dir);
    if let Some(warning) = &plugins_dir_warning {
        warnings.push(warning.clone());
    }
    checks.push(StatusCheck {
        id: PLUGINS_DIR_READABLE_ID.to_string(),
        label: "Plugin directory readable".to_string(),
        severity: CheckSeverity::Warning,
        passed: plugins_dir_warning.is_none(),
        message: if plugins_dir_warning.is_none() {
            format!("plugin dir readable: {}", plugins_dir.display())
        } else {
            format!("plugin dir check failed: {}", plugins_dir.display())
        },
    });

    let overall_passed = checks
        .iter()
        .filter(|check| matches!(check.severity, CheckSeverity::Critical))
        .all(|check| check.passed);

    let suggested_actions = status_suggested_actions(&checks, registry.present);
    let metrics = collect_dashboard_metrics(
        state_dir,
        &mut warnings,
        network,
        disk_io,
        power_details,
        system,
    );
    let health_score = calculate_health_score(&checks, &metrics, health_mode);

    Ok(DashboardSnapshot {
        schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
        contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
        collected_at: Local::now(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        state_dir: state_dir.to_path_buf(),
        health_score,
        overall_passed,
        plugin_count: plugins.len(),
        installed_plugins_on_disk,
        checks,
        warnings,
        suggested_actions,
        registry,
        metrics,
        plugins,
    })
}

fn probe_state_dir_writable(state_dir: &Path, state_exists: bool) -> (bool, String) {
    if !state_exists {
        return (false, "state dir is not present".to_string());
    }
    let probe = state_dir.join(".preen-tui-write-probe");
    match fs::write(&probe, b"probe") {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            (true, "state dir is writable".to_string())
        }
        Err(error) => (false, format!("state dir write probe failed: {error}")),
    }
}

fn read_lockfile_plugins(
    lockfile_path: &Path,
    state_dir: &Path,
) -> (Vec<PluginRow>, Option<String>) {
    if !lockfile_path.exists() {
        return (Vec::new(), None);
    }

    let content = match fs::read_to_string(lockfile_path) {
        Ok(content) => content,
        Err(error) => return (Vec::new(), Some(format!("lockfile read failed: {error}"))),
    };
    let lockfile: PluginLockfile = match content.parse() {
        Ok(lockfile) => lockfile,
        Err(error) => {
            return (
                Vec::new(),
                Some(format!("lockfile parse failed: {error:?}")),
            );
        }
    };

    let plugins = lockfile
        .plugins
        .into_iter()
        .map(|plugin| {
            let installed = state_dir.join("plugins").join(&plugin.pack_id).exists();
            PluginRow {
                pack_id: plugin.pack_id,
                version: plugin.version,
                source: plugin.source,
                rev: plugin.resolved_rev.unwrap_or(plugin.rev),
                installed,
                trusted_identity: plugin.trusted_identity,
            }
        })
        .collect();
    (plugins, None)
}

fn read_registry_summary(registry_path: &Path) -> (RegistrySummary, Option<String>) {
    if !registry_path.exists() {
        return (
            RegistrySummary {
                present: false,
                ..RegistrySummary::default()
            },
            Some("registry index is missing".to_string()),
        );
    }

    let content = match fs::read_to_string(registry_path) {
        Ok(content) => content,
        Err(error) => {
            return (
                RegistrySummary {
                    present: true,
                    ..RegistrySummary::default()
                },
                Some(format!("registry read failed: {error}")),
            );
        }
    };
    let index: RegistryIndex = match content.parse() {
        Ok(index) => index,
        Err(error) => {
            return (
                RegistrySummary {
                    present: true,
                    ..RegistrySummary::default()
                },
                Some(format!("registry parse failed: {error:?}")),
            );
        }
    };

    let age_days = index.generated_at.as_deref().and_then(registry_age_days);
    (
        RegistrySummary {
            present: true,
            generated_at: index.generated_at,
            age_days,
            entry_count: Some(index.entries.len()),
        },
        None,
    )
}

fn registry_age_days(value: &str) -> Option<i64> {
    let parsed = DateTime::parse_from_rfc3339(value).ok()?;
    let generated = parsed.with_timezone(&Utc);
    let delta = Utc::now() - generated;
    Some(delta.num_days())
}

fn plugin_dir_count(path: &Path) -> (usize, Option<String>) {
    if !path.exists() {
        return (0, None);
    }
    let mut count = 0usize;
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => return (0, Some(format!("plugin directory read failed: {error}"))),
    };
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            count = count.saturating_add(1);
        }
    }
    (count, None)
}

fn status_suggested_actions(checks: &[StatusCheck], registry_present: bool) -> Vec<String> {
    let mut actions = Vec::new();
    if check_failed(checks, STATE_DIR_EXISTS_ID) || check_failed(checks, STATE_DIR_WRITABLE_ID) {
        actions.push("preen check --fix".to_string());
    }
    if check_failed(checks, LOCKFILE_READABLE_ID) {
        actions.push("preen plugin list".to_string());
    }
    if check_failed(checks, REGISTRY_READABLE_ID) || !registry_present {
        actions.push("preen plugin registry-update".to_string());
    }
    if check_failed(checks, PLUGINS_DIR_READABLE_ID) {
        actions.push("preen plugin install <pack-id>@<version>".to_string());
    }
    actions
}

fn collect_dashboard_metrics(
    state_dir: &Path,
    warnings: &mut Vec<String>,
    network_acc: &mut NetworkAccumulator,
    disk_io_acc: &mut DiskIoAccumulator,
    power_details: &mut CachedPowerDetails,
    system: &mut System,
) -> DashboardMetrics {
    system.refresh_cpu_usage();
    std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
    system.refresh_cpu_usage();
    system.refresh_memory();
    system.refresh_processes(ProcessesToUpdate::All, true);

    let cpu_cores = std::thread::available_parallelism()
        .ok()
        .map(|value| value.get());
    let cpu_model = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_string())
        .filter(|value| !value.is_empty());
    let mut cpu_usage_pct = Some(system.global_cpu_usage() as f64);
    let mut cpu_core_usage = system
        .cpus()
        .iter()
        .map(|cpu| cpu.cpu_usage() as f64)
        .collect::<Vec<_>>();
    if cfg!(target_os = "macos")
        && let Some(mut sampled_total_cpu_pct) = collect_macos_total_cpu_usage()
    {
        if let Some(ps_total_cpu_pct) = collect_macos_ps_cpu_usage(cpu_core_usage.len()) {
            sampled_total_cpu_pct = sampled_total_cpu_pct.max(ps_total_cpu_pct);
        }
        if let Some(current_total) = cpu_usage_pct
            && current_total > 0.0
        {
            let scale = (sampled_total_cpu_pct / current_total).clamp(0.5, 6.0);
            for usage in &mut cpu_core_usage {
                *usage = (*usage * scale).clamp(0.0, 100.0);
            }
        }
        cpu_usage_pct = Some(sampled_total_cpu_pct.clamp(0.0, 100.0));
    }

    let load = System::load_average();
    let load_avg_1m = finite_float(load.one);
    let load_avg_5m = finite_float(load.five);
    let load_avg_15m = finite_float(load.fifteen);
    let uptime_seconds = Some(System::uptime());

    let memory_total_bytes = Some(system.total_memory());
    let memory_used_bytes = Some(system.used_memory());
    let memory_used_pct = compute_percent(memory_used_bytes, memory_total_bytes);
    let memory_pressure = collect_memory_pressure();

    let process_count = Some(system.processes().len() as u64);
    let top_processes = collect_top_processes(system);

    let disks = Disks::new_with_refreshed_list();
    let (disk_total_bytes, disk_available_bytes, disk_filesystem) =
        match select_state_disk(state_dir, &disks) {
            Some((total, available, fs)) => (Some(total), Some(available), fs),
            None => {
                warnings.push(format!(
                    "metrics disk probe failed for state dir: {}",
                    state_dir.display()
                ));
                (None, None, None)
            }
        };
    let disk_free_pct = compute_percent(disk_available_bytes, disk_total_bytes);
    let (disk_read_total, disk_write_total) = aggregate_process_disk_interval_bytes(system);
    let (disk_read_rate_mbps, disk_write_rate_mbps) =
        disk_io_acc.capture(disk_read_total, disk_write_total);

    let networks = Networks::new_with_refreshed_list();
    let (network_rx_bytes, network_tx_bytes) = if networks.iter().next().is_none() {
        (None, None)
    } else {
        let mut rx_sum = 0_u64;
        let mut tx_sum = 0_u64;
        for (_, data) in &networks {
            rx_sum = rx_sum.saturating_add(data.total_received());
            tx_sum = tx_sum.saturating_add(data.total_transmitted());
        }
        (Some(rx_sum), Some(tx_sum))
    };
    let (
        network_rx_rate_mbps,
        network_tx_rate_mbps,
        network_rx_history_mbps,
        network_tx_history_mbps,
    ) = network_acc.capture(network_rx_bytes, network_tx_bytes);
    let network_proxy = collect_proxy_label(&networks);
    let network_primary_ip = collect_primary_ip(&networks);
    let power_details_snapshot = collect_cached_power_details(power_details, warnings);
    let (
        power_level_pct,
        power_status,
        power_time_left,
        cpu_temperature_c,
        battery_temperature_c,
        fan_speed_rpm,
        system_power_watts,
        adapter_power_watts,
        battery_power_watts,
    ) = collect_power_metrics(warnings);

    DashboardMetrics {
        host_name: System::host_name(),
        os_version: System::long_os_version(),
        cpu_model,
        cpu_cores,
        cpu_usage_pct,
        cpu_core_usage,
        load_avg_1m,
        load_avg_5m,
        load_avg_15m,
        uptime_seconds,
        memory_total_bytes,
        memory_used_bytes,
        memory_used_pct,
        memory_pressure,
        disk_total_bytes,
        disk_available_bytes,
        disk_free_pct,
        disk_filesystem,
        disk_read_rate_mbps,
        disk_write_rate_mbps,
        process_count,
        top_processes,
        network_rx_bytes,
        network_tx_bytes,
        network_rx_rate_mbps,
        network_tx_rate_mbps,
        network_rx_history_mbps,
        network_tx_history_mbps,
        network_proxy,
        network_primary_ip,
        power_level_pct,
        power_status,
        power_time_left,
        power_health: power_details_snapshot.health,
        power_cycle_count: power_details_snapshot.cycle_count,
        power_capacity_pct: power_details_snapshot.capacity_pct,
        cpu_temperature_c,
        battery_temperature_c,
        fan_speed_rpm,
        system_power_watts,
        adapter_power_watts,
        battery_power_watts,
    }
}

fn select_state_disk(state_dir: &Path, disks: &Disks) -> Option<(u64, u64, Option<String>)> {
    let mut probe = state_dir;
    while !probe.exists() {
        probe = probe.parent()?;
    }

    let mut selected: Option<(usize, u64, u64, Option<String>)> = None;
    for disk in disks {
        let mount = disk.mount_point();
        if !probe.starts_with(mount) {
            continue;
        }
        let mount_len = mount.as_os_str().len();
        let total = disk.total_space();
        let available = disk.available_space();
        let filesystem = Some(disk.file_system().to_string_lossy().to_string())
            .filter(|value| !value.trim().is_empty());
        match selected {
            Some((best_len, _, _, _)) if mount_len <= best_len => {}
            _ => selected = Some((mount_len, total, available, filesystem)),
        }
    }
    selected.map(|(_, total, available, filesystem)| (total, available, filesystem))
}

fn collect_proxy_label(networks: &Networks) -> Option<String> {
    let mut tun_interfaces = networks
        .iter()
        .filter_map(|(name, _data)| {
            let lower = name.to_lowercase();
            if !(lower.starts_with("utun") || lower.starts_with("tun")) {
                return None;
            }
            Some(name.to_string())
        })
        .collect::<Vec<_>>();

    tun_interfaces.extend(tun_interfaces_from_ifconfig());
    tun_interfaces.sort();
    tun_interfaces.dedup();

    let mut has_tunnel = false;
    for interface in &tun_interfaces {
        has_tunnel = true;
        if let Some(value) = interface_ipv4(interface) {
            return Some(format!("TUN · {value}"));
        }
    }

    if has_tunnel {
        if cfg!(target_os = "macos")
            && let Some(ip) = primary_ipv4_from_ifconfig_macos()
        {
            return Some(format!("TUN · {ip}"));
        }
        return Some("TUN".to_string());
    }
    if let Some(label) = proxy_from_environment() {
        return Some(label);
    }
    if let Some(label) = proxy_from_scutil() {
        return Some(label);
    }
    None
}

fn proxy_from_environment() -> Option<String> {
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        let value = std::env::var(key).ok()?;
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let host = extract_proxy_host(value).unwrap_or_else(|| value.to_string());
        let kind = if value.to_lowercase().starts_with("socks") {
            "SOCKS"
        } else {
            "HTTP"
        };
        return Some(format!("{kind} · {host}"));
    }
    None
}

fn proxy_from_scutil() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let output = ProcessCommand::new("scutil")
        .args(["--proxy"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if scutil_enabled(&text, "SOCKSEnable") {
        let host = scutil_value(&text, "SOCKSProxy")
            .or_else(|| scutil_value(&text, "HTTPSProxy"))
            .or_else(|| scutil_value(&text, "HTTPProxy"));
        let port = scutil_value(&text, "SOCKSPort")
            .or_else(|| scutil_value(&text, "HTTPSPort"))
            .or_else(|| scutil_value(&text, "HTTPPort"));
        return Some(format_proxy_host(host, port, "SOCKS"));
    }
    if scutil_enabled(&text, "HTTPSEnable") || scutil_enabled(&text, "HTTPEnable") {
        let host = scutil_value(&text, "HTTPSProxy").or_else(|| scutil_value(&text, "HTTPProxy"));
        let port = scutil_value(&text, "HTTPSPort").or_else(|| scutil_value(&text, "HTTPPort"));
        return Some(format_proxy_host(host, port, "HTTP"));
    }
    None
}

fn scutil_enabled(text: &str, key: &str) -> bool {
    scutil_value(text, key).as_deref() == Some("1")
}

fn scutil_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines().map(str::trim) {
        let prefix = format!("{key} :");
        if let Some(rest) = line.strip_prefix(&prefix) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn format_proxy_host(host: Option<String>, port: Option<String>, fallback_kind: &str) -> String {
    match (host, port) {
        (Some(h), Some(p)) if !h.is_empty() && !p.is_empty() => {
            format!("{fallback_kind} · {h}:{p}")
        }
        (Some(h), _) if !h.is_empty() => format!("{fallback_kind} · {h}"),
        _ => fallback_kind.to_string(),
    }
}

fn extract_proxy_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let without_scheme = if let Some((_, rest)) = trimmed.split_once("://") {
        rest
    } else {
        trimmed
    };
    let without_auth = without_scheme.rsplit('@').next().unwrap_or(without_scheme);
    let host_port = without_auth.split('/').next().unwrap_or(without_auth);
    if host_port.is_empty() {
        return None;
    }
    Some(host_port.to_string())
}

fn interface_ipv4(interface: &str) -> Option<String> {
    if cfg!(target_os = "macos") {
        return interface_ipv4_macos(interface);
    }
    if cfg!(target_os = "linux") {
        return interface_ipv4_linux(interface);
    }
    None
}

fn collect_primary_ip(networks: &Networks) -> Option<String> {
    if cfg!(target_os = "macos")
        && let Some(ip) = primary_ipv4_from_ifconfig_macos()
    {
        return Some(ip);
    }

    for preferred in ["en0", "en1", "eth0", "wlan0", "wifi0"] {
        if let Some(ip) = interface_ipv4(preferred) {
            return Some(ip);
        }
    }

    for (name, _data) in networks {
        if is_noise_interface(name) {
            continue;
        }
        if let Some(ip) = interface_ipv4(name) {
            return Some(ip);
        }
    }
    None
}

fn primary_ipv4_from_ifconfig_macos() -> Option<String> {
    let output = ProcessCommand::new("ifconfig").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut best: Option<(u8, String)> = None;
    let mut current_name = String::new();
    let mut current_active = false;
    let mut current_ip: Option<String> = None;

    let flush = |best: &mut Option<(u8, String)>, name: &str, active: bool, ip: Option<String>| {
        let Some(ip) = ip else {
            return;
        };
        if name.is_empty() || is_noise_interface(name) {
            return;
        }
        let mut score = if name == "en0" {
            100
        } else if name.starts_with("en") {
            90
        } else if name.starts_with("eth") || name.starts_with("wlan") {
            80
        } else {
            70
        };
        if active {
            score += 20;
        }
        match best {
            Some((best_score, _)) if score <= *best_score => {}
            _ => *best = Some((score, ip)),
        }
    };

    for line in text.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') {
            flush(&mut best, &current_name, current_active, current_ip.take());
            current_active = false;
            if let Some((name, _)) = line.split_once(':') {
                current_name = name.to_string();
            } else {
                current_name.clear();
            }
            continue;
        }

        let trimmed = line.trim();
        if trimmed == "status: active" {
            current_active = true;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(ip) = rest.split_whitespace().next()
                && !ip.starts_with("127.")
            {
                current_ip = Some(ip.to_string());
            }
        }
    }

    flush(&mut best, &current_name, current_active, current_ip.take());
    best.map(|(_, ip)| ip)
}

fn is_noise_interface(name: &str) -> bool {
    let lower = name.to_lowercase();
    [
        "lo", "awdl", "utun", "llw", "bridge", "gif", "stf", "xhc", "anpi", "ap",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn collect_macos_total_cpu_usage() -> Option<f64> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let output = ProcessCommand::new("top")
        .args(["-l", "1", "-n", "0"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_macos_cpu_usage_from_top(&text)
}

fn parse_macos_cpu_usage_from_top(text: &str) -> Option<f64> {
    let line = text.lines().find(|line| line.contains("CPU usage:"))?;
    let payload = line.split_once("CPU usage:")?.1;
    let mut user_pct = None;
    let mut sys_pct = None;
    for segment in payload.split(',') {
        let trimmed = segment.trim();
        if let Some(value) = trimmed.strip_suffix("% user") {
            user_pct = value.trim().parse::<f64>().ok();
        } else if let Some(value) = trimmed.strip_suffix("% sys") {
            sys_pct = value.trim().parse::<f64>().ok();
        }
    }
    Some(user_pct.unwrap_or(0.0) + sys_pct.unwrap_or(0.0))
}

fn collect_macos_ps_cpu_usage(logical_cores: usize) -> Option<f64> {
    if !cfg!(target_os = "macos") || logical_cores == 0 {
        return None;
    }
    let output = ProcessCommand::new("ps")
        .args(["-Aceo", "pcpu"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut total = 0.0_f64;
    let mut seen_header = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !seen_header && (trimmed.to_lowercase().contains("cpu") || trimmed.contains('%')) {
            seen_header = true;
            continue;
        }
        if let Ok(value) = trimmed.parse::<f64>() {
            total += value;
        }
    }
    let max_total = (logical_cores as f64) * 100.0;
    let clamped_total = total.clamp(0.0, max_total);
    Some(clamped_total / logical_cores as f64)
}

fn tun_interfaces_from_ifconfig() -> Vec<String> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let output = match ProcessCommand::new("ifconfig").output() {
        Ok(value) if value.status.success() => value,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut names = Vec::new();
    for line in text.lines() {
        if line.starts_with('\t') || line.starts_with(' ') {
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            let lower = name.to_lowercase();
            if lower.starts_with("utun") || lower.starts_with("tun") {
                names.push(name.to_string());
            }
        }
    }
    names
}

fn interface_ipv4_macos(interface: &str) -> Option<String> {
    let output = ProcessCommand::new("ifconfig")
        .arg(interface)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            let ip = rest.split_whitespace().next()?.to_string();
            if !ip.starts_with("127.") {
                return Some(ip);
            }
        }
    }
    None
}

fn interface_ipv4_linux(interface: &str) -> Option<String> {
    let output = ProcessCommand::new("ip")
        .args(["-4", "addr", "show", "dev", interface])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            let cidr = rest.split_whitespace().next()?;
            let ip = cidr.split('/').next()?.to_string();
            if !ip.starts_with("127.") {
                return Some(ip);
            }
        }
    }
    None
}

fn finite_float(value: f64) -> Option<f64> {
    if value.is_nan() || !value.is_finite() || value.is_sign_negative() {
        return None;
    }
    Some(value)
}

fn compute_percent(numerator: Option<u64>, denominator: Option<u64>) -> Option<f64> {
    match (numerator, denominator) {
        (Some(a), Some(b)) if b > 0 => Some((a as f64 / b as f64) * 100.0),
        _ => None,
    }
}

fn collect_memory_pressure() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let output = ProcessCommand::new("memory_pressure").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
    if text.contains("critical") {
        return Some("critical".to_string());
    }
    if text.contains("warn") {
        return Some("warn".to_string());
    }
    if text.contains("normal") {
        return Some("normal".to_string());
    }
    None
}

fn collect_top_processes(system: &System) -> Vec<ProcessMetric> {
    if cfg!(target_os = "macos")
        && let Some(processes) = collect_top_processes_macos_ps()
        && !processes.is_empty()
    {
        return processes;
    }

    let total_memory = system.total_memory() as f64;
    let mut top_processes = system
        .processes()
        .values()
        .map(|process| {
            let process_memory = process.memory() as f64;
            let memory_pct = if total_memory > 0.0 {
                (process_memory / total_memory) * 100.0
            } else {
                0.0
            };
            ProcessMetric {
                name: process.name().to_string_lossy().to_string(),
                cpu_pct: process.cpu_usage() as f64,
                memory_pct,
            }
        })
        .collect::<Vec<_>>();
    top_processes.sort_by(|left, right| {
        right
            .cpu_pct
            .partial_cmp(&left.cpu_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    top_processes.truncate(4);
    top_processes
}

fn collect_top_processes_macos_ps() -> Option<Vec<ProcessMetric>> {
    let output = ProcessCommand::new("ps")
        .args(["-Aceo", "pcpu,pmem,comm", "-r"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index == 0 {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 {
            continue;
        }
        let cpu_pct = fields[0].parse::<f64>().ok().unwrap_or(0.0);
        let memory_pct = fields[1].parse::<f64>().ok().unwrap_or(0.0);
        let name = fields
            .last()
            .map(|value| {
                Path::new(value)
                    .file_name()
                    .map(|item| item.to_string_lossy().to_string())
                    .unwrap_or_else(|| (*value).to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());
        rows.push(ProcessMetric {
            name,
            cpu_pct,
            memory_pct,
        });
        if rows.len() >= 4 {
            break;
        }
    }
    Some(rows)
}

fn aggregate_process_disk_interval_bytes(system: &System) -> (Option<u64>, Option<u64>) {
    if system.processes().is_empty() {
        return (None, None);
    }
    let mut read_total = 0_u64;
    let mut write_total = 0_u64;
    for process in system.processes().values() {
        let usage = process.disk_usage();
        read_total = read_total.saturating_add(usage.read_bytes);
        write_total = write_total.saturating_add(usage.written_bytes);
    }
    (Some(read_total), Some(write_total))
}

fn collect_cached_power_details(
    cache: &mut CachedPowerDetails,
    warnings: &mut Vec<String>,
) -> CachedPowerDetails {
    if let Some(cached_at) = cache.cached_at
        && cached_at.elapsed() < METRIC_CACHE_TTL
    {
        return cache.clone();
    }

    let mut refreshed = refresh_power_details_from_system_profiler(warnings);
    if refreshed.capacity_pct.is_none()
        || refreshed.cycle_count.is_none()
        || refreshed.health.is_none()
    {
        let fallback = refresh_power_details_from_ioreg(warnings);
        if refreshed.health.is_none() {
            refreshed.health = fallback.health;
        }
        if refreshed.cycle_count.is_none() {
            refreshed.cycle_count = fallback.cycle_count;
        }
        if refreshed.capacity_pct.is_none() {
            refreshed.capacity_pct = fallback.capacity_pct;
        }
    }
    cache.health = refreshed.health;
    cache.cycle_count = refreshed.cycle_count;
    cache.capacity_pct = refreshed.capacity_pct;
    cache.cached_at = Some(Instant::now());
    cache.clone()
}

fn refresh_power_details_from_system_profiler(warnings: &mut Vec<String>) -> CachedPowerDetails {
    if !cfg!(target_os = "macos") {
        return CachedPowerDetails::default();
    }
    let output = ProcessCommand::new("system_profiler")
        .args(["SPPowerDataType"])
        .output();
    let text = match output {
        Ok(value) if value.status.success() => String::from_utf8_lossy(&value.stdout).to_string(),
        Ok(value) => {
            warnings.push(format!(
                "power details system_profiler failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            ));
            return CachedPowerDetails::default();
        }
        Err(error) => {
            warnings.push(format!("power details system_profiler failed: {error}"));
            return CachedPowerDetails::default();
        }
    };
    parse_power_details_from_system_profiler(&text)
}

fn parse_power_details_from_system_profiler(text: &str) -> CachedPowerDetails {
    let mut details = CachedPowerDetails::default();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Condition:") {
            details.health = Some(value.trim().to_string());
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("Cycle Count:") {
            details.cycle_count = extract_first_number(value).map(|item| item.round() as u64);
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("Maximum Capacity:") {
            details.capacity_pct = extract_first_number(value).map(|item| item.clamp(0.0, 100.0));
            continue;
        }
    }
    details
}

fn refresh_power_details_from_ioreg(warnings: &mut Vec<String>) -> CachedPowerDetails {
    if !cfg!(target_os = "macos") {
        return CachedPowerDetails::default();
    }
    let output = ProcessCommand::new("ioreg")
        .args(["-rn", "AppleSmartBattery"])
        .output();
    let text = match output {
        Ok(value) if value.status.success() => String::from_utf8_lossy(&value.stdout).to_string(),
        Ok(value) => {
            warnings.push(format!(
                "power details ioreg failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            ));
            return CachedPowerDetails::default();
        }
        Err(error) => {
            warnings.push(format!("power details ioreg failed: {error}"));
            return CachedPowerDetails::default();
        }
    };
    refresh_power_details_from_ioreg_text(&text)
}

fn refresh_power_details_from_ioreg_text(text: &str) -> CachedPowerDetails {
    let mut details = CachedPowerDetails::default();
    let mut nominal_capacity = None;
    let mut design_capacity = None;
    let mut raw_capacity = None;
    for line in text.lines().map(str::trim) {
        if details.health.is_none()
            && let Some(value) = parse_ioreg_string_key(line, "BatteryHealth")
        {
            details.health = Some(value);
            continue;
        }
        if details.cycle_count.is_none()
            && let Some(value) = parse_ioreg_numeric_key(line, "CycleCount")
        {
            if value >= 0.0 {
                details.cycle_count = Some(value.round() as u64);
            }
            continue;
        }
        if nominal_capacity.is_none()
            && let Some(value) = parse_ioreg_numeric_key(line, "NominalChargeCapacity")
        {
            nominal_capacity = Some(value);
            continue;
        }
        if design_capacity.is_none()
            && let Some(value) = parse_ioreg_numeric_key(line, "DesignCapacity")
        {
            design_capacity = Some(value);
            continue;
        }
        if raw_capacity.is_none()
            && let Some(value) = parse_ioreg_numeric_key(line, "AppleRawMaxCapacity")
        {
            raw_capacity = Some(value);
        }
    }

    if let (Some(nominal), Some(design)) = (nominal_capacity, design_capacity)
        && design > 0.0
    {
        details.capacity_pct = Some(((nominal / design) * 100.0).clamp(0.0, 100.0));
        return details;
    }

    if let (Some(raw), Some(design)) = (raw_capacity, design_capacity)
        && design > 0.0
    {
        details.capacity_pct = Some(((raw / design) * 100.0).clamp(0.0, 100.0));
    }
    details
}

fn parse_ioreg_string_key(line: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    if !line.contains(&marker) {
        return None;
    }
    let (_, tail) = line.split_once('=')?;
    let value = tail.split(',').next()?.trim().trim_matches('"').trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn parse_ioreg_numeric_key(line: &str, key: &str) -> Option<f64> {
    let marker = format!("\"{key}\"");
    if !line.contains(&marker) {
        return None;
    }
    let (_, tail) = line.split_once('=')?;
    extract_first_number(tail)
}

fn collect_power_metrics(
    warnings: &mut Vec<String>,
) -> (
    Option<f64>,
    Option<String>,
    Option<String>,
    Option<f64>,
    Option<f64>,
    Option<u64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
) {
    if cfg!(target_os = "macos") {
        return collect_power_metrics_macos(warnings);
    }
    if cfg!(target_os = "linux") {
        return collect_power_metrics_linux(warnings);
    }
    (None, None, None, None, None, None, None, None, None)
}

fn collect_power_metrics_macos(
    warnings: &mut Vec<String>,
) -> (
    Option<f64>,
    Option<String>,
    Option<String>,
    Option<f64>,
    Option<f64>,
    Option<u64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
) {
    let output = ProcessCommand::new("pmset").args(["-g", "batt"]).output();
    let text = match output {
        Ok(value) if value.status.success() => String::from_utf8_lossy(&value.stdout).to_string(),
        Ok(value) => {
            warnings.push(format!(
                "power metrics pmset command failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            ));
            return (None, None, None, None, None, None, None, None, None);
        }
        Err(error) => {
            warnings.push(format!("power metrics pmset command failed: {error}"));
            return (None, None, None, None, None, None, None, None, None);
        }
    };

    let mut level = None;
    let mut status = None;
    let mut time_left = None;

    for line in text.lines() {
        if !line.contains('%') {
            continue;
        }
        let parts = line
            .split(';')
            .map(|value| value.trim())
            .collect::<Vec<_>>();
        if let Some(first) = parts.first()
            && let Some(percent_token) = first.split_whitespace().find(|token| token.ends_with('%'))
        {
            level = percent_token.trim_end_matches('%').parse::<f64>().ok();
        }
        if let Some(value) = parts.get(1) {
            status = Some((*value).to_string());
        }
        if let Some(value) = parts.get(2) {
            if let Some(parsed) = parse_pmset_time_left(value) {
                time_left = Some(parsed);
            }
        }
        break;
    }

    let (
        cpu_temperature_c,
        battery_temperature_c,
        fan_speed_rpm,
        system_power_watts,
        adapter_power_watts,
        battery_power_watts,
    ) = collect_macos_thermal_metrics(warnings);

    (
        level,
        status,
        time_left,
        cpu_temperature_c,
        battery_temperature_c,
        fan_speed_rpm,
        system_power_watts,
        adapter_power_watts,
        battery_power_watts,
    )
}

fn parse_pmset_time_left(value: &str) -> Option<String> {
    let lower = value.to_lowercase();
    if lower.contains("no estimate") {
        return Some("n/a".to_string());
    }
    for token in value.split_whitespace() {
        let candidate = token.trim().trim_matches(';');
        if candidate.contains(':') && candidate.chars().all(|ch| ch.is_ascii_digit() || ch == ':') {
            return Some(candidate.to_string());
        }
    }
    None
}

fn collect_power_metrics_linux(
    warnings: &mut Vec<String>,
) -> (
    Option<f64>,
    Option<String>,
    Option<String>,
    Option<f64>,
    Option<f64>,
    Option<u64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
) {
    let power_root = Path::new("/sys/class/power_supply");
    let entries = match fs::read_dir(power_root) {
        Ok(entries) => entries,
        Err(error) => {
            warnings.push(format!("power metrics read failed: {error}"));
            return (None, None, None, None, None, None, None, None, None);
        }
    };

    let mut level = None;
    let mut status = None;
    let mut time_left = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let kind = fs::read_to_string(path.join("type"))
            .ok()
            .map(|value| value.trim().to_string())
            .unwrap_or_default();
        if kind != "Battery" {
            continue;
        }
        level = fs::read_to_string(path.join("capacity"))
            .ok()
            .and_then(|value| value.trim().parse::<f64>().ok());
        status = fs::read_to_string(path.join("status"))
            .ok()
            .map(|value| value.trim().to_string());
        time_left = fs::read_to_string(path.join("time_to_empty_now"))
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(format_uptime_like);
        break;
    }

    let cpu_temperature_c = collect_linux_cpu_temperature();
    (
        level,
        status,
        time_left,
        cpu_temperature_c,
        None,
        None,
        None,
        None,
        None,
    )
}

fn collect_macos_thermal_metrics(
    warnings: &mut Vec<String>,
) -> (
    Option<f64>,
    Option<f64>,
    Option<u64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
) {
    let output = ProcessCommand::new("ioreg")
        .args(["-rn", "AppleSmartBattery"])
        .output();
    let text = match output {
        Ok(value) if value.status.success() => String::from_utf8_lossy(&value.stdout).to_string(),
        Ok(value) => {
            warnings.push(format!(
                "thermal metrics ioreg failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            ));
            return (None, None, None, None, None, None);
        }
        Err(error) => {
            warnings.push(format!("thermal metrics ioreg failed: {error}"));
            return (None, None, None, None, None, None);
        }
    };

    let cpu_temperature_c = collect_macos_cpu_temperature();
    let mut battery_temperature_c = None;
    let mut system_power_watts = None;
    let mut adapter_power_watts = None;
    let mut battery_power_watts = None;
    for line in text.lines().map(str::trim) {
        if battery_temperature_c.is_none()
            && let Some(value) = parse_numeric_tail(line, "\"Temperature\" = ")
        {
            battery_temperature_c = Some(value / 100.0);
            continue;
        }
        if system_power_watts.is_none()
            && let Some(value) = parse_numeric_tail(line, "\"SystemPowerIn\"=")
        {
            system_power_watts = Some(value / 1000.0);
            continue;
        }
        if battery_power_watts.is_none()
            && let Some(value) = parse_signed_ioreg_tail(line, "\"BatteryPower\"=")
        {
            battery_power_watts = Some(value / 1000.0);
            continue;
        }
        if adapter_power_watts.is_none()
            && line.contains("\"AdapterDetails\"")
            && let Some((_, watts_part)) = line.split_once("\"Watts\"=")
            && let Some(raw) = extract_first_number(watts_part)
        {
            adapter_power_watts = Some(raw);
        }
    }

    let fan_speed_rpm = collect_macos_fan_speed_rpm();
    (
        cpu_temperature_c,
        battery_temperature_c,
        fan_speed_rpm,
        system_power_watts,
        adapter_power_watts,
        battery_power_watts,
    )
}

fn collect_macos_cpu_temperature() -> Option<f64> {
    collect_macos_cpu_temperature_from_powermetrics()
        .or_else(collect_macos_cpu_temperature_from_osx_cpu_temp)
}

fn collect_macos_cpu_temperature_from_powermetrics() -> Option<f64> {
    let output = ProcessCommand::new("powermetrics")
        .args(["--samplers", "cpu_power,thermal", "-n", "1", "-i", "500"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(value) = parse_powermetrics_cpu_temperature(&stdout) {
        return Some(value);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    parse_powermetrics_cpu_temperature(&stderr)
}

fn parse_powermetrics_cpu_temperature(text: &str) -> Option<f64> {
    let mut fallback = None;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let strong_match = lower.contains("cpu die temperature")
            || lower.contains("cpu temperature")
            || (lower.contains("cpu") && lower.contains("temp"));
        let weak_match = lower.contains("die temperature");
        if !strong_match && !weak_match {
            continue;
        }
        let Some(value) = extract_first_number_anywhere(line) else {
            continue;
        };
        if !(10.0..=130.0).contains(&value) {
            continue;
        }
        if strong_match {
            return Some(value);
        }
        if fallback.is_none() {
            fallback = Some(value);
        }
    }
    fallback
}

fn collect_macos_cpu_temperature_from_osx_cpu_temp() -> Option<f64> {
    let output = ProcessCommand::new("osx-cpu-temp").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    extract_first_number(&text).filter(|value| value.is_finite())
}

fn collect_macos_fan_speed_rpm() -> Option<u64> {
    let output = ProcessCommand::new("system_profiler")
        .args(["SPPowerDataType"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let lower = line.to_lowercase();
        if !(lower.contains("fan") && lower.contains("speed")) {
            continue;
        }
        if let Some((_, value)) = line.split_once(':')
            && let Some(rpm) = extract_first_number(value)
        {
            if rpm.is_finite() && rpm >= 0.0 {
                return Some(rpm.round() as u64);
            }
        }
    }
    None
}

fn collect_linux_cpu_temperature() -> Option<f64> {
    let thermal_root = Path::new("/sys/class/thermal");
    let entries = fs::read_dir(thermal_root).ok()?;
    let mut values = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
        else {
            continue;
        };
        if !name.starts_with("thermal_zone") {
            continue;
        }
        let temp_path = path.join("temp");
        let Some(raw) = fs::read_to_string(temp_path).ok() else {
            continue;
        };
        let Some(parsed) = raw.trim().parse::<f64>().ok() else {
            continue;
        };
        if parsed > 1000.0 {
            values.push(parsed / 1000.0);
        } else if parsed > 0.0 {
            values.push(parsed);
        }
    }
    if values.is_empty() {
        return None;
    }
    Some(values.iter().sum::<f64>() / values.len() as f64)
}

fn parse_numeric_tail(line: &str, marker: &str) -> Option<f64> {
    let (_, tail) = line.split_once(marker)?;
    extract_first_number(tail)
}

fn parse_signed_ioreg_tail(line: &str, marker: &str) -> Option<f64> {
    let (_, tail) = line.split_once(marker)?;
    let raw = tail
        .trim()
        .split(|ch: char| !ch.is_ascii_digit() && ch != '-' && ch != '+')
        .next()?;
    if raw.is_empty() {
        return None;
    }
    if let Ok(signed) = raw.parse::<i64>() {
        return Some(signed as f64);
    }

    // ioreg can emit negative values as uint64 two's-complement.
    let value = raw.parse::<u64>().ok()?;
    if value <= i64::MAX as u64 {
        return Some(value as f64);
    }
    let negative_magnitude = (!value).saturating_add(1);
    if negative_magnitude > i64::MAX as u64 {
        return None;
    }
    Some(-(negative_magnitude as f64))
}

fn extract_first_number(value: &str) -> Option<f64> {
    let cleaned = value
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.' || *ch == '-' || *ch == '+')
        .collect::<String>();
    if cleaned.is_empty() || cleaned == "-" || cleaned == "+" {
        return None;
    }
    cleaned.parse::<f64>().ok()
}

fn extract_first_number_anywhere(value: &str) -> Option<f64> {
    let mut start = None;
    for (index, ch) in value.char_indices() {
        let allowed = ch.is_ascii_digit() || ch == '.' || ch == '-' || ch == '+';
        if allowed {
            if start.is_none() {
                start = Some(index);
            }
            continue;
        }
        if let Some(begin) = start.take() {
            let token = &value[begin..index];
            if let Ok(parsed) = token.parse::<f64>() {
                return Some(parsed);
            }
        }
    }
    if let Some(begin) = start {
        return value[begin..].parse::<f64>().ok();
    }
    None
}

fn format_uptime_like(total_seconds: u64) -> String {
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    format!("{hours}:{minutes:02}")
}

fn check_failed(checks: &[StatusCheck], id: &str) -> bool {
    checks.iter().any(|check| check.id == id && !check.passed)
}

fn calculate_health_score(
    checks: &[StatusCheck],
    metrics: &DashboardMetrics,
    mode: DashboardHealthMode,
) -> u8 {
    match mode {
        DashboardHealthMode::MoleParity => system_health_score(metrics).clamp(0, 100) as u8,
        DashboardHealthMode::PreenStrict => combined_health_score(checks, metrics),
    }
}

fn combined_health_score(checks: &[StatusCheck], metrics: &DashboardMetrics) -> u8 {
    let mut score = system_health_score(metrics);
    for check in checks.iter().filter(|check| !check.passed) {
        let penalty = match check.severity {
            CheckSeverity::Critical => 20_i16,
            CheckSeverity::Warning => 8_i16,
        };
        score = score.saturating_sub(penalty);
    }
    score.clamp(0, 100) as u8
}

fn system_health_score(metrics: &DashboardMetrics) -> i16 {
    // Aligned with Mole scoring model so dashboard health looks familiar to users.
    const CPU_WEIGHT: f64 = 30.0;
    const MEM_WEIGHT: f64 = 25.0;
    const DISK_WEIGHT: f64 = 20.0;
    const THERMAL_WEIGHT: f64 = 15.0;
    const IO_WEIGHT: f64 = 10.0;

    let mut score = 100.0;

    let cpu = metrics.cpu_usage_pct.unwrap_or(0.0);
    score -= cpu_penalty(cpu, CPU_WEIGHT);

    let memory = metrics.memory_used_pct.unwrap_or(0.0);
    score -= memory_penalty(memory, MEM_WEIGHT);
    score -= memory_pressure_penalty(metrics.memory_pressure.as_deref());

    let disk_used = metrics
        .disk_free_pct
        .map(|value| (100.0 - value).max(0.0))
        .unwrap_or(0.0);
    score -= disk_penalty(disk_used, DISK_WEIGHT);

    if let Some(temp) = metrics.cpu_temperature_c {
        score -= thermal_penalty(temp, THERMAL_WEIGHT);
    }

    let total_io =
        metrics.disk_read_rate_mbps.unwrap_or(0.0) + metrics.disk_write_rate_mbps.unwrap_or(0.0);
    score -= io_penalty(total_io, IO_WEIGHT);

    score.clamp(0.0, 100.0).round() as i16
}

fn cpu_penalty(value: f64, weight: f64) -> f64 {
    if value <= 30.0 {
        0.0
    } else if value > 70.0 {
        weight * (value - 30.0) / 70.0
    } else {
        (weight / 2.0) * (value - 30.0) / (70.0 - 30.0)
    }
}

fn memory_penalty(value: f64, weight: f64) -> f64 {
    if value <= 50.0 {
        0.0
    } else if value > 80.0 {
        weight * (value - 50.0) / 50.0
    } else {
        (weight / 2.0) * (value - 50.0) / (80.0 - 50.0)
    }
}

fn memory_pressure_penalty(pressure: Option<&str>) -> f64 {
    match pressure.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => 15.0,
        Some("warn") => 5.0,
        _ => 0.0,
    }
}

fn disk_penalty(value: f64, weight: f64) -> f64 {
    if value <= 70.0 {
        0.0
    } else if value > 90.0 {
        weight * (value - 70.0) / (100.0 - 70.0)
    } else {
        (weight / 2.0) * (value - 70.0) / (90.0 - 70.0)
    }
}

fn thermal_penalty(value: f64, weight: f64) -> f64 {
    if value <= 60.0 {
        0.0
    } else if value > 85.0 {
        weight
    } else {
        weight * (value - 60.0) / (85.0 - 60.0)
    }
}

fn io_penalty(value: f64, weight: f64) -> f64 {
    if value <= 50.0 {
        0.0
    } else if value > 150.0 {
        weight
    } else {
        weight * (value - 50.0) / (150.0 - 50.0)
    }
}

#[cfg(test)]
fn status_health_score(checks: &[StatusCheck]) -> u8 {
    let mut score = 100_i16;
    for check in checks.iter().filter(|check| !check.passed) {
        let penalty = match check.severity {
            CheckSeverity::Critical => 40_i16,
            CheckSeverity::Warning => 15_i16,
        };
        score = score.saturating_sub(penalty);
    }
    score.clamp(0, 100) as u8
}

fn preen_state_dir() -> Result<PathBuf, String> {
    match std::env::consts::OS {
        "macos" => {
            let dir = dirs::home_dir().ok_or_else(|| "missing home dir".to_string())?;
            Ok(dir
                .join("Library")
                .join("Application Support")
                .join("Preen"))
        }
        "linux" => {
            let dir = dirs::config_dir().ok_or_else(|| "missing config dir".to_string())?;
            Ok(dir.join("preen"))
        }
        other => Err(format!("unsupported OS: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DashboardHealthMode, DiskIoAccumulator, calculate_health_score,
        collect_snapshot_for_state_dir, parse_power_details_from_system_profiler,
        parse_powermetrics_cpu_temperature, refresh_power_details_from_ioreg_text,
        status_health_score, system_health_score,
    };
    use preen_core::dashboard::{CheckSeverity, DashboardMetrics, StatusCheck};
    use std::time::{Duration, Instant};

    #[test]
    fn computes_health_score_with_weighted_penalties() {
        let checks = vec![
            StatusCheck {
                id: "state".to_string(),
                label: "State".to_string(),
                severity: CheckSeverity::Critical,
                passed: false,
                message: String::new(),
            },
            StatusCheck {
                id: "registry".to_string(),
                label: "Registry".to_string(),
                severity: CheckSeverity::Warning,
                passed: false,
                message: String::new(),
            },
        ];
        assert_eq!(status_health_score(&checks), 45);
    }

    #[test]
    fn dashboard_health_mode_defaults_to_mole_parity() {
        assert_eq!(
            DashboardHealthMode::from_str(None),
            DashboardHealthMode::MoleParity
        );
        assert_eq!(
            DashboardHealthMode::from_str(Some("unknown-mode")),
            DashboardHealthMode::MoleParity
        );
    }

    #[test]
    fn dashboard_health_mode_parses_strict_aliases() {
        assert_eq!(
            DashboardHealthMode::from_str(Some("preen_strict")),
            DashboardHealthMode::PreenStrict
        );
        assert_eq!(
            DashboardHealthMode::from_str(Some("STRICT")),
            DashboardHealthMode::PreenStrict
        );
    }

    #[test]
    fn network_history_keeps_120_points_max() {
        let mut acc = super::NetworkAccumulator::default();
        let mut rx = 1_000_u64;
        let mut tx = 2_000_u64;

        for _ in 0..150 {
            rx = rx.saturating_add(1_000);
            tx = tx.saturating_add(2_000);
            let _ = acc.capture(Some(rx), Some(tx));
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        assert_eq!(acc.rx_history_mbps.len(), 120);
        assert_eq!(acc.tx_history_mbps.len(), 120);
    }

    #[test]
    fn disk_io_accumulator_converts_interval_bytes_to_rate() {
        let mut acc = DiskIoAccumulator::default();
        let start = Instant::now();
        let first = acc.capture_at(Some(1024 * 1024), Some(2 * 1024 * 1024), start);
        assert_eq!(first, (None, None));

        let second = acc.capture_at(
            Some(1024 * 1024),
            Some(2 * 1024 * 1024),
            start + Duration::from_secs(2),
        );
        let (read, write) = second;
        let read = read.expect("read rate");
        let write = write.expect("write rate");
        assert!((read - 0.5).abs() < 0.05);
        assert!((write - 1.0).abs() < 0.05);
    }

    #[test]
    fn system_health_score_applies_memory_pressure_penalty() {
        let mut metrics = DashboardMetrics {
            cpu_usage_pct: Some(0.0),
            memory_used_pct: Some(0.0),
            disk_free_pct: Some(100.0),
            disk_read_rate_mbps: Some(0.0),
            disk_write_rate_mbps: Some(0.0),
            ..DashboardMetrics::default()
        };

        metrics.memory_pressure = Some("normal".to_string());
        assert_eq!(system_health_score(&metrics), 100);

        metrics.memory_pressure = Some("warn".to_string());
        assert_eq!(system_health_score(&metrics), 95);

        metrics.memory_pressure = Some("critical".to_string());
        assert_eq!(system_health_score(&metrics), 85);
    }

    #[test]
    fn calculate_health_score_respects_mode() {
        let checks = vec![
            StatusCheck {
                id: "critical_fail".to_string(),
                label: "Critical".to_string(),
                severity: CheckSeverity::Critical,
                passed: false,
                message: String::new(),
            },
            StatusCheck {
                id: "warning_fail".to_string(),
                label: "Warning".to_string(),
                severity: CheckSeverity::Warning,
                passed: false,
                message: String::new(),
            },
        ];
        let metrics = DashboardMetrics {
            cpu_usage_pct: Some(0.0),
            memory_used_pct: Some(0.0),
            disk_free_pct: Some(100.0),
            disk_read_rate_mbps: Some(0.0),
            disk_write_rate_mbps: Some(0.0),
            ..DashboardMetrics::default()
        };

        let mole_score = calculate_health_score(&checks, &metrics, DashboardHealthMode::MoleParity);
        let strict_score =
            calculate_health_score(&checks, &metrics, DashboardHealthMode::PreenStrict);

        assert_eq!(mole_score, 100);
        assert_eq!(strict_score, 72);
    }

    #[test]
    fn collects_snapshot_for_temp_state_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();
        std::fs::create_dir_all(state_dir).expect("state dir");
        let snapshot = collect_snapshot_for_state_dir(state_dir).expect("snapshot");
        assert_eq!(snapshot.state_dir, state_dir);
        assert_eq!(snapshot.plugin_count, 0);
        assert!(snapshot.health_score <= 100);
    }

    #[test]
    fn parses_system_profiler_power_details() {
        let text = r#"
        Condition: Normal
        Cycle Count: 339
        Maximum Capacity: 89%
        "#;
        let details = parse_power_details_from_system_profiler(text);
        assert_eq!(details.health.as_deref(), Some("Normal"));
        assert_eq!(details.cycle_count, Some(339));
        assert_eq!(details.capacity_pct, Some(89.0));
    }

    #[test]
    fn parses_system_profiler_capacity_with_nbsp_percent() {
        let text = "Maximum Capacity: 89\u{00A0}%";
        let details = parse_power_details_from_system_profiler(text);
        assert_eq!(details.capacity_pct, Some(89.0));
    }

    #[test]
    fn parses_ioreg_power_details_for_capacity_fallback() {
        let text = r#"
        | |   "BatteryHealth" = "Good"
        | |   "CycleCount"=339
        | |   "NominalChargeCapacity"=4570
        | |   "DesignCapacity"=5103
        "#;
        let details = refresh_power_details_from_ioreg_text(text);
        assert_eq!(details.health.as_deref(), Some("Good"));
        assert_eq!(details.cycle_count, Some(339));
        assert!(details.capacity_pct.is_some());
        let capacity = details.capacity_pct.unwrap_or_default();
        assert!((capacity - 89.5).abs() < 0.2);
    }

    #[test]
    fn parses_powermetrics_cpu_temperature_from_strong_label() {
        let text = r#"
        CPU die temperature: 67.8 C
        "#;
        assert_eq!(parse_powermetrics_cpu_temperature(text), Some(67.8));
    }

    #[test]
    fn parses_powermetrics_cpu_temperature_from_generic_cpu_temp_line() {
        let text = r#"
        E-Cluster active residency: 22.4%
        CPU temperature 64.2 degC
        "#;
        assert_eq!(parse_powermetrics_cpu_temperature(text), Some(64.2));
    }

    #[test]
    fn ignores_powermetrics_temperature_out_of_expected_range() {
        let text = r#"
        CPU die temperature: 3.5 C
        "#;
        assert_eq!(parse_powermetrics_cpu_temperature(text), None);
    }
}
