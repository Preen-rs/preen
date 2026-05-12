use preen_core::action_runtime::{
    ActionExecutionError, DefaultSafetyPolicy, ExecutionMode, RuntimeExecutionError,
    execute_action_with_audit,
};
use preen_core::dashboard::DashboardSnapshot;
use preen_core::performance_view::{
    PerformanceAnalyzeOutput, PerformanceOptimizationTask, PerformanceOptimizeResult,
    PerformanceOptimizeSelection, PerformanceTaskDetail, PerformanceTaskRisk,
    PerformanceTaskTarget, PerformanceViewModel,
};
use preen_core::plugin::{
    ActionMode, ActionSpec, ActionType, Manifest, MatchMode, MatchSpec, OsTarget, RiskLevel,
    RuleFile, RuleRef,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant, SystemTime};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const SAVED_STATE_MAX_AGE_DAYS: u64 = 30;
const SQLITE_MAX_VACUUM_BYTES: u64 = 100 * 1024 * 1024;

pub fn analyze(snapshot: &DashboardSnapshot) -> PerformanceAnalyzeOutput {
    let model = PerformanceViewModel::from_snapshot(snapshot);
    let details = model
        .optimization_tasks
        .iter()
        .map(|task| detail_for_task(task, snapshot))
        .collect();
    PerformanceAnalyzeOutput { model, details }
}

pub fn execute(
    snapshot: &DashboardSnapshot,
    details: &[PerformanceTaskDetail],
    selections: Vec<PerformanceOptimizeSelection>,
) -> PerformanceOptimizeResult {
    let detail_by_id = details
        .iter()
        .map(|detail| (detail.task_id.as_str(), detail))
        .collect::<BTreeMap<_, _>>();
    let mut lines = Vec::new();
    let mut completed_task_ids = Vec::new();

    if selections.is_empty() {
        return PerformanceOptimizeResult {
            lines: vec!["no optimization task selected".to_string()],
            completed_task_ids,
        };
    }

    for selection in selections {
        let target_ids = selection
            .target_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let result = match selection.task_id.as_str() {
            "inspect_top_processes" => inspect_top_processes(snapshot),
            "flush_dns_cache" => flush_dns_cache(),
            "sync_filesystem_buffers" => sync_filesystem_buffers(),
            "memory_pressure_relief" => memory_pressure_relief(),
            "thin_local_snapshots" => {
                let detail = detail_by_id.get(selection.task_id.as_str()).copied();
                thin_local_snapshots(detail, &target_ids)
            }
            "purge_apfs_space" => purge_apfs_space(),
            "run_periodic_maintenance" => run_periodic_maintenance(),
            "reset_app_store_cache" => {
                let detail = detail_by_id.get(selection.task_id.as_str()).copied();
                reset_app_store_cache(detail, &target_ids)
            }
            "refresh_finder_caches" => {
                let detail = detail_by_id.get(selection.task_id.as_str()).copied();
                refresh_finder_caches(detail, &target_ids)
            }
            "cleanup_saved_states" => {
                let detail = detail_by_id.get(selection.task_id.as_str()).copied();
                cleanup_saved_states(detail, &target_ids)
            }
            "repair_broken_preferences" => {
                let detail = detail_by_id.get(selection.task_id.as_str()).copied();
                repair_broken_preferences(detail, &target_ids)
            }
            "optimize_app_databases" => {
                let detail = detail_by_id.get(selection.task_id.as_str()).copied();
                optimize_app_databases(detail, &target_ids)
            }
            "repair_launch_services" => repair_launch_services(),
            "rebuild_font_cache" => rebuild_font_cache(),
            "refresh_dock" => refresh_dock(),
            "inspect_login_items" => {
                let detail = detail_by_id.get(selection.task_id.as_str()).copied();
                update_login_items(detail, &target_ids)
            }
            "refresh_network_stack" => refresh_network_stack(),
            "repair_user_permissions" => repair_user_permissions(),
            "refresh_bluetooth" => refresh_bluetooth(),
            "optimize_spotlight_index" => optimize_spotlight_index(),
            "refresh_fontconfig_cache" => refresh_fontconfig_cache(),
            "refresh_user_systemd" => refresh_user_systemd(),
            "vacuum_user_journal" => vacuum_user_journal(),
            "defer_heavy_maintenance" => vec![
                "skipped: heavy maintenance should run later when system pressure is lower"
                    .to_string(),
            ],
            other => vec![format!("skipped: unknown optimization task {other}")],
        };

        let ok = result.iter().any(|line| {
            line.starts_with("done:")
                || line.starts_with("removed:")
                || line.starts_with("inspected:")
        });
        if ok {
            completed_task_ids.push(selection.task_id);
        }
        lines.extend(result);
    }

    PerformanceOptimizeResult {
        lines,
        completed_task_ids,
    }
}

pub fn preview(
    details: &[PerformanceTaskDetail],
    selections: Vec<PerformanceOptimizeSelection>,
) -> PerformanceOptimizeResult {
    let detail_by_id = details
        .iter()
        .map(|detail| (detail.task_id.as_str(), detail))
        .collect::<BTreeMap<_, _>>();
    if selections.is_empty() {
        return PerformanceOptimizeResult {
            lines: vec!["dry-run: no optimization task selected".to_string()],
            completed_task_ids: Vec::new(),
        };
    }

    let mut lines = vec![format!(
        "dry-run: {} optimization task(s) selected",
        selections.len()
    )];
    for selection in selections {
        let Some(detail) = detail_by_id.get(selection.task_id.as_str()).copied() else {
            lines.push(format!("would skip unknown task: {}", selection.task_id));
            continue;
        };
        lines.push(format!("would run: {}", detail.title));
        if detail.targets.is_empty() {
            lines.push("  target whitelist: whole task".to_string());
            continue;
        }
        if selection.target_ids.is_empty() {
            lines.push("  target whitelist: none selected; task would skip".to_string());
            continue;
        }
        for target in detail
            .targets
            .iter()
            .filter(|target| selection.target_ids.contains(&target.id))
        {
            lines.push(format!("  target: {}", target.label));
        }
    }

    PerformanceOptimizeResult {
        lines,
        completed_task_ids: Vec::new(),
    }
}

fn detail_for_task(
    task: &PerformanceOptimizationTask,
    snapshot: &DashboardSnapshot,
) -> PerformanceTaskDetail {
    match task.id.as_str() {
        "inspect_top_processes" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: "Review CPU and memory-heavy processes before changing the system".to_string(),
            notes: snapshot
                .metrics
                .top_processes
                .iter()
                .take(10)
                .map(|process| {
                    format!(
                        "{}: cpu {:.1}% | memory {:.1}%",
                        process.name, process.cpu_pct, process.memory_pct
                    )
                })
                .collect(),
            targets: Vec::new(),
        },
        "inspect_login_items" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: "Select startup agents that should be moved to Trash".to_string(),
            notes: vec![
                "User LaunchAgents can be removed directly.".to_string(),
                "System LaunchAgents and LaunchDaemons are shown but require a future privileged helper."
                    .to_string(),
            ],
            targets: login_item_targets(),
        },
        "flush_dns_cache" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Refreshes local DNS resolver state.".to_string(),
                "Does not delete user data.".to_string(),
            ],
            targets: Vec::new(),
        },
        "refresh_finder_caches" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Resets QuickLook and icon services metadata.".to_string(),
                "Selected cache folders are rebuilt by macOS when needed.".to_string(),
            ],
            targets: finder_cache_targets(),
        },
        "cleanup_saved_states" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                format!("Only saved states older than {SAVED_STATE_MAX_AGE_DAYS} days are selected."),
                "This resets stale app window/session restore data.".to_string(),
            ],
            targets: saved_state_targets(),
        },
        "repair_broken_preferences" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Validates user preference plists before offering any repair.".to_string(),
                "Broken files are moved to Trash so the app can regenerate them.".to_string(),
            ],
            targets: broken_preference_targets(),
        },
        "optimize_app_databases" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Skips Mail, Safari, and Messages databases while those apps are running."
                    .to_string(),
                "Runs SQLite integrity checks before VACUUM.".to_string(),
            ],
            targets: sqlite_database_targets(),
        },
        "repair_launch_services" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Rebuilds macOS app registration and Open With metadata.".to_string(),
                "No user files are deleted.".to_string(),
            ],
            targets: Vec::new(),
        },
        "rebuild_font_cache" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Skips when common browsers are running.".to_string(),
                "Font databases are rebuilt automatically by macOS.".to_string(),
            ],
            targets: Vec::new(),
        },
        "refresh_dock" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Clears Dock icon cache database files.".to_string(),
                "Dock restarts automatically after the refresh.".to_string(),
            ],
            targets: dock_cache_targets(),
        },
        "sync_filesystem_buffers" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec!["Asks the OS to flush pending filesystem buffers.".to_string()],
            targets: Vec::new(),
        },
        "thin_local_snapshots" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Lists Time Machine local snapshots reported by tmutil.".to_string(),
                "Snapshots are not selected by default and may require administrator approval."
                    .to_string(),
            ],
            targets: local_snapshot_targets(),
        },
        "purge_apfs_space" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Requests APFS purgeable-space reclamation through diskutil.".to_string(),
                "This can take time and may require administrator approval.".to_string(),
            ],
            targets: Vec::new(),
        },
        "run_periodic_maintenance" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Runs the macOS periodic daily, weekly, and monthly scripts.".to_string(),
                "No user documents are deleted, but the task can take time.".to_string(),
            ],
            targets: Vec::new(),
        },
        "reset_app_store_cache" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Quits App Store and update helper processes before clearing selected caches."
                    .to_string(),
                "Use after stuck or failed Mac App Store updates.".to_string(),
            ],
            targets: app_store_cache_targets(),
        },
        "memory_pressure_relief" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Runs the OS-native memory relief command when available.".to_string(),
                "Best used after closing unnecessary applications.".to_string(),
            ],
            targets: Vec::new(),
        },
        "refresh_network_stack" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Checks default route and DNS before changing network caches.".to_string(),
                "Flushes route and ARP caches only when checks indicate stale state.".to_string(),
            ],
            targets: Vec::new(),
        },
        "repair_user_permissions" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Checks home ownership and write access first.".to_string(),
                "Uses the OS user-permission repair path only when needed.".to_string(),
            ],
            targets: Vec::new(),
        },
        "refresh_bluetooth" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Skips when Bluetooth HID or audio devices appear active.".to_string(),
                "Restarts bluetoothd so macOS can recreate the service.".to_string(),
            ],
            targets: Vec::new(),
        },
        "optimize_spotlight_index" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Checks Spotlight status and search latency first.".to_string(),
                "Rebuilds the index only when search looks slow and AC power is available."
                    .to_string(),
            ],
            targets: Vec::new(),
        },
        "refresh_fontconfig_cache" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Runs fontconfig cache refresh on Linux.".to_string(),
                "No user documents are deleted.".to_string(),
            ],
            targets: Vec::new(),
        },
        "refresh_user_systemd" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Reloads the user systemd manager after startup item changes.".to_string(),
                "Does not disable or remove services by itself.".to_string(),
            ],
            targets: Vec::new(),
        },
        "vacuum_user_journal" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Keeps recent user journal entries and trims older user logs.".to_string(),
                "System logs are not touched.".to_string(),
            ],
            targets: Vec::new(),
        },
        _ => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![task.reason.clone()],
            targets: Vec::new(),
        },
    }
}

fn inspect_top_processes(snapshot: &DashboardSnapshot) -> Vec<String> {
    let mut lines = vec!["inspected: top process pressure".to_string()];
    for process in snapshot.metrics.top_processes.iter().take(10) {
        lines.push(format!(
            "{}: cpu {:.1}% | memory {:.1}%",
            process.name, process.cpu_pct, process.memory_pct
        ));
    }
    if lines.len() == 1 {
        lines.push("no process sample available".to_string());
    }
    lines
}

fn flush_dns_cache() -> Vec<String> {
    let mut lines = vec!["checking: flushing DNS cache".to_string()];
    match std::env::consts::OS {
        "macos" => {
            lines.extend(run_command("dscacheutil", &["-flushcache"]));
            lines.extend(run_command("killall", &["-HUP", "mDNSResponder"]));
        }
        "linux" => {
            lines.extend(run_command("resolvectl", &["flush-caches"]));
        }
        _ => lines.push("skipped: DNS cache flush is not supported on this OS yet".to_string()),
    }
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: DNS cache refreshed".to_string());
    }
    lines
}

fn sync_filesystem_buffers() -> Vec<String> {
    let mut lines = vec!["checking: syncing filesystem buffers".to_string()];
    lines.extend(run_command("sync", &[]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: filesystem buffers synced".to_string());
    }
    lines
}

fn memory_pressure_relief() -> Vec<String> {
    let mut lines = vec!["checking: memory pressure relief".to_string()];
    if std::env::consts::OS != "macos" {
        lines.push("skipped: memory pressure relief is not supported on this OS yet".to_string());
        return lines;
    }
    for command in ["/usr/bin/purge", "/usr/sbin/purge"] {
        if Path::new(command).exists() {
            lines.extend(run_command(command, &[]));
            if lines.iter().any(|line| line.starts_with("done:")) {
                lines.push("done: memory pressure relief requested".to_string());
            }
            return lines;
        }
    }
    lines.push("skipped: purge command is not available".to_string());
    lines
}

fn thin_local_snapshots(
    detail: Option<&PerformanceTaskDetail>,
    selected_target_ids: &BTreeSet<String>,
) -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: local snapshot thinning is macOS-only".to_string()];
    }
    let Some(detail) = detail else {
        return vec!["failed: local snapshot detail is unavailable".to_string()];
    };
    if selected_target_ids.is_empty() {
        return vec!["skipped: no local snapshot selected".to_string()];
    }

    let mut lines = Vec::new();
    for target in &detail.targets {
        if !selected_target_ids.contains(&target.id) {
            continue;
        }
        let Some(snapshot_date) = target.description.strip_prefix("snapshot: ") else {
            lines.push(format!("skipped: {} has no snapshot date", target.label));
            continue;
        };
        let snapshot_date = snapshot_date
            .strip_prefix("com.apple.TimeMachine.")
            .unwrap_or(snapshot_date)
            .strip_suffix(".local")
            .unwrap_or(snapshot_date);
        lines.push(format!("checking: thinning {}", target.label));
        lines.extend(run_command(
            "tmutil",
            &["deletelocalsnapshots", snapshot_date],
        ));
    }
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: selected local snapshots thinned".to_string());
    }
    if lines.is_empty() {
        lines.push("skipped: selected snapshots were not found".to_string());
    }
    lines
}

fn run_periodic_maintenance() -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: periodic maintenance is macOS-only".to_string()];
    }
    let Some(periodic) = ["/usr/sbin/periodic"]
        .into_iter()
        .find(|path| Path::new(path).exists())
    else {
        return vec!["skipped: periodic helper is not available".to_string()];
    };
    let mut lines = vec!["checking: running periodic maintenance".to_string()];
    lines.extend(run_command(periodic, &["daily", "weekly", "monthly"]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: periodic maintenance completed".to_string());
    }
    lines
}

fn purge_apfs_space() -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: APFS purgeable-space reclaim is macOS-only".to_string()];
    }
    let mut lines = vec!["checking: purging APFS reclaimable space".to_string()];
    lines.extend(run_command("diskutil", &["apfs", "purgePurgeable", "/"]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: APFS purgeable-space reclaim requested".to_string());
    }
    lines
}

fn reset_app_store_cache(
    detail: Option<&PerformanceTaskDetail>,
    selected_target_ids: &BTreeSet<String>,
) -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: App Store cache reset is macOS-only".to_string()];
    }
    let mut lines = vec!["checking: resetting App Store update cache".to_string()];
    let _ = run_command_capture(
        "osascript",
        &["-e", "tell application \"App Store\" to quit"],
    );
    for process in [
        "App Store",
        "appstoreagent",
        "appstored",
        "storedownloadd",
        "storeagent",
        "storeuid",
        "commerce",
    ] {
        let _ = run_command_capture("pkill", &["-x", process]);
    }
    let removed = remove_selected_targets(detail, selected_target_ids, "App Store cache");
    if removed.is_empty() {
        lines.push("skipped: no App Store cache selected".to_string());
    } else {
        lines.extend(removed);
    }
    lines.push("done: App Store update helpers refreshed".to_string());
    lines
}

fn refresh_finder_caches(
    detail: Option<&PerformanceTaskDetail>,
    selected_target_ids: &BTreeSet<String>,
) -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: Finder cache refresh is macOS-only".to_string()];
    }
    let mut lines = vec!["checking: refreshing Finder caches".to_string()];
    lines.extend(run_command("qlmanage", &["-r", "cache"]));
    lines.extend(run_command("qlmanage", &["-r"]));
    lines.extend(remove_selected_targets(
        detail,
        selected_target_ids,
        "Finder cache",
    ));
    lines.push("done: Finder caches refreshed".to_string());
    lines
}

fn cleanup_saved_states(
    detail: Option<&PerformanceTaskDetail>,
    selected_target_ids: &BTreeSet<String>,
) -> Vec<String> {
    let lines = remove_selected_targets(detail, selected_target_ids, "saved state");
    if lines.is_empty() {
        return vec!["skipped: no old saved state selected".to_string()];
    }
    lines
}

fn repair_broken_preferences(
    detail: Option<&PerformanceTaskDetail>,
    selected_target_ids: &BTreeSet<String>,
) -> Vec<String> {
    let lines = remove_selected_targets(detail, selected_target_ids, "broken preference");
    if lines.is_empty() {
        return vec!["skipped: no broken preference selected".to_string()];
    }
    lines
}

fn optimize_app_databases(
    detail: Option<&PerformanceTaskDetail>,
    selected_target_ids: &BTreeSet<String>,
) -> Vec<String> {
    let Some(detail) = detail else {
        return vec!["failed: database detail is unavailable".to_string()];
    };
    if selected_target_ids.is_empty() {
        return vec!["skipped: no database selected".to_string()];
    }
    if running_any(&["Mail", "Safari", "Messages"]) {
        return vec![
            "skipped: close Mail, Safari, and Messages before optimizing app databases".to_string(),
        ];
    }

    let mut lines = Vec::new();
    for target in &detail.targets {
        if !selected_target_ids.contains(&target.id) {
            continue;
        }
        let Some(path) = target.path.as_deref().map(Path::new) else {
            lines.push(format!("skipped: {} has no path", target.label));
            continue;
        };
        if !path.exists() {
            lines.push(format!("skipped: {} no longer exists", target.label));
            continue;
        }
        if fs::metadata(path)
            .map(|metadata| metadata.len() > SQLITE_MAX_VACUUM_BYTES)
            .unwrap_or(true)
        {
            lines.push(format!(
                "skipped: {} is too large for interactive vacuum",
                target.label
            ));
            continue;
        }
        let integrity = run_command_capture(
            "sqlite3",
            &[path.to_string_lossy().as_ref(), "PRAGMA integrity_check;"],
        );
        match integrity {
            Ok(output) if output.trim() == "ok" => {
                match run_command_capture("sqlite3", &[path.to_string_lossy().as_ref(), "VACUUM;"])
                {
                    Ok(_) => lines.push(format!("done: optimized {}", target.label)),
                    Err(error) => lines.push(format!("failed: {} ({error})", target.label)),
                }
            }
            Ok(output) => lines.push(format!(
                "skipped: {} integrity check returned {}",
                target.label,
                output.trim()
            )),
            Err(error) => lines.push(format!(
                "failed: {} integrity check ({error})",
                target.label
            )),
        }
    }
    if lines.is_empty() {
        lines.push("skipped: selected databases were not found".to_string());
    }
    lines
}

fn repair_launch_services() -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: LaunchServices repair is macOS-only".to_string()];
    }
    let Some(lsregister) = launch_services_register_path() else {
        return vec!["skipped: lsregister helper is not available".to_string()];
    };
    let helper = lsregister.to_string_lossy().to_string();
    let mut lines = vec!["checking: repairing LaunchServices".to_string()];
    lines.extend(run_command(&helper, &["-gc"]));
    lines.extend(run_command(
        &helper,
        &[
            "-r", "-f", "-domain", "local", "-domain", "user", "-domain", "system",
        ],
    ));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: LaunchServices metadata rebuilt".to_string());
    }
    lines
}

fn rebuild_font_cache() -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: font cache rebuild is macOS-only".to_string()];
    }
    if let Some(browser) = running_browser_name() {
        return vec![format!(
            "skipped: close {browser} before rebuilding font caches"
        )];
    }
    let mut lines = vec!["checking: rebuilding font cache".to_string()];
    lines.extend(run_command("atsutil", &["databases", "-remove"]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: font cache rebuild requested".to_string());
    }
    lines
}

fn refresh_dock() -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: Dock refresh is macOS-only".to_string()];
    }
    let mut lines = vec!["checking: refreshing Dock".to_string()];
    for target in dock_cache_targets() {
        if let Some(path) = target.path.as_deref().map(Path::new) {
            if path.exists() {
                match trash::delete(path) {
                    Ok(()) => lines.push(format!("removed: {}", target.label)),
                    Err(error) => lines.push(format!("failed: {} ({error})", target.label)),
                }
            }
        }
    }
    if let Some(home) = home_dir() {
        let plist = home
            .join("Library")
            .join("Preferences")
            .join("com.apple.dock.plist");
        if plist.exists() {
            let _ = fs::OpenOptions::new().append(true).open(plist);
        }
    }
    lines.extend(run_command("killall", &["Dock"]));
    if lines
        .iter()
        .any(|line| line.starts_with("done:") || line.starts_with("removed:"))
    {
        lines.push("done: Dock refreshed".to_string());
    }
    lines
}

fn refresh_network_stack() -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: network stack refresh is macOS-only".to_string()];
    }
    let route_ok = run_command_capture("route", &["-n", "get", "default"]).is_ok();
    let dns_ok = run_command_capture("scutil", &["--dns"])
        .map(|output| output.contains("nameserver"))
        .unwrap_or(false);
    if route_ok && dns_ok {
        return vec!["done: network route and DNS checks already look healthy".to_string()];
    }
    let mut lines = vec!["checking: refreshing network stack".to_string()];
    lines.extend(run_command("route", &["-n", "flush"]));
    lines.extend(run_command("arp", &["-a", "-d"]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: network stack refresh requested".to_string());
    }
    lines
}

fn repair_user_permissions() -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: user permission repair is macOS-only".to_string()];
    }
    if !home_permissions_need_repair() {
        return vec!["done: user folder permissions already look healthy".to_string()];
    }
    let uid = match run_command_capture("id", &["-u"]) {
        Ok(value) => value.trim().to_string(),
        Err(error) => return vec![format!("failed: could not resolve uid ({error})")],
    };
    let mut lines = vec!["checking: repairing user permissions".to_string()];
    lines.extend(run_command(
        "diskutil",
        &["resetUserPermissions", "/", &uid],
    ));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: user permission repair requested".to_string());
    }
    lines
}

fn refresh_bluetooth() -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: Bluetooth refresh is macOS-only".to_string()];
    }
    if bluetooth_dependency_active() {
        return vec!["skipped: active Bluetooth input or audio dependency detected".to_string()];
    }
    let mut lines = vec!["checking: refreshing Bluetooth".to_string()];
    lines.extend(run_command("pkill", &["-TERM", "bluetoothd"]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: bluetoothd restart requested".to_string());
    }
    lines
}

fn optimize_spotlight_index() -> Vec<String> {
    if std::env::consts::OS != "macos" {
        return vec!["skipped: Spotlight optimization is macOS-only".to_string()];
    }
    let status = run_command_capture("mdutil", &["-s", "/"]).unwrap_or_default();
    if status.to_ascii_lowercase().contains("disabled") {
        return vec!["skipped: Spotlight indexing is disabled".to_string()];
    }
    if !spotlight_search_looks_slow() {
        return vec!["done: Spotlight search latency looks healthy".to_string()];
    }
    if !on_ac_power() {
        return vec!["skipped: Spotlight rebuild waits for AC power".to_string()];
    }
    let mut lines = vec!["checking: rebuilding Spotlight index".to_string()];
    lines.extend(run_command("mdutil", &["-E", "/"]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: Spotlight rebuild requested".to_string());
    }
    lines
}

fn refresh_fontconfig_cache() -> Vec<String> {
    if std::env::consts::OS != "linux" {
        return vec!["skipped: fontconfig refresh is Linux-only".to_string()];
    }
    let mut lines = vec!["checking: refreshing fontconfig cache".to_string()];
    lines.extend(run_command("fc-cache", &["-r"]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: fontconfig cache refreshed".to_string());
    }
    lines
}

fn refresh_user_systemd() -> Vec<String> {
    if std::env::consts::OS != "linux" {
        return vec!["skipped: user service refresh is Linux-only".to_string()];
    }
    let mut lines = vec!["checking: reloading user service manager".to_string()];
    lines.extend(run_command("systemctl", &["--user", "daemon-reload"]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: user service manager reloaded".to_string());
    }
    lines
}

fn vacuum_user_journal() -> Vec<String> {
    if std::env::consts::OS != "linux" {
        return vec!["skipped: user journal vacuum is Linux-only".to_string()];
    }
    let mut lines = vec!["checking: vacuuming user journal".to_string()];
    lines.extend(run_command("journalctl", &["--user", "--vacuum-time=7d"]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: user journal vacuumed".to_string());
    }
    lines
}

fn update_login_items(
    detail: Option<&PerformanceTaskDetail>,
    selected_target_ids: &BTreeSet<String>,
) -> Vec<String> {
    let Some(detail) = detail else {
        return vec!["failed: login item detail is unavailable".to_string()];
    };
    if selected_target_ids.is_empty() {
        return vec!["skipped: no login item selected".to_string()];
    }

    let mut lines = Vec::new();
    for target in &detail.targets {
        if !selected_target_ids.contains(&target.id) {
            continue;
        }
        if let Some(unit) = target.id.strip_prefix("systemd_user__") {
            lines.extend(disable_user_systemd_unit(unit));
            continue;
        }
        let Some(path) = target.path.as_deref().map(Path::new) else {
            lines.push(format!("skipped: {} has no path", target.label));
            continue;
        };
        if target.requires_admin {
            lines.push(format!(
                "skipped: {} requires a privileged helper",
                target.label
            ));
            continue;
        }
        if !is_user_launch_agent(path) {
            if !is_user_autostart_entry(path) {
                lines.push(format!(
                    "skipped: {} is outside user startup locations",
                    target.label
                ));
                continue;
            }
        } else {
            let _ = bootout_launch_agent(path);
        }
        match trash::delete(path) {
            Ok(()) => lines.push(format!("removed: {}", target.label)),
            Err(error) => lines.push(format!("failed: {} ({error})", target.label)),
        }
    }
    if lines.is_empty() {
        lines.push("skipped: selected login items were not found".to_string());
    }
    lines
}

fn login_item_targets() -> Vec<PerformanceTaskTarget> {
    let mut targets = Vec::new();
    for root in login_item_roots() {
        let Ok(entries) = fs::read_dir(&root.path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let extension = path.extension().and_then(|value| value.to_str());
            if extension != Some("plist") && extension != Some("desktop") {
                continue;
            }
            let fallback_label = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("login item")
                .to_string();
            let info = read_launch_plist_info(&path);
            let launch_label = info.label.as_deref().unwrap_or(&fallback_label);
            let label = if extension == Some("desktop") {
                read_desktop_entry_name(&path)
                    .unwrap_or_else(|| humanize_identifier(&fallback_label))
            } else {
                human_launch_label(launch_label, info.executable.as_deref())
            };
            let description =
                launch_item_description(&root, launch_label, info.executable.as_deref());
            targets.push(PerformanceTaskTarget {
                id: stable_target_id(&path),
                label,
                description,
                path: Some(path.to_string_lossy().into_owned()),
                selected_by_default: false,
                requires_admin: root.requires_admin,
                risk: if root.requires_admin {
                    PerformanceTaskRisk::Medium
                } else {
                    PerformanceTaskRisk::Low
                },
            });
        }
    }
    targets.extend(user_systemd_targets());
    targets.sort_by(|left, right| {
        left.requires_admin
            .cmp(&right.requires_admin)
            .then_with(|| left.label.cmp(&right.label))
    });
    targets
}

fn local_snapshot_targets() -> Vec<PerformanceTaskTarget> {
    if std::env::consts::OS != "macos" {
        return Vec::new();
    }
    let output = run_command_capture("tmutil", &["listlocalsnapshots", "/"]).unwrap_or_default();
    output
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("com.apple.TimeMachine."))
        .map(|snapshot| {
            let date = snapshot
                .strip_prefix("com.apple.TimeMachine.")
                .unwrap_or(snapshot)
                .strip_suffix(".local")
                .unwrap_or(snapshot);
            PerformanceTaskTarget {
                id: format!("tm_snapshot__{}", stable_target_text(snapshot)),
                label: format!("Time Machine {date}"),
                description: format!("snapshot: {snapshot}"),
                path: None,
                selected_by_default: false,
                requires_admin: true,
                risk: PerformanceTaskRisk::Medium,
            }
        })
        .collect()
}

fn app_store_cache_targets() -> Vec<PerformanceTaskTarget> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    [
        (
            "App Store cache",
            home.join("Library")
                .join("Caches")
                .join("com.apple.appstore"),
        ),
        (
            "App Store cache store",
            home.join("Library")
                .join("Caches")
                .join("com.apple.AppStore"),
        ),
        (
            "App Store daemon cache",
            home.join("Library")
                .join("Caches")
                .join("com.apple.appstored"),
        ),
        (
            "Store commerce cache",
            home.join("Library")
                .join("Caches")
                .join("com.apple.commerce"),
        ),
    ]
    .into_iter()
    .filter(|(_, path)| path.exists())
    .map(|(label, path)| target_from_path(label, "Mac App Store update cache", path, false, true))
    .collect()
}

fn finder_cache_targets() -> Vec<PerformanceTaskTarget> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    [
        (
            "QuickLook thumbnails",
            home.join("Library")
                .join("Caches")
                .join("com.apple.QuickLook.thumbnailcache"),
        ),
        (
            "Icon services store",
            home.join("Library")
                .join("Caches")
                .join("com.apple.iconservices.store"),
        ),
        (
            "Icon services cache",
            home.join("Library")
                .join("Caches")
                .join("com.apple.iconservices"),
        ),
    ]
    .into_iter()
    .map(|(label, path)| target_from_path(label, "Finder visual cache", path, false, true))
    .collect()
}

fn saved_state_targets() -> Vec<PerformanceTaskTarget> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let root = home.join("Library").join("Saved Application State");
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("savedState") {
            continue;
        }
        if !path_is_older_than_days(&path, SAVED_STATE_MAX_AGE_DAYS) {
            continue;
        }
        let label = saved_state_label(&path);
        targets.push(target_from_path(
            &label,
            "Saved app window/session state",
            path,
            false,
            true,
        ));
    }
    targets.sort_by(|left, right| left.label.cmp(&right.label));
    targets
}

fn broken_preference_targets() -> Vec<PerformanceTaskTarget> {
    if std::env::consts::OS != "macos" {
        return Vec::new();
    }
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let root = home.join("Library").join("Preferences");
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("plist") {
            continue;
        }
        if run_command_capture("plutil", &["-lint", path.to_string_lossy().as_ref()]).is_ok() {
            continue;
        }
        let label = path
            .file_stem()
            .and_then(|value| value.to_str())
            .map(humanize_identifier)
            .unwrap_or_else(|| "Broken Preference".to_string());
        targets.push(target_from_path(
            &label,
            "Invalid user preference plist",
            path,
            false,
            true,
        ));
    }
    targets.sort_by(|left, right| left.label.cmp(&right.label));
    targets
}

fn sqlite_database_targets() -> Vec<PerformanceTaskTarget> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    collect_sqlite_candidates(&home.join("Library").join("Safari"), &mut candidates, 1);
    collect_sqlite_candidates(&home.join("Library").join("Messages"), &mut candidates, 1);
    collect_sqlite_candidates(&home.join("Library").join("Mail"), &mut candidates, 4);

    let mut targets = Vec::new();
    for path in candidates {
        if path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|name| {
                name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal")
            })
            .unwrap_or(false)
        {
            continue;
        }
        if fs::metadata(&path)
            .map(|metadata| metadata.len() > SQLITE_MAX_VACUUM_BYTES)
            .unwrap_or(true)
        {
            continue;
        }
        if !looks_like_sqlite_database(&path) {
            continue;
        }
        let label = sqlite_target_label(&path);
        targets.push(target_from_path(
            &label,
            "SQLite database",
            path,
            false,
            false,
        ));
    }
    targets.sort_by(|left, right| left.label.cmp(&right.label));
    targets
}

fn dock_cache_targets() -> Vec<PerformanceTaskTarget> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let app_support = home
        .join("Library")
        .join("Application Support")
        .join("Dock");
    let mut targets = Vec::new();
    if let Ok(entries) = fs::read_dir(app_support) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("db") {
                targets.push(target_from_path(
                    "Dock icon cache",
                    "Dock cache database",
                    path,
                    false,
                    true,
                ));
            }
        }
    }
    targets
}

fn target_from_path(
    label: &str,
    description: &str,
    path: PathBuf,
    requires_admin: bool,
    selected_by_default: bool,
) -> PerformanceTaskTarget {
    PerformanceTaskTarget {
        id: stable_target_id(&path),
        label: label.to_string(),
        description: description.to_string(),
        path: Some(path.to_string_lossy().into_owned()),
        selected_by_default,
        requires_admin,
        risk: if requires_admin {
            PerformanceTaskRisk::Medium
        } else {
            PerformanceTaskRisk::Low
        },
    }
}

fn remove_selected_targets(
    detail: Option<&PerformanceTaskDetail>,
    selected_target_ids: &BTreeSet<String>,
    item_type: &str,
) -> Vec<String> {
    let Some(detail) = detail else {
        return vec![format!("failed: {item_type} detail is unavailable")];
    };
    if selected_target_ids.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for target in &detail.targets {
        if !selected_target_ids.contains(&target.id) {
            continue;
        }
        let Some(path) = target.path.as_deref().map(Path::new) else {
            lines.push(format!("skipped: {} has no path", target.label));
            continue;
        };
        if !path.exists() {
            lines.push(format!("skipped: {} no longer exists", target.label));
            continue;
        }
        match trash::delete(path) {
            Ok(()) => lines.push(format!("removed: {}", target.label)),
            Err(error) => lines.push(format!("failed: {} ({error})", target.label)),
        }
    }
    lines
}

#[derive(Debug, Default)]
struct LaunchPlistInfo {
    label: Option<String>,
    executable: Option<String>,
}

fn read_launch_plist_info(path: &Path) -> LaunchPlistInfo {
    let text = fs::read_to_string(path).ok();
    let label = text
        .as_deref()
        .and_then(|content| plist_string_value(content, "Label"))
        .or_else(|| plutil_extract(path, "Label"));
    let executable = text
        .as_deref()
        .and_then(|content| {
            plist_array_first_string(content, "ProgramArguments")
                .or_else(|| plist_string_value(content, "Program"))
        })
        .or_else(|| plutil_extract(path, "ProgramArguments.0"))
        .or_else(|| plutil_extract(path, "Program"));

    LaunchPlistInfo { label, executable }
}

fn read_desktop_entry_name(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    content.lines().find_map(|line| {
        line.strip_prefix("Name=")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn plist_string_value(content: &str, key: &str) -> Option<String> {
    let key_marker = format!("<key>{key}</key>");
    let after_key = content.split(&key_marker).nth(1)?;
    let start = after_key.find("<string>")? + "<string>".len();
    let end = after_key[start..].find("</string>")? + start;
    Some(unescape_plist_string(&after_key[start..end])).filter(|value| !value.trim().is_empty())
}

fn plist_array_first_string(content: &str, key: &str) -> Option<String> {
    let key_marker = format!("<key>{key}</key>");
    let after_key = content.split(&key_marker).nth(1)?;
    let array_start = after_key.find("<array>")? + "<array>".len();
    let array_end = after_key[array_start..].find("</array>")? + array_start;
    let array_content = &after_key[array_start..array_end];
    let start = array_content.find("<string>")? + "<string>".len();
    let end = array_content[start..].find("</string>")? + start;
    Some(unescape_plist_string(&array_content[start..end])).filter(|value| !value.trim().is_empty())
}

fn unescape_plist_string(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .trim()
        .to_string()
}

fn plutil_extract(path: &Path, key_path: &str) -> Option<String> {
    if std::env::consts::OS != "macos" {
        return None;
    }
    let output = ProcessCommand::new("plutil")
        .args(["-extract", key_path, "raw", "-o", "-"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn launch_item_description(
    root: &LoginItemRoot,
    launch_label: &str,
    executable: Option<&str>,
) -> String {
    let mut parts = vec![root.label.to_string(), format!("id: {launch_label}")];
    if let Some(executable) = executable
        .map(clean_launch_executable)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("target: {executable}"));
    }
    parts.join(" | ")
}

fn clean_launch_executable(value: &str) -> String {
    value
        .strip_prefix("file://")
        .unwrap_or(value)
        .trim_matches('"')
        .to_string()
}

fn human_launch_label(launch_label: &str, executable: Option<&str>) -> String {
    let normalized = launch_label.to_ascii_lowercase();
    for (prefix, label) in known_launch_labels() {
        if normalized == *prefix || normalized.starts_with(prefix) {
            return match launch_role_suffix(&normalized) {
                Some(suffix) if !label.eq_ignore_ascii_case(suffix) => {
                    format!("{label} {suffix}")
                }
                _ => label.to_string(),
            };
        }
    }

    let from_label = humanize_identifier(launch_label);
    if !from_label.eq_ignore_ascii_case("Helper")
        && !from_label.eq_ignore_ascii_case("Agent")
        && !from_label.eq_ignore_ascii_case("Service")
    {
        return from_label;
    }

    executable
        .and_then(|value| Path::new(value).file_stem())
        .and_then(|value| value.to_str())
        .map(humanize_identifier)
        .unwrap_or_else(|| "Login Item".to_string())
}

fn launch_role_suffix(normalized_label: &str) -> Option<&'static str> {
    let last = normalized_label
        .split(|ch: char| ch == '.' || ch == '_' || ch == '-')
        .filter(|part| !part.is_empty())
        .next_back()?;
    match last {
        "agent" => Some("Agent"),
        "daemon" => Some("Daemon"),
        "helper" => Some("Helper"),
        "service" => Some("Service"),
        "xpc" | "xpcservice" => Some("XPC Service"),
        "updater" | "update" => Some("Updater"),
        "wake" => Some("Wake"),
        "launcher" => Some("Launcher"),
        "login" | "loginitem" => Some("Login Item"),
        _ => None,
    }
}

fn known_launch_labels() -> &'static [(&'static str, &'static str)] {
    &[
        ("com.apple", "Apple"),
        ("com.google.googleupdater", "Google Updater"),
        ("com.google.keystone", "Google Keystone"),
        ("com.jetbrains.toolbox", "JetBrains Toolbox"),
        ("com.macpaw.cleanmymac", "CleanMyMac"),
        ("com.openai.atlas", "OpenAI Atlas"),
        ("org.mozilla.firefox", "Firefox"),
        ("com.microsoft", "Microsoft"),
        ("com.docker", "Docker"),
        ("com.spotify", "Spotify"),
        ("com.tinyspeck.slackmacgap", "Slack"),
        ("us.zoom", "Zoom"),
    ]
}

fn humanize_identifier(value: &str) -> String {
    let mut pieces = value
        .trim_end_matches(".plist")
        .split(|ch: char| ch == '.' || ch == '_' || ch == '-' || ch == ' ')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();

    let junk_prefixes = ["com", "org", "net", "io", "dev", "app", "homebrew", "mxcl"];
    while pieces
        .first()
        .map(|part| junk_prefixes.contains(&part.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
    {
        pieces.remove(0);
    }

    let junk_suffixes = [
        "agent",
        "daemon",
        "helper",
        "helpers",
        "service",
        "xpc",
        "xpcservice",
        "updater",
        "update",
        "wake",
        "launcher",
        "login",
        "loginitem",
        "installer",
        "uninstaller",
        "background",
    ];
    while pieces
        .last()
        .map(|part| junk_suffixes.contains(&part.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
    {
        pieces.pop();
    }

    if pieces.is_empty() {
        return "Login Item".to_string();
    }

    pieces
        .into_iter()
        .map(|piece| titleize_identifier_piece(&piece))
        .collect::<Vec<_>>()
        .join(" ")
}

fn titleize_identifier_piece(piece: &str) -> String {
    if piece
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        && piece.len() > 1
    {
        return piece.to_string();
    }
    let mut out = String::new();
    let mut previous_lower = false;
    for ch in piece.chars() {
        if ch.is_ascii_uppercase() && previous_lower {
            out.push(' ');
        }
        out.push(ch);
        previous_lower = ch.is_ascii_lowercase();
    }
    out.split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

struct LoginItemRoot {
    label: &'static str,
    path: PathBuf,
    requires_admin: bool,
}

fn login_item_roots() -> Vec<LoginItemRoot> {
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if std::env::consts::OS == "linux" {
            roots.push(LoginItemRoot {
                label: "User autostart entry",
                path: home.join(".config").join("autostart"),
                requires_admin: false,
            });
        } else {
            roots.push(LoginItemRoot {
                label: "User LaunchAgent",
                path: home.join("Library").join("LaunchAgents"),
                requires_admin: false,
            });
        }
    }
    if std::env::consts::OS == "macos" {
        roots.push(LoginItemRoot {
            label: "Global LaunchAgent",
            path: PathBuf::from("/Library/LaunchAgents"),
            requires_admin: true,
        });
        roots.push(LoginItemRoot {
            label: "System LaunchDaemon",
            path: PathBuf::from("/Library/LaunchDaemons"),
            requires_admin: true,
        });
    }
    roots
}

fn stable_target_id(path: &Path) -> String {
    stable_target_text(&path.to_string_lossy())
}

fn stable_target_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn is_user_launch_agent(path: &Path) -> bool {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return false;
    };
    path.starts_with(home.join("Library").join("LaunchAgents"))
}

fn is_user_autostart_entry(path: &Path) -> bool {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return false;
    };
    path.starts_with(home.join(".config").join("autostart"))
        && path.extension().and_then(|value| value.to_str()) == Some("desktop")
}

fn user_systemd_targets() -> Vec<PerformanceTaskTarget> {
    if std::env::consts::OS != "linux" {
        return Vec::new();
    }
    let output = run_command_capture(
        "systemctl",
        &[
            "--user",
            "list-unit-files",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ],
    )
    .unwrap_or_default();
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| unit.ends_with(".service") || unit.ends_with(".timer"))
        .map(|unit| PerformanceTaskTarget {
            id: format!("systemd_user__{unit}"),
            label: humanize_identifier(unit),
            description: format!("User systemd unit | id: {unit}"),
            path: None,
            selected_by_default: false,
            requires_admin: false,
            risk: PerformanceTaskRisk::Low,
        })
        .collect()
}

fn disable_user_systemd_unit(unit_id: &str) -> Vec<String> {
    let unit = unit_id;
    let mut lines = vec![format!("checking: disabling user unit {unit}")];
    lines.extend(run_command(
        "systemctl",
        &["--user", "disable", "--now", &unit],
    ));
    lines
}

fn bootout_launch_agent(path: &Path) -> Vec<String> {
    let uid = ProcessCommand::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(uid) = uid else {
        return vec!["warning: could not resolve uid for launchctl bootout".to_string()];
    };
    run_command(
        "launchctl",
        &["bootout", &format!("gui/{uid}"), &path.to_string_lossy()],
    )
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn path_is_older_than_days(path: &Path, days: u64) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|age| age >= Duration::from_secs(days * 24 * 60 * 60))
        .unwrap_or(false)
}

fn saved_state_label(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|name| {
            let stem = name
                .strip_suffix(".savedState")
                .unwrap_or(name)
                .strip_suffix(".savedstate")
                .unwrap_or(name);
            humanize_identifier(stem)
        })
        .unwrap_or_else(|| "Saved State".to_string())
}

fn collect_sqlite_candidates(root: &Path, out: &mut Vec<PathBuf>, max_depth: usize) {
    if max_depth == 0 || !root.exists() {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sqlite_candidates(&path, out, max_depth.saturating_sub(1));
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if name.ends_with(".db") || name.ends_with(".sqlite") || name.starts_with("Envelope Index")
        {
            out.push(path);
        }
    }
}

fn looks_like_sqlite_database(path: &Path) -> bool {
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut header = [0_u8; 16];
    file.read_exact(&mut header).is_ok() && header.starts_with(b"SQLite format 3")
}

fn sqlite_target_label(path: &Path) -> String {
    let text = path.to_string_lossy();
    let app = if text.contains("/Library/Mail/") {
        "Mail"
    } else if text.contains("/Library/Messages/") {
        "Messages"
    } else if text.contains("/Library/Safari/") {
        "Safari"
    } else {
        "App"
    };
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("database");
    format!("{app} {name}")
}

fn launch_services_register_path() -> Option<PathBuf> {
    [
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
        "/System/Library/CoreServices/CoreTypes.bundle/Contents/Library/lsregister",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
}

fn running_any(names: &[&str]) -> bool {
    names.iter().any(|name| process_is_running(name))
}

fn running_browser_name() -> Option<&'static str> {
    [
        "Safari",
        "Google Chrome",
        "Chromium",
        "Arc",
        "Firefox",
        "Brave Browser",
        "Microsoft Edge",
    ]
    .into_iter()
    .find(|name| process_is_running(name))
}

fn process_is_running(name: &str) -> bool {
    run_command_capture("pgrep", &["-x", name]).is_ok()
        || run_command_capture("pgrep", &["-f", name]).is_ok()
}

fn home_permissions_need_repair() -> bool {
    let Some(home) = home_dir() else {
        return false;
    };
    let probe = home.join(format!(".preen-permission-probe-{}", std::process::id()));
    if fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)
        .is_err()
    {
        return true;
    }
    let _ = fs::remove_file(probe);
    let uid = run_command_capture("id", &["-u"])
        .ok()
        .map(|value| value.trim().to_string());
    let owner = run_command_capture("stat", &["-f", "%u", home.to_string_lossy().as_ref()])
        .ok()
        .map(|value| value.trim().to_string());
    uid.is_some() && owner.is_some() && uid != owner
}

fn bluetooth_dependency_active() -> bool {
    let profile =
        run_command_capture("system_profiler", &["SPBluetoothDataType"]).unwrap_or_default();
    let lower = profile.to_ascii_lowercase();
    lower.contains("keyboard")
        || lower.contains("mouse")
        || lower.contains("trackpad")
        || lower.contains("headphones")
        || lower.contains("airpods")
}

fn spotlight_search_looks_slow() -> bool {
    let start = Instant::now();
    let _ = run_command_capture("mdfind", &["kMDItemFSName == 'Applications'"]);
    start.elapsed() > Duration::from_secs(2)
}

fn on_ac_power() -> bool {
    run_command_capture("pmset", &["-g", "batt"])
        .map(|output| output.to_ascii_lowercase().contains("ac power"))
        .unwrap_or(false)
}

fn run_command_capture(command: &str, args: &[&str]) -> Result<String, String> {
    let mut process = ProcessCommand::new(command);
    process
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let start = Instant::now();
    let mut child = process
        .spawn()
        .map_err(|error| format!("{command} ({error})"))?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|error| format!("{command} ({error})"))?;
                if status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
                }
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return Err(if stderr.is_empty() {
                    format!("{command} exited with {status}")
                } else {
                    stderr
                });
            }
            Ok(None) if start.elapsed() >= COMMAND_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{command} timed out"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(error) => return Err(format!("{command} ({error})")),
        }
    }
}

fn run_command(command: &str, args: &[&str]) -> Vec<String> {
    match run_command_via_action_runtime(command, args, ExecutionMode::Apply) {
        Ok(lines) => lines,
        Err(error) => vec![format!("failed: {command} ({error})")],
    }
}

fn run_command_via_action_runtime(
    command: &str,
    args: &[&str],
    mode: ExecutionMode,
) -> Result<Vec<String>, RuntimeExecutionError> {
    let (manifest, rule) = optimize_command_rule(command, args);
    let executor = crate::action_executor::OsActionExecutor;
    let policy = DefaultSafetyPolicy::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|error| {
            RuntimeExecutionError::Execute(ActionExecutionError::Failed {
                message: format!("runtime init failed: {error}"),
            })
        })?;
    let result = runtime.block_on(execute_action_with_audit(
        &manifest,
        &rule,
        mode,
        Some("performance-confirmed"),
        &policy,
        &executor,
        None,
    ))?;
    let mut lines = result
        .warnings
        .into_iter()
        .map(|warning| format!("warning: {warning}"))
        .collect::<Vec<_>>();
    if mode == ExecutionMode::DryRun {
        lines.push(format!("dry-run: {}", format_command(command, args)));
    } else {
        lines.push(format!("done: {command}"));
    }
    Ok(lines)
}

fn optimize_command_rule(command: &str, args: &[&str]) -> (Manifest, RuleFile) {
    let rule_id = format!(
        "performance-{}",
        stable_target_text(&format_command(command, args))
    );
    let mut params = std::collections::HashMap::new();
    params.insert("command_allowlist".to_string(), command.to_string());
    let action = ActionSpec {
        action_type: ActionType::RunCommand,
        paths: Vec::new(),
        command: std::iter::once(command.to_string())
            .chain(args.iter().map(|arg| (*arg).to_string()))
            .collect(),
        mode: Some(ActionMode::Confirm),
        timeout_sec: Some(COMMAND_TIMEOUT.as_secs()),
        allow_globs: false,
        max_items: Some(1),
        package_manager: None,
        project_types: Vec::new(),
        params,
    };
    let manifest = Manifest {
        schema_version: preen_core::plugin::MANIFEST_SCHEMA_V1,
        pack_id: "preen.performance".to_string(),
        name: "Preen Performance".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        description: "Built-in performance optimization actions".to_string(),
        author: "Preen".to_string(),
        license: "Proprietary".to_string(),
        homepage: None,
        core_compat: preen_core::plugin::RUNTIME_CORE_VERSION.to_string(),
        action_api: preen_core::plugin::SUPPORTED_ACTION_API,
        os_targets: vec![OsTarget::Macos, OsTarget::Linux],
        capabilities: vec![
            preen_core::plugin::Capability::SystemOptimize,
            preen_core::plugin::Capability::RunCommand,
        ],
        signing: None,
        rules: vec![RuleRef {
            id: rule_id.clone(),
            name: "Performance command".to_string(),
            rule_file: "builtin".to_string(),
        }],
    };
    let rule = RuleFile {
        schema_version: preen_core::plugin::RULE_SCHEMA_V1,
        id: rule_id,
        name: format!("Run {}", format_command(command, args)),
        category: preen_core::ItemCategory::Other("System optimization".to_string()),
        risk: RiskLevel::Medium,
        enabled: true,
        matcher: MatchSpec {
            mode: MatchMode::Command,
            paths: Vec::new(),
            strategy: None,
            command: Vec::new(),
            parser: None,
        },
        action,
    };
    (manifest, rule)
}

fn format_command(command: &str, args: &[&str]) -> String {
    std::iter::once(command)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_launch_label_prefers_known_app_names() {
        assert_eq!(
            human_launch_label("com.google.keystone.agent", None),
            "Google Keystone Agent"
        );
        assert_eq!(
            human_launch_label("com.google.keystone.xpcservice", None),
            "Google Keystone XPC Service"
        );
        assert_eq!(
            human_launch_label("com.macpaw.CleanMyMac5.Updater", None),
            "CleanMyMac Updater"
        );
        assert_eq!(
            human_launch_label("com.openai.atlas.update-helper", None),
            "OpenAI Atlas Helper"
        );
    }

    #[test]
    fn human_launch_label_falls_back_to_meaningful_bundle_segment() {
        assert_eq!(human_launch_label("homebrew.mxcl.mailpit", None), "Mailpit");
        assert_eq!(
            human_launch_label("com.example.cool-app.helper", None),
            "Example Cool App"
        );
    }

    #[test]
    fn launch_plist_xml_parser_reads_label_and_program_arguments() {
        let content = r#"
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.example.cool-app.helper</string>
            <key>ProgramArguments</key>
            <array>
                <string>/Applications/Cool App.app/Contents/MacOS/Cool App</string>
                <string>--background</string>
            </array>
        </dict>
        </plist>
        "#;

        assert_eq!(
            plist_string_value(content, "Label").as_deref(),
            Some("com.example.cool-app.helper")
        );
        assert_eq!(
            plist_array_first_string(content, "ProgramArguments").as_deref(),
            Some("/Applications/Cool App.app/Contents/MacOS/Cool App")
        );
    }
}
