use crate::model::{DashboardSnapshot, PluginActionKind};
use preen_core::app_uninstall::InstalledApplication;
use preen_core::dashboard_provider::DashboardProvider;
use preen_core::dashboard_service::DashboardApplicationService;
use preen_core::smart_care::{SmartCarePluginDescriptor, SmartCarePreview, SmartCareProfile};
use preen_os::dashboard::SnapshotCollector;
use preen_os::plugin_command::{PluginCommandOutput, run_plugin_cli_command};
use preen_os::smart_care::resolve_descriptors_with_report_from_state_dir;
use preen_os::smart_care_runtime::{
    analyze, execute_from_state_dir, undo_from_state_dir, undo_local_dry_run,
};
use preen_os::{app_inventory, app_uninstall};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Debug)]
pub enum WorkerEvent {
    Snapshot {
        snapshot: Box<DashboardSnapshot>,
        smart_care_descriptors: Vec<SmartCarePluginDescriptor>,
        smart_care_error: Option<String>,
        smart_care_source_summary: Option<String>,
        smart_care_skipped_pack_ids: Vec<String>,
        smart_care_dev_fallback_pack_ids: Vec<String>,
    },
    Error(String),
    PluginActionResult {
        action: PluginActionKind,
        ok: bool,
        lines: Vec<String>,
    },
    ApplicationsInventoryAnalyzeResult {
        applications: Vec<InstalledApplication>,
    },
    ApplicationsPathsInspectResult {
        app_name: String,
        paths: Vec<String>,
    },
    ApplicationsUninstallResult {
        lines: Vec<String>,
        removed_apps: Vec<String>,
    },
    ApplicationsUndoResult {
        lines: Vec<String>,
        restored_apps: Vec<String>,
    },
    SmartCareAnalyzeResult {
        preview: SmartCarePreview,
        lines: Vec<String>,
    },
    SmartCareRunResult {
        lines: Vec<String>,
    },
    SmartCareUndoResult {
        lines: Vec<String>,
    },
}

#[derive(Debug)]
pub enum WorkerCommand {
    RefreshNow,
    RunPluginAction {
        action: PluginActionKind,
        spec: Option<String>,
    },
    ApplicationsInventoryAnalyze,
    ApplicationsPathsInspect {
        application: InstalledApplication,
    },
    ApplicationsUninstall {
        applications: Vec<InstalledApplication>,
    },
    ApplicationsUndo,
    SmartCareAnalyze {
        profile: SmartCareProfile,
        descriptors: Vec<SmartCarePluginDescriptor>,
    },
    SmartCareRun {
        preview: SmartCarePreview,
        disabled_entry_ids: HashSet<String>,
        review_confirmed: bool,
        apply_confirmed: bool,
    },
    SmartCareUndo {
        has_last_run_report: bool,
    },
    Shutdown,
}

pub struct StatusWorker {
    command_tx: Sender<WorkerCommand>,
    join_handle: Option<JoinHandle<()>>,
}

type PluginCommandRunner =
    Arc<dyn Fn(PluginActionKind, Option<&str>) -> PluginCommandOutput + Send + Sync>;

impl StatusWorker {
    pub fn spawn(interval: Duration) -> (Self, Receiver<WorkerEvent>) {
        Self::spawn_with_provider(interval, Box::new(SnapshotCollector::new()))
    }

    pub fn spawn_with_provider(
        interval: Duration,
        provider: Box<dyn DashboardProvider>,
    ) -> (Self, Receiver<WorkerEvent>) {
        Self::spawn_with_provider_and_runner(interval, provider, Arc::new(run_plugin_cli_command))
    }

    pub(crate) fn spawn_with_provider_and_runner(
        interval: Duration,
        provider: Box<dyn DashboardProvider>,
        plugin_runner: PluginCommandRunner,
    ) -> (Self, Receiver<WorkerEvent>) {
        let (event_tx, event_rx) = mpsc::channel::<WorkerEvent>();
        let (command_tx, command_rx) = mpsc::channel::<WorkerCommand>();

        let join_handle = thread::spawn(move || {
            run_worker_loop(interval, command_rx, event_tx, provider, plugin_runner)
        });

        (
            Self {
                command_tx,
                join_handle: Some(join_handle),
            },
            event_rx,
        )
    }

    pub fn refresh_now(&self) {
        let _ = self.command_tx.send(WorkerCommand::RefreshNow);
    }

    pub fn run_plugin_action(&self, action: PluginActionKind, spec: Option<String>) {
        let _ = self
            .command_tx
            .send(WorkerCommand::RunPluginAction { action, spec });
    }

    pub fn run_applications_inventory_analyze(&self) {
        let _ = self
            .command_tx
            .send(WorkerCommand::ApplicationsInventoryAnalyze);
    }

    pub fn run_applications_paths_inspect(&self, application: InstalledApplication) {
        let _ = self
            .command_tx
            .send(WorkerCommand::ApplicationsPathsInspect { application });
    }

    pub fn run_applications_uninstall(&self, applications: Vec<InstalledApplication>) {
        let _ = self
            .command_tx
            .send(WorkerCommand::ApplicationsUninstall { applications });
    }

    pub fn run_applications_undo(&self) {
        let _ = self.command_tx.send(WorkerCommand::ApplicationsUndo);
    }

    pub fn run_smart_care_analyze(
        &self,
        profile: SmartCareProfile,
        descriptors: Vec<SmartCarePluginDescriptor>,
    ) {
        let _ = self.command_tx.send(WorkerCommand::SmartCareAnalyze {
            profile,
            descriptors,
        });
    }

    pub fn run_smart_care_execute(
        &self,
        preview: SmartCarePreview,
        disabled_entry_ids: HashSet<String>,
        review_confirmed: bool,
        apply_confirmed: bool,
    ) {
        let _ = self.command_tx.send(WorkerCommand::SmartCareRun {
            preview,
            disabled_entry_ids,
            review_confirmed,
            apply_confirmed,
        });
    }

    pub fn run_smart_care_undo(&self, has_last_run_report: bool) {
        let _ = self.command_tx.send(WorkerCommand::SmartCareUndo {
            has_last_run_report,
        });
    }

    pub fn shutdown(&mut self) {
        let _ = self.command_tx.send(WorkerCommand::Shutdown);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_worker_loop(
    interval: Duration,
    command_rx: Receiver<WorkerCommand>,
    event_tx: Sender<WorkerEvent>,
    provider: Box<dyn DashboardProvider>,
    plugin_runner: PluginCommandRunner,
) {
    let mut service = DashboardApplicationService::new(provider);
    let background_action_running = Arc::new(AtomicBool::new(false));
    let mut latest_state_dir: Option<PathBuf> = None;
    loop {
        match service.next_snapshot() {
            Ok(snapshot) => {
                latest_state_dir = Some(snapshot.state_dir.clone());
                let (
                    descriptors,
                    smart_care_error,
                    smart_care_source_summary,
                    smart_care_skipped_pack_ids,
                    smart_care_dev_fallback_pack_ids,
                ) = resolve_smart_care_descriptors(&snapshot);
                if event_tx
                    .send(WorkerEvent::Snapshot {
                        snapshot: Box::new(snapshot),
                        smart_care_descriptors: descriptors,
                        smart_care_error,
                        smart_care_source_summary,
                        smart_care_skipped_pack_ids,
                        smart_care_dev_fallback_pack_ids,
                    })
                    .is_err()
                {
                    break;
                }
            }
            Err(error) => {
                if event_tx
                    .send(WorkerEvent::Error(error.to_string()))
                    .is_err()
                {
                    break;
                }
            }
        }

        match command_rx.recv_timeout(interval) {
            Ok(WorkerCommand::RefreshNow) => continue,
            Ok(WorkerCommand::RunPluginAction { action, spec }) => {
                if background_action_running.swap(true, Ordering::SeqCst) {
                    if event_tx
                        .send(WorkerEvent::Error(
                            "background action already running".to_string(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let event_tx_for_plugin = event_tx.clone();
                let plugin_runner = Arc::clone(&plugin_runner);
                let background_action_running = Arc::clone(&background_action_running);
                thread::spawn(move || {
                    let output = plugin_runner(action, spec.as_deref());
                    background_action_running.store(false, Ordering::SeqCst);
                    let _ = event_tx_for_plugin.send(WorkerEvent::PluginActionResult {
                        action,
                        ok: output.ok,
                        lines: output.lines,
                    });
                });
                continue;
            }
            Ok(WorkerCommand::ApplicationsInventoryAnalyze) => {
                if background_action_running.swap(true, Ordering::SeqCst) {
                    if event_tx
                        .send(WorkerEvent::Error(
                            "background action already running".to_string(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let event_tx_for_action = event_tx.clone();
                let background_action_running = Arc::clone(&background_action_running);
                thread::spawn(move || {
                    let applications = app_inventory::collect_installed_applications();
                    background_action_running.store(false, Ordering::SeqCst);
                    let _ = event_tx_for_action
                        .send(WorkerEvent::ApplicationsInventoryAnalyzeResult { applications });
                });
                continue;
            }
            Ok(WorkerCommand::ApplicationsPathsInspect { application }) => {
                if background_action_running.swap(true, Ordering::SeqCst) {
                    if event_tx
                        .send(WorkerEvent::Error(
                            "background action already running".to_string(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let event_tx_for_action = event_tx.clone();
                let background_action_running = Arc::clone(&background_action_running);
                thread::spawn(move || {
                    let app_name = application.identity.display_name.clone();
                    let paths = app_uninstall::build_uninstall_plan_for_application(application)
                        .target_paths();
                    background_action_running.store(false, Ordering::SeqCst);
                    let _ = event_tx_for_action
                        .send(WorkerEvent::ApplicationsPathsInspectResult { app_name, paths });
                });
                continue;
            }
            Ok(WorkerCommand::ApplicationsUninstall { applications }) => {
                if background_action_running.swap(true, Ordering::SeqCst) {
                    if event_tx
                        .send(WorkerEvent::Error(
                            "background action already running".to_string(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let event_tx_for_action = event_tx.clone();
                let background_action_running = Arc::clone(&background_action_running);
                let state_dir = latest_state_dir.clone();
                thread::spawn(move || {
                    let output =
                        app_uninstall::execute_app_uninstall(applications, state_dir.as_deref());
                    background_action_running.store(false, Ordering::SeqCst);
                    match output {
                        Ok(output) => {
                            let _ = event_tx_for_action.send(
                                WorkerEvent::ApplicationsUninstallResult {
                                    lines: output.lines,
                                    removed_apps: output.removed_apps,
                                },
                            );
                        }
                        Err(error) => {
                            let _ = event_tx_for_action.send(WorkerEvent::Error(error));
                        }
                    }
                });
                continue;
            }
            Ok(WorkerCommand::ApplicationsUndo) => {
                if background_action_running.swap(true, Ordering::SeqCst) {
                    if event_tx
                        .send(WorkerEvent::Error(
                            "background action already running".to_string(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let event_tx_for_action = event_tx.clone();
                let background_action_running = Arc::clone(&background_action_running);
                let state_dir = latest_state_dir.clone();
                thread::spawn(move || {
                    let output = state_dir
                        .as_deref()
                        .ok_or_else(|| "state directory is unavailable".to_string())
                        .and_then(app_uninstall::undo_last_app_uninstall);
                    background_action_running.store(false, Ordering::SeqCst);
                    match output {
                        Ok(output) => {
                            let _ = event_tx_for_action.send(WorkerEvent::ApplicationsUndoResult {
                                lines: output.lines,
                                restored_apps: output.restored_apps,
                            });
                        }
                        Err(error) => {
                            let _ = event_tx_for_action.send(WorkerEvent::Error(error));
                        }
                    }
                });
                continue;
            }
            Ok(WorkerCommand::SmartCareAnalyze {
                profile,
                descriptors,
            }) => {
                if background_action_running.swap(true, Ordering::SeqCst) {
                    if event_tx
                        .send(WorkerEvent::Error(
                            "background action already running".to_string(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let event_tx_for_action = event_tx.clone();
                let background_action_running = Arc::clone(&background_action_running);
                let state_dir = latest_state_dir.clone();
                thread::spawn(move || {
                    let output = analyze(&profile, &descriptors, state_dir.as_deref());
                    background_action_running.store(false, Ordering::SeqCst);
                    let _ = event_tx_for_action.send(WorkerEvent::SmartCareAnalyzeResult {
                        preview: output.preview,
                        lines: output.lines,
                    });
                });
                continue;
            }
            Ok(WorkerCommand::SmartCareRun {
                preview,
                disabled_entry_ids,
                review_confirmed,
                apply_confirmed,
            }) => {
                if background_action_running.swap(true, Ordering::SeqCst) {
                    if event_tx
                        .send(WorkerEvent::Error(
                            "background action already running".to_string(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let event_tx_for_action = event_tx.clone();
                let background_action_running = Arc::clone(&background_action_running);
                let state_dir = latest_state_dir.clone();
                thread::spawn(move || {
                    let output = match state_dir {
                        Some(state_dir) => execute_from_state_dir(
                            &state_dir,
                            &preview,
                            &disabled_entry_ids,
                            review_confirmed,
                            apply_confirmed,
                        ),
                        None => preen_os::smart_care_runtime::SmartCareExecuteOutput {
                            lines: vec![
                                "run: failed".to_string(),
                                "reason: state directory is unavailable".to_string(),
                            ],
                        },
                    };
                    background_action_running.store(false, Ordering::SeqCst);
                    let _ = event_tx_for_action.send(WorkerEvent::SmartCareRunResult {
                        lines: output.lines,
                    });
                });
                continue;
            }
            Ok(WorkerCommand::SmartCareUndo {
                has_last_run_report,
            }) => {
                if background_action_running.swap(true, Ordering::SeqCst) {
                    if event_tx
                        .send(WorkerEvent::Error(
                            "background action already running".to_string(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let event_tx_for_action = event_tx.clone();
                let background_action_running = Arc::clone(&background_action_running);
                let state_dir = latest_state_dir.clone();
                thread::spawn(move || {
                    let output = match state_dir {
                        Some(state_dir) => undo_from_state_dir(&state_dir),
                        None => undo_local_dry_run(has_last_run_report),
                    };
                    background_action_running.store(false, Ordering::SeqCst);
                    let _ = event_tx_for_action.send(WorkerEvent::SmartCareUndoResult {
                        lines: output.lines,
                    });
                });
                continue;
            }
            Ok(WorkerCommand::Shutdown) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn resolve_smart_care_descriptors(
    snapshot: &DashboardSnapshot,
) -> (
    Vec<SmartCarePluginDescriptor>,
    Option<String>,
    Option<String>,
    Vec<String>,
    Vec<String>,
) {
    match resolve_descriptors_with_report_from_state_dir(snapshot.state_dir.as_path()) {
        Ok(report) => {
            let source_summary =
                if report.descriptors.is_empty() && report.skipped_plugins.is_empty() {
                    None
                } else {
                    Some(report.source_summary())
                };
            let resolver_warning = report.skipped_summary(3);
            (
                report.descriptors,
                resolver_warning,
                source_summary,
                report.skipped_plugins,
                report.dev_fallback_pack_ids,
            )
        }
        Err(error) => {
            if is_missing_lockfile_error(&error) {
                return (Vec::new(), None, None, Vec::new(), Vec::new());
            }
            (Vec::new(), Some(error), None, Vec::new(), Vec::new())
        }
    }
}

fn is_missing_lockfile_error(error: &str) -> bool {
    let lowered = error.to_ascii_lowercase();
    let read_error = lowered.contains("failed to read lockfile")
        || lowered.contains("failed to read plugin lockfile");
    let not_found = lowered.contains("no such file")
        || lowered.contains("os error 2")
        || lowered.contains("not found");
    read_error && not_found
}

#[cfg(test)]
mod tests {
    use super::*;
    use preen_core::dashboard::{
        DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
        DashboardSnapshot, RegistrySummary,
    };
    use preen_core::plugin_lock::{LockedPlugin, PluginLockfile};
    use preen_core::smart_care::SmartCareCapability;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Instant;

    struct TestProvider {
        seq: u8,
    }

    impl DashboardProvider for TestProvider {
        fn next_snapshot(&mut self) -> Result<DashboardSnapshot, String> {
            let score = self.seq;
            self.seq = self.seq.saturating_add(1);
            Ok(snapshot_with_health(score))
        }
    }

    struct FlakyProvider {
        first_call_failed: bool,
        next_score: u8,
    }

    impl DashboardProvider for FlakyProvider {
        fn next_snapshot(&mut self) -> Result<DashboardSnapshot, String> {
            if !self.first_call_failed {
                self.first_call_failed = true;
                return Err("transient snapshot failure".to_string());
            }
            let score = self.next_score;
            self.next_score = self.next_score.saturating_add(1);
            Ok(snapshot_with_health(score))
        }
    }

    struct FixedStateProvider {
        snapshot: DashboardSnapshot,
    }

    impl DashboardProvider for FixedStateProvider {
        fn next_snapshot(&mut self) -> Result<DashboardSnapshot, String> {
            Ok(self.snapshot.clone())
        }
    }

    fn snapshot_with_health(score: u8) -> DashboardSnapshot {
        DashboardSnapshot {
            schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
            contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
            collected_at: std::time::SystemTime::now().into(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            state_dir: PathBuf::from("/tmp/preen-state"),
            health_score: score,
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

    fn snapshot_with_health_and_state_dir(score: u8, state_dir: PathBuf) -> DashboardSnapshot {
        let mut snapshot = snapshot_with_health(score);
        snapshot.state_dir = state_dir;
        snapshot
    }

    fn create_temp_state_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!("preen-tui-{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn create_test_plugin_pack(state_dir: &Path, pack_id: &str) {
        let pack_dir = state_dir.join("plugins").join(pack_id);
        fs::create_dir_all(pack_dir.join("rules")).unwrap();
        fs::write(
            pack_dir.join("manifest.toml"),
            format!(
                r#"
schema_version = 1
pack_id = "{pack_id}"
name = "Test"
version = "1.0.0"
description = "Test plugin"
author = "Preen"
license = "MIT"
homepage = ""
core_compat = ">=0.1.0,<2.0.0"
action_api = 1
os_targets = ["Macos", "Linux"]
capabilities = ["FsRead"]

[[rules]]
id = "{pack_id}.rule"
name = "Rule"
rule_file = "rules/rule-1.toml"
"#
            ),
        )
        .unwrap();
        fs::write(
            pack_dir.join("rules/rule-1.toml"),
            format!(
                r#"
schema_version = 1
id = "{pack_id}.rule"
name = "Rule"
category = "Cache"
risk = "Low"
enabled = true

[match]
mode = "Paths"
paths = ["~/Library/Caches"]
strategy = "Recursive"
command = []
parser = ""

[action]
action_type = "TrashPaths"
paths = ["~/Library/Caches"]
command = []
mode = "Confirm"
timeout_sec = 30
allow_globs = false
max_items = 100
package_manager = ""
project_types = []
params = {{}}
"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn resolve_smart_care_descriptors_ignores_missing_lockfile_error() {
        let temp_path = create_temp_state_dir("missing-lockfile");
        let snapshot = snapshot_with_health_and_state_dir(80, temp_path.clone());
        let (descriptors, smart_care_error, source_summary, skipped_pack_ids, fallback_ids) =
            resolve_smart_care_descriptors(&snapshot);

        assert!(descriptors.is_empty());
        assert!(smart_care_error.is_none());
        assert!(source_summary.is_none());
        assert!(skipped_pack_ids.is_empty());
        assert!(fallback_ids.is_empty());
        let _ = fs::remove_dir_all(temp_path);
    }

    #[test]
    fn resolve_smart_care_descriptors_scans_plugins_dir_when_lockfile_is_missing() {
        let temp_path = create_temp_state_dir("plugins-scan-fallback");
        create_test_plugin_pack(&temp_path, "preen-rs.cleanup.base");

        let snapshot = snapshot_with_health_and_state_dir(82, temp_path.clone());
        let (descriptors, smart_care_error, source_summary, skipped_pack_ids, fallback_ids) =
            resolve_smart_care_descriptors(&snapshot);

        assert!(smart_care_error.is_none());
        assert_eq!(source_summary.as_deref(), Some("plugins-scan (packs=1)"));
        assert!(skipped_pack_ids.is_empty());
        assert!(fallback_ids.is_empty());
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].capability, SmartCareCapability::Cleanup);

        let _ = fs::remove_dir_all(temp_path);
    }

    #[test]
    fn resolve_smart_care_descriptors_keeps_parse_errors_visible() {
        let temp_path = create_temp_state_dir("invalid-lockfile");
        fs::write(temp_path.join("plugins.lock"), "invalid_toml = [").unwrap();
        let snapshot = snapshot_with_health_and_state_dir(81, temp_path.clone());
        let (_descriptors, smart_care_error, _source_summary, _skipped_pack_ids, _fallback_ids) =
            resolve_smart_care_descriptors(&snapshot);

        let error = smart_care_error.expect("parse error should be visible to UI");
        assert!(error.contains("failed to parse plugin lockfile"));
        let _ = fs::remove_dir_all(temp_path);
    }

    #[test]
    fn resolve_smart_care_descriptors_surfaces_skipped_pack_warning() {
        let temp_path = create_temp_state_dir("missing-pack-warning");
        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![LockedPlugin {
                pack_id: "preen-rs.cleanup.base".to_string(),
                source: "registry".to_string(),
                url: "https://example.com/preen-rs.cleanup.base".to_string(),
                rev: "0123456789abcdef0123456789abcdef01234567".to_string(),
                resolved_rev: None,
                version: "1.0.0".to_string(),
                manifest_hash: "sha256:abc".to_string(),
                signature: "sha256:def".to_string(),
                trusted_identity: "https://example.com/workflow".to_string(),
            }],
        };
        fs::write(
            temp_path.join("plugins.lock"),
            lockfile.to_string().expect("valid test lockfile"),
        )
        .unwrap();

        let snapshot = snapshot_with_health_and_state_dir(81, temp_path.clone());
        let (descriptors, smart_care_error, source_summary, skipped_pack_ids, fallback_ids) =
            resolve_smart_care_descriptors(&snapshot);

        assert!(descriptors.is_empty());
        assert_eq!(
            source_summary.as_deref(),
            Some("state-only (packs=0) | skipped=1")
        );
        assert_eq!(skipped_pack_ids, vec!["preen-rs.cleanup.base".to_string()]);
        assert_eq!(fallback_ids, Vec::<String>::new());
        let warning = smart_care_error.expect("skipped pack warning should be shown");
        assert!(
            warning.contains("skipped plugin packs: preen-rs.cleanup.base"),
            "unexpected warning: {warning}",
        );
        let _ = fs::remove_dir_all(temp_path);
    }

    #[test]
    fn snapshot_event_uses_plugins_scan_fallback_when_lockfile_is_missing() {
        let temp_path = create_temp_state_dir("snapshot-plugins-scan-fallback");
        create_test_plugin_pack(&temp_path, "preen-rs.cleanup.base");
        let provider = Box::new(FixedStateProvider {
            snapshot: snapshot_with_health_and_state_dir(84, temp_path.clone()),
        });
        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider(Duration::from_secs(60), provider);

        let event = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("snapshot event");

        let WorkerEvent::Snapshot {
            smart_care_descriptors,
            smart_care_error,
            smart_care_source_summary,
            smart_care_skipped_pack_ids,
            smart_care_dev_fallback_pack_ids,
            ..
        } = event
        else {
            panic!("expected snapshot event");
        };

        assert!(smart_care_error.is_none());
        assert_eq!(
            smart_care_source_summary.as_deref(),
            Some("plugins-scan (packs=1)")
        );
        assert!(smart_care_skipped_pack_ids.is_empty());
        assert!(smart_care_dev_fallback_pack_ids.is_empty());
        assert_eq!(smart_care_descriptors.len(), 1);
        assert_eq!(
            smart_care_descriptors[0].capability,
            SmartCareCapability::Cleanup
        );

        worker.shutdown();
        let _ = fs::remove_dir_all(temp_path);
    }

    #[test]
    fn refresh_now_emits_next_snapshot_immediately() {
        let provider = Box::new(TestProvider { seq: 42 });
        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider(Duration::from_secs(60), provider);

        let first = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first event");
        let WorkerEvent::Snapshot {
            snapshot: first_snapshot,
            ..
        } = first
        else {
            panic!("expected first snapshot event");
        };
        assert_eq!(first_snapshot.health_score, 42);

        let start = Instant::now();
        worker.refresh_now();
        let second = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("second event");
        let WorkerEvent::Snapshot {
            snapshot: second_snapshot,
            ..
        } = second
        else {
            panic!("expected refreshed snapshot event");
        };
        assert_eq!(second_snapshot.health_score, 43);
        assert!(start.elapsed() < Duration::from_secs(2));

        worker.shutdown();
    }

    #[test]
    fn plugin_action_uses_injected_runner() {
        let provider = Box::new(TestProvider { seq: 1 });
        let captured = Arc::new(Mutex::new(Vec::<(PluginActionKind, Option<String>)>::new()));
        let captured_for_runner = Arc::clone(&captured);
        let runner: PluginCommandRunner = Arc::new(move |action, spec| {
            captured_for_runner
                .lock()
                .expect("lock captured runner calls")
                .push((action, spec.map(ToString::to_string)));
            PluginCommandOutput {
                ok: true,
                lines: vec!["ok".to_string()],
            }
        });

        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider_and_runner(Duration::from_secs(60), provider, runner);
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");

        worker.run_plugin_action(
            PluginActionKind::Info,
            Some("preen-rs.homebrew@1.0.7".to_string()),
        );

        let started = Instant::now();
        let event = loop {
            assert!(started.elapsed() < Duration::from_secs(2));
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(WorkerEvent::PluginActionResult { action, ok, lines }) => {
                    break (action, ok, lines);
                }
                Ok(WorkerEvent::ApplicationsInventoryAnalyzeResult { .. })
                | Ok(WorkerEvent::ApplicationsPathsInspectResult { .. })
                | Ok(WorkerEvent::ApplicationsUninstallResult { .. })
                | Ok(WorkerEvent::ApplicationsUndoResult { .. })
                | Ok(WorkerEvent::SmartCareAnalyzeResult { .. })
                | Ok(WorkerEvent::SmartCareRunResult { .. })
                | Ok(WorkerEvent::SmartCareUndoResult { .. }) => {}
                Ok(WorkerEvent::Snapshot { .. }) => {}
                Ok(WorkerEvent::Error(error)) => panic!("unexpected worker error: {error}"),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => panic!("worker disconnected"),
            }
        };
        let (action, ok, lines) = event;
        assert_eq!(action, PluginActionKind::Info);
        assert!(ok);
        assert_eq!(lines, vec!["ok".to_string()]);

        let calls = captured.lock().expect("lock captured calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, PluginActionKind::Info);
        assert_eq!(calls[0].1.as_deref(), Some("preen-rs.homebrew@1.0.7"));

        worker.shutdown();
    }

    #[test]
    fn shutdown_stops_event_stream() {
        let provider = Box::new(TestProvider { seq: 10 });
        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider(Duration::from_millis(100), provider);
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");
        worker.shutdown();
        match event_rx.recv_timeout(Duration::from_millis(300)) {
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {}
            Ok(_) => panic!("unexpected event after shutdown"),
        }
    }

    #[test]
    fn worker_recovers_after_transient_snapshot_error() {
        let provider = Box::new(FlakyProvider {
            first_call_failed: false,
            next_score: 80,
        });
        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider(Duration::from_secs(60), provider);

        let first = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first worker event");
        let WorkerEvent::Error(error) = first else {
            panic!("expected initial transient error");
        };
        assert!(error.contains("transient snapshot failure"));

        worker.refresh_now();

        let second = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("recovered snapshot event");
        let WorkerEvent::Snapshot { snapshot, .. } = second else {
            panic!("expected recovered snapshot event");
        };
        assert_eq!(snapshot.health_score, 80);

        worker.shutdown();
    }

    #[test]
    fn plugin_action_runs_async_without_blocking_snapshot_updates() {
        let provider = Box::new(TestProvider { seq: 1 });
        let runner: PluginCommandRunner = Arc::new(|_, _| {
            std::thread::sleep(Duration::from_millis(300));
            PluginCommandOutput {
                ok: true,
                lines: vec!["done".to_string()],
            }
        });

        let (mut worker, event_rx) = StatusWorker::spawn_with_provider_and_runner(
            Duration::from_millis(50),
            provider,
            runner,
        );
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");
        worker.run_plugin_action(
            PluginActionKind::Test,
            Some("preen-rs.homebrew@1.0.7".to_string()),
        );

        let mut saw_snapshot_before_result = false;
        let mut saw_plugin_result = false;
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(WorkerEvent::Snapshot { .. }) => {
                    if !saw_plugin_result {
                        saw_snapshot_before_result = true;
                    }
                }
                Ok(WorkerEvent::PluginActionResult { .. }) => {
                    saw_plugin_result = true;
                    break;
                }
                Ok(WorkerEvent::ApplicationsInventoryAnalyzeResult { .. })
                | Ok(WorkerEvent::ApplicationsPathsInspectResult { .. })
                | Ok(WorkerEvent::ApplicationsUninstallResult { .. })
                | Ok(WorkerEvent::ApplicationsUndoResult { .. })
                | Ok(WorkerEvent::SmartCareAnalyzeResult { .. })
                | Ok(WorkerEvent::SmartCareRunResult { .. })
                | Ok(WorkerEvent::SmartCareUndoResult { .. }) => {}
                Ok(WorkerEvent::Error(error)) => panic!("unexpected worker error: {error}"),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        assert!(saw_snapshot_before_result);
        assert!(saw_plugin_result);
        worker.shutdown();
    }

    #[test]
    fn worker_rejects_concurrent_plugin_actions() {
        let provider = Box::new(TestProvider { seq: 1 });
        let runner: PluginCommandRunner = Arc::new(|_, _| {
            std::thread::sleep(Duration::from_millis(350));
            PluginCommandOutput {
                ok: true,
                lines: vec!["done".to_string()],
            }
        });

        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider_and_runner(Duration::from_secs(60), provider, runner);
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");

        let spec = Some("preen-rs.homebrew@1.0.7".to_string());
        worker.run_plugin_action(PluginActionKind::Preflight, spec.clone());
        worker.run_plugin_action(PluginActionKind::Install, spec);

        let mut saw_busy_error = false;
        let mut saw_any_result = false;
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            match event_rx.recv_timeout(Duration::from_millis(300)) {
                Ok(WorkerEvent::Error(error)) => {
                    if error.contains("already running") {
                        saw_busy_error = true;
                    }
                }
                Ok(WorkerEvent::PluginActionResult { .. }) => {
                    saw_any_result = true;
                    if saw_busy_error {
                        break;
                    }
                }
                Ok(WorkerEvent::ApplicationsInventoryAnalyzeResult { .. })
                | Ok(WorkerEvent::ApplicationsPathsInspectResult { .. })
                | Ok(WorkerEvent::ApplicationsUninstallResult { .. })
                | Ok(WorkerEvent::ApplicationsUndoResult { .. })
                | Ok(WorkerEvent::SmartCareAnalyzeResult { .. })
                | Ok(WorkerEvent::SmartCareRunResult { .. })
                | Ok(WorkerEvent::SmartCareUndoResult { .. }) => {}
                Ok(WorkerEvent::Snapshot { .. }) => {}
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        assert!(saw_busy_error);
        assert!(saw_any_result);
        worker.shutdown();
    }

    #[test]
    fn smart_care_analyze_command_emits_result_event() {
        let provider = Box::new(TestProvider { seq: 1 });
        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider(Duration::from_secs(60), provider);
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");

        worker.run_smart_care_analyze(
            preen_core::smart_care::SmartCareProfile::default_profile(),
            Vec::new(),
        );

        let started = Instant::now();
        let mut saw_result = false;
        while started.elapsed() < Duration::from_secs(2) {
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(WorkerEvent::SmartCareAnalyzeResult { preview, lines }) => {
                    assert!(!preview.overall_ready);
                    assert!(lines.iter().any(|line| line == "overall: blocked"));
                    saw_result = true;
                    break;
                }
                Ok(WorkerEvent::Snapshot { .. })
                | Ok(WorkerEvent::ApplicationsInventoryAnalyzeResult { .. })
                | Ok(WorkerEvent::ApplicationsPathsInspectResult { .. })
                | Ok(WorkerEvent::ApplicationsUninstallResult { .. })
                | Ok(WorkerEvent::ApplicationsUndoResult { .. })
                | Ok(WorkerEvent::PluginActionResult { .. })
                | Ok(WorkerEvent::SmartCareRunResult { .. })
                | Ok(WorkerEvent::SmartCareUndoResult { .. }) => {}
                Ok(WorkerEvent::Error(error)) => panic!("unexpected worker error: {error}"),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        assert!(saw_result);
        worker.shutdown();
    }

    #[test]
    fn smart_care_run_and_undo_emit_result_events() {
        let provider = Box::new(TestProvider { seq: 1 });
        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider(Duration::from_secs(60), provider);
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");

        let analyze_output = preen_os::smart_care_runtime::analyze(
            &preen_core::smart_care::SmartCareProfile::default_profile(),
            &[],
            None,
        );
        worker.run_smart_care_execute(analyze_output.preview, HashSet::new(), false, false);

        let started = Instant::now();
        let mut saw_run = false;
        let mut saw_undo = false;
        while started.elapsed() < Duration::from_secs(3) {
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(WorkerEvent::SmartCareRunResult { lines }) => {
                    assert!(
                        lines
                            .iter()
                            .any(|line| line == "reason: review is required before run")
                    );
                    saw_run = true;
                    worker.run_smart_care_undo(false);
                }
                Ok(WorkerEvent::SmartCareUndoResult { lines }) => {
                    assert!(lines.iter().any(|line| line == "undo: skipped"));
                    saw_undo = true;
                }
                Ok(WorkerEvent::Snapshot { .. })
                | Ok(WorkerEvent::ApplicationsInventoryAnalyzeResult { .. })
                | Ok(WorkerEvent::ApplicationsPathsInspectResult { .. })
                | Ok(WorkerEvent::ApplicationsUninstallResult { .. })
                | Ok(WorkerEvent::ApplicationsUndoResult { .. })
                | Ok(WorkerEvent::PluginActionResult { .. })
                | Ok(WorkerEvent::SmartCareAnalyzeResult { .. }) => {}
                Ok(WorkerEvent::Error(error)) => panic!("unexpected worker error: {error}"),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if saw_run && saw_undo {
                break;
            }
        }

        assert!(saw_run);
        assert!(saw_undo);
        worker.shutdown();
    }
}
