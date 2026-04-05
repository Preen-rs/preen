use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, MutexGuard, OnceLock};

use preen_core::action_runtime::{
    ActionExecutionError, ActionExecutorPort, ActionRisk, ExecutionMode, ExecutionPlan,
    ExecutionRequest,
};
use preen_core::plugin::{ActionSpec, ActionType};
use preen_os::action_executor::OsActionExecutor;

fn env_lock() -> MutexGuard<'static, ()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: callers ensure serialized env mutation with ENV_LOCK.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }

    fn clear(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: callers ensure serialized env mutation with ENV_LOCK.
        unsafe {
            std::env::remove_var(key);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => {
                // SAFETY: callers ensure serialized env mutation with ENV_LOCK.
                unsafe {
                    std::env::set_var(self.key, value);
                }
            }
            None => {
                // SAFETY: callers ensure serialized env mutation with ENV_LOCK.
                unsafe {
                    std::env::remove_var(self.key);
                }
            }
        }
    }
}

fn sample_plan(action_type: ActionType, mode: ExecutionMode, paths: Vec<String>) -> ExecutionPlan {
    sample_plan_with(
        action_type,
        mode,
        paths,
        Vec::new(),
        HashMap::new(),
        Some(30),
    )
}

fn sample_plan_with(
    action_type: ActionType,
    mode: ExecutionMode,
    paths: Vec<String>,
    command: Vec<String>,
    params: HashMap<String, String>,
    timeout_sec: Option<u64>,
) -> ExecutionPlan {
    ExecutionPlan {
        request: ExecutionRequest {
            pack_id: "preen-rs.test".to_string(),
            rule_id: "rule-1".to_string(),
            action: ActionSpec {
                action_type,
                paths,
                command,
                mode: None,
                timeout_sec,
                allow_globs: false,
                max_items: Some(100),
                package_manager: None,
                project_types: Vec::new(),
                params,
            },
            risk: ActionRisk::Low,
            mode,
        },
        requires_confirmation: false,
    }
}

#[tokio::test]
async fn dry_run_does_not_delete_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("cache.txt");
    fs::write(&target, b"hello").unwrap();
    let plan = sample_plan(
        ActionType::DeletePaths,
        ExecutionMode::DryRun,
        vec![target.to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert!(out.freed_bytes > 0);
    assert!(target.exists());
}

#[tokio::test]
async fn apply_deletepaths_removes_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("cache.txt");
    fs::write(&target, b"hello").unwrap();
    let plan = sample_plan(
        ActionType::DeletePaths,
        ExecutionMode::Apply,
        vec![target.to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert!(out.freed_bytes > 0);
    assert!(!target.exists());
}

#[tokio::test]
async fn unsupported_action_returns_error() {
    let plan = sample_plan(
        ActionType::Other("custom_action".to_string()),
        ExecutionMode::DryRun,
        vec![],
    );
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(
        err,
        ActionExecutionError::UnsupportedAction { .. }
    ));
}

#[tokio::test]
async fn app_uninstall_apply_deletes_target_paths() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("Demo.app");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("Info.plist"), b"demo").unwrap();
    let plan = sample_plan(
        ActionType::AppUninstall,
        ExecutionMode::Apply,
        vec![app.to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert!(out.freed_bytes > 0);
    assert!(out.warnings.is_empty());
    assert!(!app.exists());
}

#[tokio::test]
async fn app_uninstall_requires_paths_or_command() {
    let plan = sample_plan(ActionType::AppUninstall, ExecutionMode::DryRun, vec![]);
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::Failed { .. }));
    assert!(err.to_string().contains("requires paths or command"));
}

#[tokio::test]
async fn remove_orphans_apply_deletes_target_paths() {
    let dir = tempfile::tempdir().unwrap();
    let orphan = dir.path().join("orphan.cache");
    fs::write(&orphan, b"x").unwrap();
    let plan = sample_plan(
        ActionType::RemoveOrphans,
        ExecutionMode::Apply,
        vec![orphan.to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert!(out.freed_bytes > 0);
    assert!(out.warnings.is_empty());
    assert!(!orphan.exists());
}

#[tokio::test]
async fn optimize_system_runs_allowlisted_command() {
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "echo".to_string());
    let plan = sample_plan_with(
        ActionType::OptimizeSystem,
        ExecutionMode::Apply,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        params,
        Some(5),
    );
    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert_eq!(out.freed_bytes, 0);
}

#[tokio::test]
async fn optimize_system_requires_command() {
    let plan = sample_plan(ActionType::OptimizeSystem, ExecutionMode::Apply, vec![]);
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::Failed { .. }));
    assert!(err.to_string().contains("requires command"));
}

#[tokio::test]
async fn find_installers_dry_run_matches_known_extensions() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("app.pkg"), b"x").unwrap();
    fs::write(dir.path().join("archive.zip"), b"x").unwrap();
    fs::write(dir.path().join("notes.txt"), b"x").unwrap();
    let plan = sample_plan(
        ActionType::FindInstallers,
        ExecutionMode::DryRun,
        vec![dir.path().to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert!(out.freed_bytes > 0);
    assert!(out.warnings.is_empty());
    assert!(dir.path().join("app.pkg").exists());
    assert!(dir.path().join("archive.zip").exists());
    assert!(dir.path().join("notes.txt").exists());
}

#[tokio::test]
async fn find_installers_apply_deletes_only_matching_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let dmg = dir.path().join("setup.dmg");
    let txt = dir.path().join("readme.txt");
    fs::write(&dmg, b"x").unwrap();
    fs::write(&txt, b"x").unwrap();
    let plan = sample_plan(
        ActionType::FindInstallers,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert!(out.freed_bytes > 0);
    assert!(!dmg.exists());
    assert!(txt.exists());
}

#[tokio::test]
async fn project_cleanup_dry_run_matches_common_artifact_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    fs::create_dir_all(project.join("node_modules")).unwrap();
    fs::create_dir_all(project.join("target")).unwrap();
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(project.join("node_modules").join("pkg.json"), b"x").unwrap();
    fs::write(project.join("target").join("bin"), b"x").unwrap();
    let plan = sample_plan(
        ActionType::ProjectCleanup,
        ExecutionMode::DryRun,
        vec![project.to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert!(out.freed_bytes > 0);
    assert!(out.warnings.is_empty());
    assert!(project.join("node_modules").exists());
    assert!(project.join("target").exists());
    assert!(project.join("src").exists());
}

#[tokio::test]
async fn project_cleanup_apply_deletes_only_artifact_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    fs::create_dir_all(project.join("node_modules")).unwrap();
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(project.join("node_modules").join("pkg.json"), b"x").unwrap();
    fs::write(project.join("src").join("main.rs"), b"x").unwrap();
    let plan = sample_plan(
        ActionType::ProjectCleanup,
        ExecutionMode::Apply,
        vec![project.to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert!(out.freed_bytes > 0);
    assert!(!project.join("node_modules").exists());
    assert!(project.join("src").exists());
}

#[tokio::test]
async fn disk_usage_snapshot_reports_file_count_and_size() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.bin"), vec![1_u8; 8]).unwrap();
    fs::create_dir_all(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested").join("b.bin"), vec![1_u8; 4]).unwrap();
    let plan = sample_plan(
        ActionType::DiskUsageSnapshot,
        ExecutionMode::DryRun,
        vec![dir.path().to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert!(out.freed_bytes >= 12);
    assert!(out.warnings.is_empty());
}

#[tokio::test]
async fn system_status_is_noop_success() {
    let plan = sample_plan(ActionType::SystemStatus, ExecutionMode::DryRun, vec![]);
    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 0);
    assert_eq!(out.freed_bytes, 0);
    assert!(out.warnings.is_empty());
}

#[tokio::test]
async fn system_status_reports_file_count_and_size() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.bin"), vec![1_u8; 8]).unwrap();
    fs::create_dir_all(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested").join("b.bin"), vec![1_u8; 4]).unwrap();
    let plan = sample_plan(
        ActionType::SystemStatus,
        ExecutionMode::DryRun,
        vec![dir.path().to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert!(out.freed_bytes >= 12);
    assert!(out.warnings.is_empty());
}

#[tokio::test]
async fn system_status_apply_is_read_only() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("x.dat"), vec![1_u8; 3]).unwrap();
    fs::write(dir.path().join("y.dat"), vec![1_u8; 5]).unwrap();
    let plan = sample_plan(
        ActionType::SystemStatus,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert!(out.freed_bytes >= 8);
    assert!(out.warnings.is_empty());
    assert!(dir.path().join("x.dat").exists());
    assert!(dir.path().join("y.dat").exists());
}

#[tokio::test]
async fn system_status_reports_missing_path_and_truncation_warnings() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.bin"), vec![1_u8; 4]).unwrap();
    fs::write(dir.path().join("b.bin"), vec![1_u8; 3]).unwrap();
    fs::write(dir.path().join("c.bin"), vec![1_u8; 2]).unwrap();
    let missing = dir.path().join("missing");
    let mut plan = sample_plan_with(
        ActionType::SystemStatus,
        ExecutionMode::DryRun,
        vec![
            missing.to_string_lossy().to_string(),
            dir.path().to_string_lossy().to_string(),
        ],
        Vec::new(),
        HashMap::new(),
        Some(30),
    );
    plan.request.action.max_items = Some(2);

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert!(out.freed_bytes >= 9);
    assert_eq!(out.warnings.len(), 2);
    assert!(out.warnings[0].contains("path not found"));
    assert!(out.warnings[1].contains("truncated at max_items=2"));
}

#[tokio::test]
async fn scan_paths_counts_files_without_modifying_targets() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    fs::write(dir.path().join("nested").join("b.txt"), b"b").unwrap();

    let plan = sample_plan(
        ActionType::ScanPaths,
        ExecutionMode::DryRun,
        vec![dir.path().to_string_lossy().to_string()],
    );
    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert_eq!(out.freed_bytes, 0);
    assert!(out.warnings.is_empty());
    assert!(dir.path().join("a.txt").exists());
    assert!(dir.path().join("nested").join("b.txt").exists());
}

#[tokio::test]
async fn scan_paths_respects_max_items_and_reports_truncation() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    fs::write(dir.path().join("b.txt"), b"b").unwrap();
    fs::write(dir.path().join("c.txt"), b"c").unwrap();
    let plan = sample_plan_with(
        ActionType::ScanPaths,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
        Vec::new(),
        HashMap::new(),
        Some(10),
    );
    let mut limited = plan.clone();
    limited.request.action.max_items = Some(2);

    let out = OsActionExecutor.execute(&limited).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert_eq!(out.freed_bytes, 0);
    assert_eq!(out.warnings.len(), 1);
    assert!(out.warnings[0].contains("truncated"));
    assert!(dir.path().join("a.txt").exists());
    assert!(dir.path().join("b.txt").exists());
    assert!(dir.path().join("c.txt").exists());
}

#[tokio::test]
async fn match_regex_counts_only_matching_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("keep.log"), b"a").unwrap();
    fs::write(dir.path().join("skip.tmp"), b"b").unwrap();
    let mut params = HashMap::new();
    params.insert("pattern".to_string(), r"\.log$".to_string());
    let plan = sample_plan_with(
        ActionType::MatchRegex,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
        Vec::new(),
        params,
        Some(10),
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert_eq!(out.freed_bytes, 0);
    assert!(out.warnings.is_empty());
}

#[tokio::test]
async fn match_regex_respects_max_items_and_reports_truncation() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.log"), b"a").unwrap();
    fs::write(dir.path().join("b.log"), b"b").unwrap();
    fs::write(dir.path().join("c.log"), b"c").unwrap();
    let mut params = HashMap::new();
    params.insert("pattern".to_string(), r"\.log$".to_string());
    let mut plan = sample_plan_with(
        ActionType::MatchRegex,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
        Vec::new(),
        params,
        Some(10),
    );
    plan.request.action.max_items = Some(2);

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert_eq!(out.freed_bytes, 0);
    assert_eq!(out.warnings.len(), 1);
    assert!(out.warnings[0].contains("truncated"));
}

#[tokio::test]
async fn match_regex_requires_pattern_param() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.log"), b"a").unwrap();
    let plan = sample_plan_with(
        ActionType::MatchRegex,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
        Vec::new(),
        HashMap::new(),
        Some(10),
    );
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::Failed { .. }));
    assert!(err.to_string().contains("requires params.pattern"));
}

#[tokio::test]
async fn match_regex_rejects_invalid_pattern() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.log"), b"a").unwrap();
    let mut params = HashMap::new();
    params.insert("pattern".to_string(), "(".to_string());
    let plan = sample_plan_with(
        ActionType::MatchRegex,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
        Vec::new(),
        params,
        Some(10),
    );
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::Failed { .. }));
    assert!(err.to_string().contains("invalid pattern"));
}

#[tokio::test]
async fn older_than_days_days_zero_counts_all_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    fs::write(dir.path().join("b.txt"), b"b").unwrap();
    let mut params = HashMap::new();
    params.insert("days".to_string(), "0".to_string());
    let plan = sample_plan_with(
        ActionType::OlderThanDays,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
        Vec::new(),
        params,
        Some(10),
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert_eq!(out.freed_bytes, 0);
    assert!(out.warnings.is_empty());
}

#[tokio::test]
async fn older_than_days_large_days_matches_none() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    fs::write(dir.path().join("b.txt"), b"b").unwrap();
    let mut params = HashMap::new();
    params.insert("days".to_string(), "10000".to_string());
    let plan = sample_plan_with(
        ActionType::OlderThanDays,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
        Vec::new(),
        params,
        Some(10),
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 0);
    assert_eq!(out.freed_bytes, 0);
    assert!(out.warnings.is_empty());
}

#[tokio::test]
async fn older_than_days_requires_days_param() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    let plan = sample_plan_with(
        ActionType::OlderThanDays,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
        Vec::new(),
        HashMap::new(),
        Some(10),
    );
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::Failed { .. }));
    assert!(err.to_string().contains("requires params.days"));
}

#[tokio::test]
async fn older_than_days_rejects_invalid_days_param() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    let mut params = HashMap::new();
    params.insert("days".to_string(), "abc".to_string());
    let plan = sample_plan_with(
        ActionType::OlderThanDays,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
        Vec::new(),
        params,
        Some(10),
    );
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::Failed { .. }));
    assert!(err.to_string().contains("invalid days value"));
}

#[tokio::test]
async fn prune_empty_dirs_dry_run_counts_without_removal() {
    let dir = tempfile::tempdir().unwrap();
    let empty_chain = dir.path().join("empty").join("nested");
    fs::create_dir_all(&empty_chain).unwrap();
    let non_empty = dir.path().join("keep");
    fs::create_dir_all(&non_empty).unwrap();
    fs::write(non_empty.join("file.txt"), b"x").unwrap();

    let plan = sample_plan(
        ActionType::PruneEmptyDirs,
        ExecutionMode::DryRun,
        vec![dir.path().to_string_lossy().to_string()],
    );
    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert_eq!(out.freed_bytes, 0);
    assert!(out.warnings.is_empty());
    assert!(empty_chain.exists());
    assert!(non_empty.exists());
}

#[tokio::test]
async fn prune_empty_dirs_apply_removes_only_empty_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let empty_chain = dir.path().join("empty").join("nested");
    fs::create_dir_all(&empty_chain).unwrap();
    let non_empty = dir.path().join("keep");
    fs::create_dir_all(&non_empty).unwrap();
    fs::write(non_empty.join("file.txt"), b"x").unwrap();

    let plan = sample_plan(
        ActionType::PruneEmptyDirs,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
    );
    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert_eq!(out.freed_bytes, 0);
    assert!(out.warnings.is_empty());
    assert!(!empty_chain.exists());
    assert!(non_empty.exists());
}

#[tokio::test]
async fn prune_empty_dirs_respects_max_items_and_reports_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let empty_chain = dir.path().join("a").join("b").join("c");
    fs::create_dir_all(&empty_chain).unwrap();
    let mut plan = sample_plan(
        ActionType::PruneEmptyDirs,
        ExecutionMode::Apply,
        vec![dir.path().to_string_lossy().to_string()],
    );
    plan.request.action.max_items = Some(2);

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 2);
    assert_eq!(out.freed_bytes, 0);
    assert_eq!(out.warnings.len(), 1);
    assert!(out.warnings[0].contains("truncated"));
    assert!(!dir.path().join("a").join("b").join("c").exists());
    assert!(!dir.path().join("a").join("b").exists());
    assert!(dir.path().join("a").exists());
}

#[tokio::test]
async fn prune_empty_dirs_warns_for_non_directory_target() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file.txt");
    fs::write(&file, b"x").unwrap();
    let plan = sample_plan(
        ActionType::PruneEmptyDirs,
        ExecutionMode::Apply,
        vec![file.to_string_lossy().to_string()],
    );
    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 0);
    assert_eq!(out.freed_bytes, 0);
    assert_eq!(out.warnings.len(), 1);
    assert!(out.warnings[0].contains("not directory"));
    assert!(file.exists());
}

#[tokio::test]
async fn run_command_dry_run_reports_warning() {
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "echo".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::DryRun,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        params,
        Some(5),
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert_eq!(out.freed_bytes, 0);
    assert_eq!(out.warnings.len(), 1);
    assert!(out.warnings[0].contains("dry-run skipped command"));
}

#[tokio::test]
async fn run_command_apply_executes_when_allowlisted() {
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "echo".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        params,
        Some(5),
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert_eq!(out.freed_bytes, 0);
    assert!(out.warnings.is_empty());
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn run_command_rejects_when_allowlist_missing() {
    let _guard = env_lock();
    let _env = EnvVarGuard::clear("PREEN_RUN_COMMAND_ALLOWLIST");
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        HashMap::new(),
        Some(5),
    );

    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::Failed { .. }));
    assert!(err.to_string().contains("allowlist is empty"));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn run_command_rejects_when_not_allowlisted() {
    let _guard = env_lock();
    let _env = EnvVarGuard::clear("PREEN_RUN_COMMAND_ALLOWLIST");
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "ls".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        params,
        Some(5),
    );

    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::CommandDenied { .. }));
    assert!(err.to_string().contains("denied by allowlist"));
}

#[tokio::test]
async fn run_command_times_out() {
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "sh".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 2".to_string(),
        ],
        params,
        Some(1),
    );

    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::CommandTimeout { .. }));
    assert!(err.to_string().contains("timed out"));
}

#[tokio::test]
async fn run_command_non_zero_exit_is_classified() {
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "sh".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 12".to_string(),
        ],
        params,
        Some(5),
    );

    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(
        err,
        ActionExecutionError::CommandNonZero { code: Some(12), .. }
    ));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn run_command_accepts_allowlist_from_env() {
    let _guard = env_lock();
    let _env = EnvVarGuard::set("PREEN_RUN_COMMAND_ALLOWLIST", "echo");
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        HashMap::new(),
        Some(5),
    );
    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
}

#[tokio::test]
async fn run_command_rejects_unsafe_path_when_only_basename_is_allowlisted() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("echo");
    fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }

    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "echo".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec![script.to_string_lossy().to_string()],
        params,
        Some(5),
    );

    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::CommandDenied { .. }));
}

#[tokio::test]
async fn run_command_rejects_traversal_under_safe_prefix_when_only_basename_is_allowlisted() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("echo");
    fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }

    let escaped = script.to_string_lossy().trim_start_matches('/').to_string();
    let traversal = format!("/usr/bin/../../{escaped}");
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "echo".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec![traversal],
        params,
        Some(5),
    );

    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::CommandDenied { .. }));
}

#[tokio::test]
async fn run_command_allows_unsafe_path_when_explicitly_allowlisted() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("echo");
    fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }

    let mut params = HashMap::new();
    params.insert(
        "allowlist".to_string(),
        script.to_string_lossy().to_string(),
    );
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec![script.to_string_lossy().to_string()],
        params,
        Some(5),
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert_eq!(out.freed_bytes, 0);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn run_command_bare_command_uses_safe_path_not_path_env() {
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("hijacked");
    let script = dir.path().join("echo");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }
    let _path = EnvVarGuard::set("PATH", &dir.path().to_string_lossy());

    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "echo".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec!["echo".to_string(), "ok".to_string()],
        params,
        Some(5),
    );

    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
    assert!(!marker.exists());
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn run_command_params_allowlist_overrides_env_allowlist() {
    let _guard = env_lock();
    let _env = EnvVarGuard::set("PREEN_RUN_COMMAND_ALLOWLIST", "echo");
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "ls".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        params,
        Some(5),
    );
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::CommandDenied { .. }));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn run_command_empty_param_allowlist_does_not_fallback_to_env() {
    let _guard = env_lock();
    let _env = EnvVarGuard::set("PREEN_RUN_COMMAND_ALLOWLIST", "echo");
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "   ".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        params,
        Some(5),
    );
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::Failed { .. }));
    assert!(err.to_string().contains("allowlist is empty"));
}

#[tokio::test]
async fn run_command_timeout_zero_is_treated_as_one_second() {
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "sh".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 2".to_string(),
        ],
        params,
        Some(0),
    );
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(
        err,
        ActionExecutionError::CommandTimeout { timeout_sec: 1, .. }
    ));
}

#[tokio::test]
async fn run_command_timeout_none_uses_default() {
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "echo".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        params,
        None,
    );
    let out = OsActionExecutor.execute(&plan).await.unwrap();
    assert_eq!(out.affected_items, 1);
}

#[tokio::test]
async fn run_command_timeout_above_policy_max_is_rejected() {
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "echo".to_string());
    let plan = sample_plan_with(
        ActionType::RunCommand,
        ExecutionMode::Apply,
        vec![],
        vec!["/bin/echo".to_string(), "ok".to_string()],
        params,
        Some(601),
    );

    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(err, ActionExecutionError::Failed { .. }));
    assert!(err.to_string().contains("timeout exceeds max 600 seconds"));
}
