use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
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
    let plan = sample_plan(ActionType::AppUninstall, ExecutionMode::DryRun, vec![]);
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(
        err,
        ActionExecutionError::UnsupportedAction { .. }
    ));
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
