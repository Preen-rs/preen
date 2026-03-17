use std::collections::HashMap;
use std::fs;

use preen_core::action_runtime::{
    ActionExecutionError, ActionExecutorPort, ActionRisk, ExecutionMode, ExecutionPlan,
    ExecutionRequest,
};
use preen_core::plugin::{ActionSpec, ActionType};
use preen_os::action_executor::OsActionExecutor;

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
    let plan = sample_plan(ActionType::ScanPaths, ExecutionMode::DryRun, vec![]);
    let err = OsActionExecutor.execute(&plan).await.unwrap_err();
    assert!(matches!(
        err,
        ActionExecutionError::UnsupportedAction { .. }
    ));
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
