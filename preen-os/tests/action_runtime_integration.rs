use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

use preen_core::ItemCategory;
use preen_core::action_runtime::{
    ActionAuditEvent, ActionAuditSink, ActionExecutionError, DefaultSafetyPolicy, ExecutionMode,
    RuntimeExecutionError, execute_action_with_audit,
};
use preen_core::plugin::{
    ActionSpec, ActionType, Capability, Manifest, MatchMode, MatchSpec, OsTarget, RiskLevel,
    RuleFile, RuleRef,
};
use preen_core::rules::ScanStrategy;
use preen_os::action_executor::OsActionExecutor;

struct RecordingAuditSink {
    events: Mutex<Vec<ActionAuditEvent>>,
}

impl RecordingAuditSink {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<ActionAuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl ActionAuditSink for RecordingAuditSink {
    fn record(&self, event: ActionAuditEvent) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event);
    }
}

fn sample_manifest(rule_id: &str) -> Manifest {
    Manifest {
        schema_version: 1,
        pack_id: "preen-rs.test".to_string(),
        name: "Test Pack".to_string(),
        version: "1.0.0".to_string(),
        description: "test".to_string(),
        author: "test".to_string(),
        license: "MIT".to_string(),
        homepage: None,
        core_compat: ">=0.1.0,<2.0.0".to_string(),
        action_api: 1,
        os_targets: vec![OsTarget::Macos, OsTarget::Linux],
        capabilities: vec![Capability::FsRead],
        signing: None,
        rules: vec![RuleRef {
            id: rule_id.to_string(),
            name: "Rule".to_string(),
            rule_file: "rules/rule.toml".to_string(),
        }],
    }
}

fn sample_rule(
    rule_id: &str,
    action: ActionSpec,
    mode: MatchMode,
    risk: RiskLevel,
    paths: Vec<String>,
) -> RuleFile {
    RuleFile {
        schema_version: 1,
        id: rule_id.to_string(),
        name: "Rule".to_string(),
        category: ItemCategory::Cache,
        risk,
        enabled: true,
        matcher: MatchSpec {
            mode,
            paths,
            strategy: Some(ScanStrategy::Recursive),
            command: Vec::new(),
            parser: None,
        },
        action,
    }
}

#[tokio::test]
async fn os_executor_scan_paths_emits_success_audit_lifecycle() {
    let dir = tempfile::Builder::new()
        .prefix("preen-scan-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    fs::write(dir.path().join("b.txt"), b"b").unwrap();
    let rule_id = "scan-rule";
    let manifest = sample_manifest(rule_id);
    let rule = sample_rule(
        rule_id,
        ActionSpec {
            action_type: ActionType::ScanPaths,
            paths: vec![dir.path().to_string_lossy().to_string()],
            command: Vec::new(),
            mode: None,
            timeout_sec: Some(30),
            allow_globs: false,
            max_items: Some(100),
            package_manager: None,
            project_types: Vec::new(),
            params: HashMap::new(),
        },
        MatchMode::Paths,
        RiskLevel::Low,
        vec![dir.path().to_string_lossy().to_string()],
    );
    let sink = RecordingAuditSink::new();
    let policy = DefaultSafetyPolicy::default();
    let executor = OsActionExecutor;

    let out = execute_action_with_audit(
        &manifest,
        &rule,
        ExecutionMode::Apply,
        None,
        &policy,
        &executor,
        Some(&sink),
    )
    .await
    .expect("scan should succeed");

    assert_eq!(out.affected_items, 2);
    assert_eq!(out.freed_bytes, 0);
    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_kind, "plan_built");
    assert_eq!(events[1].event_kind, "execution_started");
    assert_eq!(events[2].event_kind, "execution_succeeded");
    assert_eq!(events[2].detail_code, None);
    assert_eq!(events[2].affected_items, Some(2));
}

#[tokio::test]
async fn os_executor_run_command_denied_emits_command_denied_detail_code() {
    let rule_id = "run-rule";
    let manifest = sample_manifest(rule_id);
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "ls".to_string());
    let rule = sample_rule(
        rule_id,
        ActionSpec {
            action_type: ActionType::RunCommand,
            paths: Vec::new(),
            command: vec!["/bin/echo".to_string(), "ok".to_string()],
            mode: None,
            timeout_sec: Some(30),
            allow_globs: false,
            max_items: Some(100),
            package_manager: None,
            project_types: Vec::new(),
            params,
        },
        MatchMode::Command,
        RiskLevel::Low,
        Vec::new(),
    );
    let sink = RecordingAuditSink::new();
    let policy = DefaultSafetyPolicy::default();
    let executor = OsActionExecutor;

    let err = execute_action_with_audit(
        &manifest,
        &rule,
        ExecutionMode::DryRun,
        None,
        &policy,
        &executor,
        Some(&sink),
    )
    .await
    .expect_err("run command should be denied by allowlist");

    assert!(matches!(
        err,
        RuntimeExecutionError::Execute(ActionExecutionError::CommandDenied { .. })
    ));
    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_kind, "plan_built");
    assert_eq!(events[1].event_kind, "execution_started");
    assert_eq!(events[2].event_kind, "execution_failed");
    assert_eq!(events[2].detail_code.as_deref(), Some("command_denied"));
}

#[tokio::test]
async fn os_executor_unsupported_action_emits_unsupported_action_detail_code() {
    let rule_id = "unsupported-rule";
    let manifest = sample_manifest(rule_id);
    let rule = sample_rule(
        rule_id,
        ActionSpec {
            action_type: ActionType::AppUninstall,
            paths: Vec::new(),
            command: Vec::new(),
            mode: None,
            timeout_sec: Some(30),
            allow_globs: false,
            max_items: Some(100),
            package_manager: None,
            project_types: Vec::new(),
            params: HashMap::new(),
        },
        MatchMode::Paths,
        RiskLevel::Low,
        vec!["/tmp".to_string()],
    );
    let sink = RecordingAuditSink::new();
    let policy = DefaultSafetyPolicy::default();
    let executor = OsActionExecutor;

    let err = execute_action_with_audit(
        &manifest,
        &rule,
        ExecutionMode::DryRun,
        None,
        &policy,
        &executor,
        Some(&sink),
    )
    .await
    .expect_err("unsupported action should fail");

    assert!(matches!(
        err,
        RuntimeExecutionError::Execute(ActionExecutionError::UnsupportedAction { .. })
    ));
    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].event_kind, "execution_failed");
    assert_eq!(events[2].detail_code.as_deref(), Some("unsupported_action"));
}

#[tokio::test]
async fn os_executor_run_command_timeout_emits_command_timeout_detail_code() {
    let rule_id = "run-timeout-rule";
    let manifest = sample_manifest(rule_id);
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "sh".to_string());
    let rule = sample_rule(
        rule_id,
        ActionSpec {
            action_type: ActionType::RunCommand,
            paths: Vec::new(),
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 2".to_string(),
            ],
            mode: None,
            timeout_sec: Some(1),
            allow_globs: false,
            max_items: Some(100),
            package_manager: None,
            project_types: Vec::new(),
            params,
        },
        MatchMode::Command,
        RiskLevel::Low,
        Vec::new(),
    );
    let sink = RecordingAuditSink::new();
    let policy = DefaultSafetyPolicy::default();
    let executor = OsActionExecutor;

    let err = execute_action_with_audit(
        &manifest,
        &rule,
        ExecutionMode::Apply,
        Some("ok"),
        &policy,
        &executor,
        Some(&sink),
    )
    .await
    .expect_err("run command should timeout");

    assert!(matches!(
        err,
        RuntimeExecutionError::Execute(ActionExecutionError::CommandTimeout { .. })
    ));
    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_kind, "plan_built");
    assert_eq!(events[1].event_kind, "execution_started");
    assert_eq!(events[2].event_kind, "execution_failed");
    assert_eq!(events[2].detail_code.as_deref(), Some("command_timeout"));
}

#[tokio::test]
async fn os_executor_run_command_non_zero_emits_command_non_zero_detail_code() {
    let rule_id = "run-non-zero-rule";
    let manifest = sample_manifest(rule_id);
    let mut params = HashMap::new();
    params.insert("allowlist".to_string(), "sh".to_string());
    let rule = sample_rule(
        rule_id,
        ActionSpec {
            action_type: ActionType::RunCommand,
            paths: Vec::new(),
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 12".to_string(),
            ],
            mode: None,
            timeout_sec: Some(30),
            allow_globs: false,
            max_items: Some(100),
            package_manager: None,
            project_types: Vec::new(),
            params,
        },
        MatchMode::Command,
        RiskLevel::Low,
        Vec::new(),
    );
    let sink = RecordingAuditSink::new();
    let policy = DefaultSafetyPolicy::default();
    let executor = OsActionExecutor;

    let err = execute_action_with_audit(
        &manifest,
        &rule,
        ExecutionMode::Apply,
        Some("ok"),
        &policy,
        &executor,
        Some(&sink),
    )
    .await
    .expect_err("run command should fail with non-zero status");

    assert!(matches!(
        err,
        RuntimeExecutionError::Execute(ActionExecutionError::CommandNonZero { code: Some(12), .. })
    ));
    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_kind, "plan_built");
    assert_eq!(events[1].event_kind, "execution_started");
    assert_eq!(events[2].event_kind, "execution_failed");
    assert_eq!(events[2].detail_code.as_deref(), Some("command_non_zero"));
}
