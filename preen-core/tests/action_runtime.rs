use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use preen_core::ItemCategory;
use preen_core::action_runtime::{
    ActionAuditContext, ActionAuditEvent, ActionAuditSink, ActionExecutionError,
    ActionExecutionResult, ActionExecutorPort, DefaultSafetyPolicy, ExecutionMode, PlanError,
    RuntimeExecutionError, SafetyViolation, audit_event_for_execution_failed,
    audit_event_for_execution_started, audit_event_for_execution_succeeded,
    audit_event_for_plan_built, audit_event_for_plan_rejected, build_execution_plan,
    execute_action_with_audit, execution_error_detail_code, plan_error_detail_code,
};
use preen_core::plugin::{
    ActionSpec, ActionType, Manifest, MatchMode, MatchSpec, RiskLevel, RuleFile, RuleRef,
};
use preen_core::rules::ScanStrategy;

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
        os_targets: vec![preen_core::plugin::OsTarget::Macos],
        capabilities: vec![preen_core::plugin::Capability::FsRead],
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
    action_type: ActionType,
    paths: Vec<&str>,
    risk: RiskLevel,
) -> RuleFile {
    RuleFile {
        schema_version: 1,
        id: rule_id.to_string(),
        name: "Rule".to_string(),
        category: ItemCategory::Cache,
        risk,
        enabled: true,
        matcher: MatchSpec {
            mode: MatchMode::Paths,
            paths: vec!["/tmp".to_string()],
            strategy: Some(ScanStrategy::Recursive),
            command: Vec::new(),
            parser: None,
        },
        action: ActionSpec {
            action_type,
            paths: paths.into_iter().map(ToOwned::to_owned).collect(),
            command: Vec::new(),
            mode: None,
            timeout_sec: Some(30),
            allow_globs: false,
            max_items: Some(100),
            package_manager: None,
            project_types: Vec::new(),
            params: HashMap::new(),
        },
    }
}

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
        self.events.lock().unwrap().clone()
    }
}

impl ActionAuditSink for RecordingAuditSink {
    fn record(&self, event: ActionAuditEvent) {
        self.events.lock().unwrap().push(event);
    }
}

struct MockExecutorOk;

#[async_trait]
impl ActionExecutorPort for MockExecutorOk {
    async fn execute(
        &self,
        _plan: &preen_core::action_runtime::ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        Ok(ActionExecutionResult {
            affected_items: 2,
            freed_bytes: 2048,
            warnings: vec![],
        })
    }
}

struct MockExecutorFail;

#[async_trait]
impl ActionExecutorPort for MockExecutorFail {
    async fn execute(
        &self,
        _plan: &preen_core::action_runtime::ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        Err(ActionExecutionError::Failed {
            message: "io failure".to_string(),
        })
    }
}

#[test]
fn policy_blocks_root_system_path_for_destructive_action() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::DeletePaths,
        vec!["/System/Library/Caches"],
        RiskLevel::High,
    );
    let policy = DefaultSafetyPolicy::default();

    let err = build_execution_plan(&manifest, &rule, ExecutionMode::Apply, Some("ok"), &policy)
        .expect_err("system path must be blocked");

    assert!(matches!(
        err,
        PlanError::SafetyRejected(SafetyViolation::BlockedPath { .. })
    ));
}

#[test]
fn policy_allows_allowlisted_private_var_subpath() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::DeletePaths,
        vec!["/private/var/log/test.log"],
        RiskLevel::High,
    );
    let policy = DefaultSafetyPolicy::default();

    let plan = build_execution_plan(&manifest, &rule, ExecutionMode::Apply, Some("ok"), &policy)
        .expect("allowlisted subpath should pass");

    assert!(plan.requires_confirmation);
}

#[test]
fn apply_high_risk_action_requires_confirmation_token() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::TrashPaths,
        vec!["~/Library/Caches/App"],
        RiskLevel::High,
    );
    let policy = DefaultSafetyPolicy::default();

    let err = build_execution_plan(&manifest, &rule, ExecutionMode::Apply, None, &policy)
        .expect_err("missing confirmation should fail");

    assert!(matches!(err, PlanError::ConfirmationRequired { .. }));
}

#[test]
fn dry_run_allows_high_risk_action_without_confirmation() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::TrashPaths,
        vec!["~/Library/Caches/App"],
        RiskLevel::High,
    );
    let policy = DefaultSafetyPolicy::default();

    let plan = build_execution_plan(&manifest, &rule, ExecutionMode::DryRun, None, &policy)
        .expect("dry-run should not require confirmation");

    assert!(!plan.requires_confirmation);
}

#[test]
fn apply_run_command_requires_confirmation_even_for_medium_risk() {
    let mut rule = sample_rule("rule-1", ActionType::RunCommand, vec![], RiskLevel::Medium);
    rule.action.command = vec!["brew".to_string(), "cleanup".to_string()];
    let manifest = sample_manifest("rule-1");
    let policy = DefaultSafetyPolicy::default();

    let err = build_execution_plan(&manifest, &rule, ExecutionMode::Apply, None, &policy)
        .expect_err("run_command apply should require confirmation");

    assert!(matches!(err, PlanError::ConfirmationRequired { .. }));
}

#[test]
fn rule_must_be_declared_in_manifest() {
    let manifest = sample_manifest("rule-other");
    let rule = sample_rule(
        "rule-1",
        ActionType::ScanPaths,
        vec!["/tmp"],
        RiskLevel::Low,
    );
    let policy = DefaultSafetyPolicy::default();

    let err = build_execution_plan(&manifest, &rule, ExecutionMode::DryRun, None, &policy)
        .expect_err("undeclared rule must fail");

    assert!(matches!(err, PlanError::RuleNotInManifest { .. }));
}

#[test]
fn plan_error_detail_code_contract_is_stable() {
    assert_eq!(
        plan_error_detail_code(&PlanError::RuleNotInManifest {
            rule_id: "rule-1".to_string()
        }),
        "rule_not_in_manifest"
    );
    assert_eq!(
        plan_error_detail_code(&PlanError::ConfirmationRequired {
            rule_id: "rule-1".to_string()
        }),
        "confirmation_required"
    );
    assert_eq!(
        plan_error_detail_code(&PlanError::SafetyRejected(SafetyViolation::BlockedPath {
            path: "/System".to_string()
        })),
        "blocked_path"
    );
    assert_eq!(
        plan_error_detail_code(&PlanError::SafetyRejected(SafetyViolation::RelativePath {
            path: "tmp".to_string()
        })),
        "relative_path"
    );
}

#[test]
fn execution_error_detail_code_contract_is_stable() {
    assert_eq!(
        execution_error_detail_code(&ActionExecutionError::UnsupportedAction {
            action: "RunCommand".to_string()
        }),
        "unsupported_action"
    );
    assert_eq!(
        execution_error_detail_code(&ActionExecutionError::CommandDenied {
            command: "rm".to_string()
        }),
        "command_denied"
    );
    assert_eq!(
        execution_error_detail_code(&ActionExecutionError::CommandTimeout {
            command: "sleep 10".to_string(),
            timeout_sec: 1
        }),
        "command_timeout"
    );
    assert_eq!(
        execution_error_detail_code(&ActionExecutionError::CommandNonZero {
            command: "false".to_string(),
            code: Some(1)
        }),
        "command_non_zero"
    );
    assert_eq!(
        execution_error_detail_code(&ActionExecutionError::Failed {
            message: "timeout".to_string()
        }),
        "execution_failed"
    );
}

#[test]
fn audit_event_for_plan_built_has_serializable_contract() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::TrashPaths,
        vec!["~/Library/Caches/App"],
        RiskLevel::High,
    );
    let policy = DefaultSafetyPolicy::default();
    let plan = build_execution_plan(&manifest, &rule, ExecutionMode::Apply, Some("ok"), &policy)
        .expect("plan should be built");

    let event = audit_event_for_plan_built(&plan);
    let value = serde_json::to_value(&event).unwrap();
    assert_eq!(value["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(value["event_kind"].as_str().unwrap(), "plan_built");
    assert_eq!(
        value["context"]["action_type"].as_str().unwrap(),
        "trash_paths"
    );
    assert!(value["event_id"].as_str().unwrap().len() > 10);
    assert!(!value["occurred_at"].as_str().unwrap().trim().is_empty());
    assert!(value["requires_confirmation"].as_bool().unwrap());
}

#[test]
fn audit_event_for_plan_rejected_contains_reason_fields() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::DeletePaths,
        vec!["tmp"],
        RiskLevel::Medium,
    );
    let ctx = ActionAuditContext::from_manifest_rule(&manifest, &rule, ExecutionMode::Apply);
    let err = PlanError::SafetyRejected(SafetyViolation::RelativePath {
        path: "tmp".to_string(),
    });

    let event = audit_event_for_plan_rejected(ctx, &err);
    let value = serde_json::to_value(&event).unwrap();
    assert_eq!(value["event_kind"].as_str().unwrap(), "plan_rejected");
    assert_eq!(value["detail_code"].as_str().unwrap(), "relative_path");
    assert!(
        value["message"]
            .as_str()
            .unwrap()
            .contains("path must be absolute")
    );
    assert!(!value["requires_confirmation"].as_bool().unwrap());
}

#[test]
fn audit_event_for_execution_succeeded_and_failed_have_expected_payload() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::TrashPaths,
        vec!["/tmp/app"],
        RiskLevel::Low,
    );
    let policy = DefaultSafetyPolicy::default();
    let plan = build_execution_plan(&manifest, &rule, ExecutionMode::Apply, Some("ok"), &policy)
        .expect("plan should be built");

    let started = audit_event_for_execution_started(&plan);
    let started_value = serde_json::to_value(&started).unwrap();
    assert_eq!(
        started_value["event_kind"].as_str().unwrap(),
        "execution_started"
    );

    let ok = audit_event_for_execution_succeeded(
        &plan,
        &ActionExecutionResult {
            affected_items: 5,
            freed_bytes: 1024,
            warnings: vec![],
        },
    );
    let ok_value = serde_json::to_value(&ok).unwrap();
    assert_eq!(
        ok_value["event_kind"].as_str().unwrap(),
        "execution_succeeded"
    );
    assert_eq!(ok_value["affected_items"].as_u64().unwrap(), 5);
    assert_eq!(ok_value["freed_bytes"].as_u64().unwrap(), 1024);

    let failed = audit_event_for_execution_failed(
        &plan,
        &ActionExecutionError::UnsupportedAction {
            action: "run_command".to_string(),
        },
    );
    let failed_value = serde_json::to_value(&failed).unwrap();
    assert_eq!(
        failed_value["event_kind"].as_str().unwrap(),
        "execution_failed"
    );
    assert_eq!(
        failed_value["detail_code"].as_str().unwrap(),
        "unsupported_action"
    );
}

#[tokio::test]
async fn execute_action_with_audit_emits_ordered_success_lifecycle() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::TrashPaths,
        vec!["/tmp/app"],
        RiskLevel::Low,
    );
    let policy = DefaultSafetyPolicy::default();
    let sink = RecordingAuditSink::new();
    let executor = MockExecutorOk;

    let out = execute_action_with_audit(
        &manifest,
        &rule,
        ExecutionMode::Apply,
        Some("ok"),
        &policy,
        &executor,
        Some(&sink),
    )
    .await
    .expect("execution should pass");

    assert_eq!(out.affected_items, 2);
    assert_eq!(out.freed_bytes, 2048);

    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_kind, "plan_built");
    assert_eq!(events[1].event_kind, "execution_started");
    assert_eq!(events[2].event_kind, "execution_succeeded");
    assert_eq!(events[2].affected_items, Some(2));
}

#[tokio::test]
async fn execute_action_with_audit_emits_plan_rejected_on_policy_failure() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::DeletePaths,
        vec!["relative/path"],
        RiskLevel::Medium,
    );
    let policy = DefaultSafetyPolicy::default();
    let sink = RecordingAuditSink::new();
    let executor = MockExecutorOk;

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
    .expect_err("plan should be rejected");

    assert!(matches!(
        err,
        RuntimeExecutionError::Plan(PlanError::SafetyRejected(
            SafetyViolation::RelativePath { .. }
        ))
    ));
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_kind, "plan_rejected");
    assert_eq!(events[0].detail_code.as_deref(), Some("relative_path"));
}

#[tokio::test]
async fn execute_action_with_audit_emits_execution_failed_on_executor_error() {
    let manifest = sample_manifest("rule-1");
    let rule = sample_rule(
        "rule-1",
        ActionType::TrashPaths,
        vec!["/tmp/app"],
        RiskLevel::Low,
    );
    let policy = DefaultSafetyPolicy::default();
    let sink = RecordingAuditSink::new();
    let executor = MockExecutorFail;

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
    .expect_err("execution should fail");

    assert!(matches!(
        err,
        RuntimeExecutionError::Execute(ActionExecutionError::Failed { .. })
    ));
    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_kind, "plan_built");
    assert_eq!(events[1].event_kind, "execution_started");
    assert_eq!(events[2].event_kind, "execution_failed");
    assert_eq!(events[2].detail_code.as_deref(), Some("execution_failed"));
}
