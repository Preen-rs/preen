use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::plugin::{ActionSpec, ActionType, Manifest, RiskLevel, RuleFile};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    DryRun,
    Apply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl ActionRisk {
    pub const fn is_high_or_critical(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

impl From<&RiskLevel> for ActionRisk {
    fn from(value: &RiskLevel) -> Self {
        match value {
            RiskLevel::Low => Self::Low,
            RiskLevel::Medium => Self::Medium,
            RiskLevel::High => Self::High,
            RiskLevel::Critical => Self::Critical,
            RiskLevel::Other(_) => Self::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub pack_id: String,
    pub rule_id: String,
    pub action: ActionSpec,
    pub risk: ActionRisk,
    pub mode: ExecutionMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyDecision {
    pub requires_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SafetyViolation {
    #[error("destructive path blocked by policy: {path}")]
    BlockedPath { path: String },
    #[error("path must be absolute: {path}")]
    RelativePath { path: String },
}

pub trait SafetyPolicy: Send + Sync {
    fn evaluate(&self, request: &ExecutionRequest) -> Result<SafetyDecision, SafetyViolation>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultSafetyPolicy {
    blocked_path_prefixes: Vec<String>,
    allowlisted_prefixes: Vec<String>,
}

impl Default for DefaultSafetyPolicy {
    fn default() -> Self {
        Self {
            blocked_path_prefixes: vec![
                "/".to_string(),
                "/System".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
                "/usr".to_string(),
                "/etc".to_string(),
                "/var".to_string(),
                "/private".to_string(),
                "/Library/Extensions".to_string(),
            ],
            allowlisted_prefixes: vec![
                "/private/tmp".to_string(),
                "/private/var/tmp".to_string(),
                "/private/var/log".to_string(),
                "/private/var/folders".to_string(),
                "/private/var/db/diagnostics".to_string(),
                "/private/var/db/DiagnosticPipeline".to_string(),
                "/private/var/db/powerlog".to_string(),
                "/private/var/db/reportmemoryexception".to_string(),
            ],
        }
    }
}

impl DefaultSafetyPolicy {
    pub fn with_prefixes(
        blocked_path_prefixes: Vec<String>,
        allowlisted_prefixes: Vec<String>,
    ) -> Self {
        Self {
            blocked_path_prefixes,
            allowlisted_prefixes,
        }
    }

    fn is_blocked_path(&self, path: &str) -> bool {
        let normalized = path.trim();
        if normalized.is_empty() {
            return false;
        }
        if self
            .allowlisted_prefixes
            .iter()
            .any(|p| normalized.starts_with(p))
        {
            return false;
        }
        self.blocked_path_prefixes
            .iter()
            .any(|p| normalized == p || normalized.starts_with(&format!("{p}/")))
    }
}

impl SafetyPolicy for DefaultSafetyPolicy {
    fn evaluate(&self, request: &ExecutionRequest) -> Result<SafetyDecision, SafetyViolation> {
        if is_path_bound_action(&request.action.action_type) {
            for path in &request.action.paths {
                if !path.starts_with('/') && !path.starts_with("~/") {
                    return Err(SafetyViolation::RelativePath { path: path.clone() });
                }
                if path.starts_with('/') && self.is_blocked_path(path) {
                    return Err(SafetyViolation::BlockedPath { path: path.clone() });
                }
            }
        }

        let requires_confirmation = request.mode == ExecutionMode::Apply
            && (request.risk.is_high_or_critical()
                || matches!(request.action.action_type, ActionType::RunCommand)
                || is_destructive_action(&request.action.action_type));

        Ok(SafetyDecision {
            requires_confirmation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub request: ExecutionRequest,
    pub requires_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlanError {
    #[error("manifest/rule mismatch: rule does not belong to manifest: {rule_id}")]
    RuleNotInManifest { rule_id: String },
    #[error("safety policy rejected action: {0}")]
    SafetyRejected(#[from] SafetyViolation),
    #[error("confirmation token is required for action: {rule_id}")]
    ConfirmationRequired { rule_id: String },
}

pub fn build_execution_plan(
    manifest: &Manifest,
    rule: &RuleFile,
    mode: ExecutionMode,
    confirmation_token: Option<&str>,
    safety_policy: &dyn SafetyPolicy,
) -> Result<ExecutionPlan, PlanError> {
    if !manifest.rules.iter().any(|item| item.id == rule.id) {
        return Err(PlanError::RuleNotInManifest {
            rule_id: rule.id.clone(),
        });
    }

    let request = ExecutionRequest {
        pack_id: manifest.pack_id.clone(),
        rule_id: rule.id.clone(),
        action: rule.action.clone(),
        risk: ActionRisk::from(&rule.risk),
        mode,
    };

    let decision = safety_policy.evaluate(&request)?;
    if decision.requires_confirmation && confirmation_token.is_none() {
        return Err(PlanError::ConfirmationRequired {
            rule_id: rule.id.clone(),
        });
    }

    Ok(ExecutionPlan {
        request,
        requires_confirmation: decision.requires_confirmation,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionExecutionResult {
    pub affected_items: u64,
    pub freed_bytes: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ActionExecutionError {
    #[error("unsupported action for executor: {action}")]
    UnsupportedAction { action: String },
    #[error("run command denied by allowlist: {command}")]
    CommandDenied { command: String },
    #[error("run command timed out after {timeout_sec}s: {command}")]
    CommandTimeout { command: String, timeout_sec: u64 },
    #[error("run command exited with non-zero status {code:?}: {command}")]
    CommandNonZero { command: String, code: Option<i32> },
    #[error("execution failed: {message}")]
    Failed { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RuntimeExecutionError {
    #[error("plan failed: {0}")]
    Plan(#[from] PlanError),
    #[error("execution failed: {0}")]
    Execute(#[from] ActionExecutionError),
}

pub const ACTION_AUDIT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionAuditEventKind {
    PlanBuilt,
    PlanRejected,
    ExecutionStarted,
    ExecutionSucceeded,
    ExecutionFailed,
}

impl ActionAuditEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlanBuilt => "plan_built",
            Self::PlanRejected => "plan_rejected",
            Self::ExecutionStarted => "execution_started",
            Self::ExecutionSucceeded => "execution_succeeded",
            Self::ExecutionFailed => "execution_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionAuditContext {
    pub pack_id: String,
    pub rule_id: String,
    pub action_type: String,
    pub mode: ExecutionMode,
    pub risk: ActionRisk,
}

impl ActionAuditContext {
    pub fn from_plan(plan: &ExecutionPlan) -> Self {
        Self {
            pack_id: plan.request.pack_id.clone(),
            rule_id: plan.request.rule_id.clone(),
            action_type: action_type_label(&plan.request.action.action_type).to_string(),
            mode: plan.request.mode,
            risk: plan.request.risk,
        }
    }

    pub fn from_manifest_rule(manifest: &Manifest, rule: &RuleFile, mode: ExecutionMode) -> Self {
        Self {
            pack_id: manifest.pack_id.clone(),
            rule_id: rule.id.clone(),
            action_type: action_type_label(&rule.action.action_type).to_string(),
            mode,
            risk: ActionRisk::from(&rule.risk),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionAuditEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub occurred_at: DateTime<Utc>,
    pub event_kind: String,
    pub context: ActionAuditContext,
    pub requires_confirmation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_items: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freed_bytes: Option<u64>,
}

fn new_audit_event(
    event_kind: ActionAuditEventKind,
    context: ActionAuditContext,
    requires_confirmation: bool,
) -> ActionAuditEvent {
    ActionAuditEvent {
        schema_version: ACTION_AUDIT_SCHEMA_VERSION,
        event_id: Uuid::new_v4().to_string(),
        occurred_at: Utc::now(),
        event_kind: event_kind.as_str().to_string(),
        context,
        requires_confirmation,
        detail_code: None,
        message: None,
        affected_items: None,
        freed_bytes: None,
    }
}

fn action_type_label(action_type: &ActionType) -> &str {
    match action_type {
        ActionType::ScanPaths => "scan_paths",
        ActionType::MatchRegex => "match_regex",
        ActionType::OlderThanDays => "older_than_days",
        ActionType::TrashPaths => "trash_paths",
        ActionType::DeletePaths => "delete_paths",
        ActionType::PruneEmptyDirs => "prune_empty_dirs",
        ActionType::RemoveOrphans => "remove_orphans",
        ActionType::AppUninstall => "app_uninstall",
        ActionType::DiskUsageSnapshot => "disk_usage_snapshot",
        ActionType::SystemStatus => "system_status",
        ActionType::ProjectCleanup => "project_cleanup",
        ActionType::FindInstallers => "find_installers",
        ActionType::OptimizeSystem => "optimize_system",
        ActionType::RunCommand => "run_command",
        ActionType::Other(label) => label.as_str(),
    }
}

pub fn plan_error_detail_code(error: &PlanError) -> &'static str {
    match error {
        PlanError::RuleNotInManifest { .. } => "rule_not_in_manifest",
        PlanError::SafetyRejected(SafetyViolation::BlockedPath { .. }) => "blocked_path",
        PlanError::SafetyRejected(SafetyViolation::RelativePath { .. }) => "relative_path",
        PlanError::ConfirmationRequired { .. } => "confirmation_required",
    }
}

pub fn execution_error_detail_code(error: &ActionExecutionError) -> &'static str {
    match error {
        ActionExecutionError::UnsupportedAction { .. } => "unsupported_action",
        ActionExecutionError::CommandDenied { .. } => "command_denied",
        ActionExecutionError::CommandTimeout { .. } => "command_timeout",
        ActionExecutionError::CommandNonZero { .. } => "command_non_zero",
        ActionExecutionError::Failed { .. } => "execution_failed",
    }
}

pub fn audit_event_for_plan_built(plan: &ExecutionPlan) -> ActionAuditEvent {
    new_audit_event(
        ActionAuditEventKind::PlanBuilt,
        ActionAuditContext::from_plan(plan),
        plan.requires_confirmation,
    )
}

pub fn audit_event_for_plan_rejected(
    context: ActionAuditContext,
    error: &PlanError,
) -> ActionAuditEvent {
    let mut event = new_audit_event(ActionAuditEventKind::PlanRejected, context, false);
    event.detail_code = Some(plan_error_detail_code(error).to_string());
    event.message = Some(error.to_string());
    event
}

pub fn audit_event_for_execution_started(plan: &ExecutionPlan) -> ActionAuditEvent {
    new_audit_event(
        ActionAuditEventKind::ExecutionStarted,
        ActionAuditContext::from_plan(plan),
        plan.requires_confirmation,
    )
}

pub fn audit_event_for_execution_succeeded(
    plan: &ExecutionPlan,
    result: &ActionExecutionResult,
) -> ActionAuditEvent {
    let mut event = new_audit_event(
        ActionAuditEventKind::ExecutionSucceeded,
        ActionAuditContext::from_plan(plan),
        plan.requires_confirmation,
    );
    event.affected_items = Some(result.affected_items);
    event.freed_bytes = Some(result.freed_bytes);
    event
}

pub fn audit_event_for_execution_failed(
    plan: &ExecutionPlan,
    error: &ActionExecutionError,
) -> ActionAuditEvent {
    let mut event = new_audit_event(
        ActionAuditEventKind::ExecutionFailed,
        ActionAuditContext::from_plan(plan),
        plan.requires_confirmation,
    );
    event.detail_code = Some(execution_error_detail_code(error).to_string());
    event.message = Some(error.to_string());
    event
}

pub trait ActionAuditSink: Send + Sync {
    fn record(&self, event: ActionAuditEvent);
}

#[async_trait]
pub trait ActionExecutorPort: Send + Sync {
    async fn execute(
        &self,
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError>;
}

pub async fn execute_action_with_audit(
    manifest: &Manifest,
    rule: &RuleFile,
    mode: ExecutionMode,
    confirmation_token: Option<&str>,
    safety_policy: &dyn SafetyPolicy,
    executor: &dyn ActionExecutorPort,
    audit_sink: Option<&dyn ActionAuditSink>,
) -> Result<ActionExecutionResult, RuntimeExecutionError> {
    let context = ActionAuditContext::from_manifest_rule(manifest, rule, mode);
    let plan = match build_execution_plan(manifest, rule, mode, confirmation_token, safety_policy) {
        Ok(plan) => {
            if let Some(sink) = audit_sink {
                sink.record(audit_event_for_plan_built(&plan));
            }
            plan
        }
        Err(error) => {
            if let Some(sink) = audit_sink {
                sink.record(audit_event_for_plan_rejected(context, &error));
            }
            return Err(RuntimeExecutionError::Plan(error));
        }
    };

    if let Some(sink) = audit_sink {
        sink.record(audit_event_for_execution_started(&plan));
    }
    match executor.execute(&plan).await {
        Ok(result) => {
            if let Some(sink) = audit_sink {
                sink.record(audit_event_for_execution_succeeded(&plan, &result));
            }
            Ok(result)
        }
        Err(error) => {
            if let Some(sink) = audit_sink {
                sink.record(audit_event_for_execution_failed(&plan, &error));
            }
            Err(RuntimeExecutionError::Execute(error))
        }
    }
}

pub fn is_destructive_action(action_type: &ActionType) -> bool {
    matches!(
        action_type,
        ActionType::TrashPaths
            | ActionType::DeletePaths
            | ActionType::PruneEmptyDirs
            | ActionType::RemoveOrphans
            | ActionType::AppUninstall
            | ActionType::ProjectCleanup
            | ActionType::FindInstallers
            | ActionType::OptimizeSystem
    )
}

pub fn is_path_bound_action(action_type: &ActionType) -> bool {
    matches!(
        action_type,
        ActionType::ScanPaths
            | ActionType::MatchRegex
            | ActionType::OlderThanDays
            | ActionType::TrashPaths
            | ActionType::DeletePaths
            | ActionType::PruneEmptyDirs
            | ActionType::ProjectCleanup
            | ActionType::FindInstallers
    )
}
