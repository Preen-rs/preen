use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{ItemCategory, rules::ScanStrategy};

pub const MANIFEST_SCHEMA_V1: u32 = 1;
pub const RULE_SCHEMA_V1: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsTarget {
    Macos,
    Linux,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    FsRead,
    FsTrash,
    FsDelete,
    SystemOptimize,
    RunCommand,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningInfo {
    pub sigstore: bool,
    pub issuer: Option<String>,
    pub identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    pub id: String,
    pub name: String,
    pub rule_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub pack_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub license: String,
    pub homepage: Option<String>,
    pub core_compat: String,
    pub action_api: u32,
    pub os_targets: Vec<OsTarget>,
    pub capabilities: Vec<Capability>,
    pub signing: Option<SigningInfo>,
    pub rules: Vec<RuleRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchMode {
    Paths,
    Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchSpec {
    pub mode: MatchMode,
    pub paths: Vec<String>,
    pub strategy: Option<ScanStrategy>,
    pub command: Vec<String>,
    pub parser: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    ScanPaths,
    MatchRegex,
    OlderThanDays,
    TrashPaths,
    DeletePaths,
    PruneEmptyDirs,
    RemoveOrphans,
    AppUninstall,
    DiskUsageSnapshot,
    SystemStatus,
    ProjectCleanup,
    FindInstallers,
    OptimizeSystem,
    RunCommand,
    Other(String),
}

impl ActionType {
    const BUILTIN_VARIANTS: [ActionType; 14] = [
        ActionType::ScanPaths,
        ActionType::MatchRegex,
        ActionType::OlderThanDays,
        ActionType::TrashPaths,
        ActionType::DeletePaths,
        ActionType::PruneEmptyDirs,
        ActionType::RemoveOrphans,
        ActionType::AppUninstall,
        ActionType::DiskUsageSnapshot,
        ActionType::SystemStatus,
        ActionType::ProjectCleanup,
        ActionType::FindInstallers,
        ActionType::OptimizeSystem,
        ActionType::RunCommand,
    ];

    pub fn builtin_variants() -> &'static [ActionType] {
        &Self::BUILTIN_VARIANTS
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionMode {
    Confirm,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSpec {
    pub action_type: ActionType,
    pub paths: Vec<String>,
    pub command: Vec<String>,
    pub mode: Option<ActionMode>,
    pub timeout_sec: Option<u64>,
    pub allow_globs: bool,
    pub max_items: Option<u64>,
    pub package_manager: Option<String>,
    pub project_types: Vec<String>,
    pub params: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleFile {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub category: ItemCategory,
    pub risk: RiskLevel,
    pub enabled: bool,
    #[serde(rename = "match")]
    pub matcher: MatchSpec,
    pub action: ActionSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    SchemaVersionUnsupported { found: u32, expected: u32 },
    MissingField { field: String },
    DuplicateRuleId { id: String },
    InvalidMatchSpec { reason: String },
    InvalidActionSpec { reason: String },
    Parse { context: String, message: String },
    RuleRefMissing { id: String },
    InvalidCoreCompat { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPolicy {
    pub allowlist: Vec<String>,
    pub remote_policy_url: Option<String>,
    pub remote_policy_identity: Option<String>,
    pub require_signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBundle {
    pub signature: String,
    pub certificate: String,
    pub rekor_log_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationInput {
    pub manifest_bytes: Vec<u8>,
    pub signature: SignatureBundle,
    pub expected_identity: Option<String>,
    pub expected_issuer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationOutcome {
    pub identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    NotTrusted { identity: String },
    SignatureInvalid(String),
    LogVerificationFailed(String),
    PolicyUnavailable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCheckId {
    VersionMatchesLock,
    SignatureVerified,
    TrustVerified,
    CoreCompatVerified,
    ActionApiVerified,
    OsTargetVerified,
}

impl PluginCheckId {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::VersionMatchesLock => "version_matches_lock",
            Self::SignatureVerified => "signature_verified",
            Self::TrustVerified => "trust_verified",
            Self::CoreCompatVerified => "core_compat_verified",
            Self::ActionApiVerified => "action_api_verified",
            Self::OsTargetVerified => "os_target_verified",
        }
    }
}

impl Display for PluginCheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCheckStatus {
    pub check: PluginCheckId,
    pub passed: bool,
}

impl PluginCheckStatus {
    pub fn new(check: PluginCheckId, passed: bool) -> Self {
        Self { check, passed }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRunSummary {
    pub overall_passed: bool,
    pub duration_ms: u64,
    pub checks: Vec<PluginCheckStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCheckSeverity {
    Info,
    Warning,
    Critical,
}

impl PluginCheckSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginFailureHint {
    pub code: &'static str,
    pub action: &'static str,
    pub priority: u8,
}

impl PluginFailureHint {
    pub const fn unknown() -> Self {
        Self {
            code: "unknown_failure",
            action: "collect_logs_and_retry",
            priority: 255,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginFailureHintContext {
    pub code: &'static str,
    pub action: &'static str,
    pub priority: u8,
    pub message: String,
}

pub fn plugin_failure_hint_context(
    hint: PluginFailureHint,
    language: &str,
) -> PluginFailureHintContext {
    PluginFailureHintContext {
        code: hint.code,
        action: hint.action,
        priority: hint.priority,
        message: plugin_failure_hint_message(hint.code, language),
    }
}

pub fn plugin_failure_hint_context_from_detail_code(
    detail_code: &str,
    language: &str,
) -> PluginFailureHintContext {
    plugin_failure_hint_context(plugin_failure_hint_from_detail_code(detail_code), language)
}

pub fn plugin_unknown_failure_hint_context(language: &str) -> PluginFailureHintContext {
    plugin_failure_hint_context(PluginFailureHint::unknown(), language)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginDetailCode {
    InstallCloneFailed,
    PreflightCloneFailed,
    InstallSourceCloneFailed,
    InstallSourceFetchFailed,
    InstallSourceCheckoutFailed,
    InstallSourceGitResolveFailed,
    PreflightSourceCloneFailed,
    PreflightSourceFetchFailed,
    PreflightSourceCheckoutFailed,
    PreflightSourceGitResolveFailed,
}

impl PluginDetailCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstallCloneFailed => "install_clone_failed",
            Self::PreflightCloneFailed => "preflight_clone_failed",
            Self::InstallSourceCloneFailed => "install_source_clone_failed",
            Self::InstallSourceFetchFailed => "install_source_fetch_failed",
            Self::InstallSourceCheckoutFailed => "install_source_checkout_failed",
            Self::InstallSourceGitResolveFailed => "install_source_git_resolve_failed",
            Self::PreflightSourceCloneFailed => "preflight_source_clone_failed",
            Self::PreflightSourceFetchFailed => "preflight_source_fetch_failed",
            Self::PreflightSourceCheckoutFailed => "preflight_source_checkout_failed",
            Self::PreflightSourceGitResolveFailed => "preflight_source_git_resolve_failed",
        }
    }

    pub fn parse(code: &str) -> Option<Self> {
        Some(match code {
            "install_clone_failed" => Self::InstallCloneFailed,
            "preflight_clone_failed" => Self::PreflightCloneFailed,
            "install_source_clone_failed" => Self::InstallSourceCloneFailed,
            "install_source_fetch_failed" => Self::InstallSourceFetchFailed,
            "install_source_checkout_failed" => Self::InstallSourceCheckoutFailed,
            "install_source_git_resolve_failed" => Self::InstallSourceGitResolveFailed,
            "preflight_source_clone_failed" => Self::PreflightSourceCloneFailed,
            "preflight_source_fetch_failed" => Self::PreflightSourceFetchFailed,
            "preflight_source_checkout_failed" => Self::PreflightSourceCheckoutFailed,
            "preflight_source_git_resolve_failed" => Self::PreflightSourceGitResolveFailed,
            _ => return None,
        })
    }

    pub const fn is_install_checkout_failure(self) -> bool {
        matches!(
            self,
            Self::InstallCloneFailed
                | Self::InstallSourceCloneFailed
                | Self::InstallSourceFetchFailed
                | Self::InstallSourceCheckoutFailed
                | Self::InstallSourceGitResolveFailed
        )
    }

    pub const fn is_preflight_checkout_failure(self) -> bool {
        matches!(
            self,
            Self::PreflightCloneFailed
                | Self::PreflightSourceCloneFailed
                | Self::PreflightSourceFetchFailed
                | Self::PreflightSourceCheckoutFailed
                | Self::PreflightSourceGitResolveFailed
        )
    }
}

pub fn plugin_failure_hint_from_detail_code(code: &str) -> PluginFailureHint {
    if let Some(detail_code) = PluginDetailCode::parse(code)
        && (detail_code.is_install_checkout_failure()
            || detail_code.is_preflight_checkout_failure())
    {
        return PluginFailureHint {
            code: "source_checkout_failed",
            action: "validate_git_url_and_pinned_rev",
            priority: 2,
        };
    }
    match code {
        "preflight_signature_or_trust_failed"
        | "install_signature_or_trust_failed"
        | "verify_signature_or_trust_failed"
        | "test_signature_or_trust_failed" => PluginFailureHint {
            code: "trust_or_signature_failed",
            action: "check_sigstore_identity_and_trust_policy",
            priority: 0,
        },
        "preflight_core_compat_failed"
        | "install_core_compat_failed"
        | "verify_core_compat_failed"
        | "test_core_compat_failed" => PluginFailureHint {
            code: "core_compat_failed",
            action: "update_plugin_or_core_version",
            priority: 1,
        },
        "preflight_action_api_unsupported"
        | "install_action_api_unsupported"
        | "verify_action_api_unsupported"
        | "test_action_api_unsupported" => PluginFailureHint {
            code: "action_api_unsupported",
            action: "upgrade_preen_core_or_plugin_action_api",
            priority: 1,
        },
        "preflight_os_target_failed"
        | "install_os_target_failed"
        | "verify_os_target_failed"
        | "test_os_target_failed" => PluginFailureHint {
            code: "os_target_failed",
            action: "use_plugin_with_matching_os_target",
            priority: 1,
        },
        "verify_resolved_rev_drift" | "test_resolved_rev_drift" => PluginFailureHint {
            code: "resolved_rev_drift",
            action: "reinstall_plugin_with_exact_pinned_commit",
            priority: 2,
        },
        "verify_manifest_hash_drift" | "test_manifest_hash_drift" => PluginFailureHint {
            code: "manifest_hash_drift",
            action: "reinstall_plugin_or_validate_local_files",
            priority: 2,
        },
        "verify_signature_hash_drift" | "test_signature_hash_drift" => PluginFailureHint {
            code: "signature_hash_drift",
            action: "restore_manifest_sig_or_reinstall_plugin",
            priority: 2,
        },
        "verify_version_drift" | "test_version_drift" => PluginFailureHint {
            code: "version_drift",
            action: "sync_lockfile_and_installed_plugin_version",
            priority: 3,
        },
        "verify_spec_invalid" => PluginFailureHint {
            code: "invalid_spec",
            action: "use_format_url_at_tag_or_commit",
            priority: 3,
        },
        "registry_source_missing" => PluginFailureHint {
            code: "invalid_spec",
            action: "set_registry_source_or_pass_source_flag",
            priority: 2,
        },
        "registry_source_fetch_failed"
        | "registry_signature_fetch_failed"
        | "registry_source_read_failed"
        | "registry_signature_read_failed" => PluginFailureHint {
            code: "registry_or_source_resolve_failed",
            action: "refresh_registry_or_validate_pack_id_and_version",
            priority: 2,
        },
        "registry_identity_invalid" | "registry_issuer_invalid" => PluginFailureHint {
            code: "trust_or_signature_failed",
            action: "check_sigstore_identity_and_trust_policy",
            priority: 1,
        },
        "registry_signature_verify_failed" => PluginFailureHint {
            code: "trust_or_signature_failed",
            action: "check_sigstore_identity_and_trust_policy",
            priority: 0,
        },
        "registry_index_parse_failed" => PluginFailureHint {
            code: "pack_load_failed",
            action: "fix_registry_index_format_and_retry",
            priority: 2,
        },
        "registry_freshness_failed" => PluginFailureHint {
            code: "aggregate_failed",
            action: "refresh_registry_or_adjust_staleness_policy",
            priority: 2,
        },
        "registry_write_failed" => PluginFailureHint {
            code: "aggregate_failed",
            action: "check_registry_cache_permissions_and_retry",
            priority: 2,
        },
        "preflight_pack_load_failed" | "install_pack_load_failed" | "verify_pack_load_failed" => {
            PluginFailureHint {
                code: "pack_load_failed",
                action: "validate_manifest_and_rule_files",
                priority: 2,
            }
        }
        "install_source_resolve_failed" => PluginFailureHint {
            code: "registry_or_source_resolve_failed",
            action: "refresh_registry_or_validate_pack_id_and_version",
            priority: 2,
        },
        "preflight_spec_invalid" | "install_spec_invalid" => PluginFailureHint {
            code: "invalid_spec",
            action: "use_format_url_at_tag_or_commit",
            priority: 3,
        },
        "install_trust_policy_invalid" => PluginFailureHint {
            code: "trust_policy_invalid",
            action: "fix_trust_config_and_retry",
            priority: 2,
        },
        "install_lockfile_load_failed" | "install_lockfile_save_failed" => PluginFailureHint {
            code: "lockfile_io_failed",
            action: "check_lockfile_path_permissions_and_retry",
            priority: 3,
        },
        "install_manifest_hash_failed" | "install_signature_hash_failed" => PluginFailureHint {
            code: "artifact_hash_failed",
            action: "verify_manifest_artifacts_and_retry",
            priority: 2,
        },
        "test_all_failed" | "preflight_all_failed" => PluginFailureHint {
            code: "aggregate_failed",
            action: "inspect_per_plugin_failure_rows",
            priority: 4,
        },
        _ => PluginFailureHint::unknown(),
    }
}

pub fn plugin_detail_code_from_drift_field(field: &str) -> Option<&'static str> {
    match field {
        "signature_or_trust" => Some("test_signature_or_trust_failed"),
        "core_compat" => Some("test_core_compat_failed"),
        "action_api" => Some("test_action_api_unsupported"),
        "os_targets" => Some("test_os_target_failed"),
        "resolved_rev" => Some("test_resolved_rev_drift"),
        "manifest_hash" => Some("test_manifest_hash_drift"),
        "signature_hash" => Some("test_signature_hash_drift"),
        "version" => Some("test_version_drift"),
        _ => None,
    }
}

pub fn plugin_primary_detail_code_from_drifts(drifts: &[PluginTestDrift]) -> Option<&'static str> {
    drifts
        .iter()
        .filter_map(|drift| {
            plugin_detail_code_from_drift_field(&drift.field).map(|code| {
                let priority = plugin_failure_hint_from_detail_code(code).priority;
                (priority, code)
            })
        })
        .min_by_key(|(priority, _)| *priority)
        .map(|(_, code)| code)
}

pub fn plugin_failure_hint_from_drift_field(field: &str) -> PluginFailureHint {
    match field {
        "signature_or_trust" => PluginFailureHint {
            code: "trust_or_signature_failed",
            action: "reverify_signature_and_identity_allowlist",
            priority: 0,
        },
        "core_compat" => PluginFailureHint {
            code: "core_compat_failed",
            action: "align_plugin_core_compat_with_runtime",
            priority: 1,
        },
        "action_api" => PluginFailureHint {
            code: "action_api_unsupported",
            action: "upgrade_plugin_or_runtime_action_api",
            priority: 1,
        },
        "os_targets" => PluginFailureHint {
            code: "os_target_failed",
            action: "install_plugin_that_supports_current_os",
            priority: 1,
        },
        "resolved_rev" => PluginFailureHint {
            code: "resolved_rev_drift",
            action: "reinstall_plugin_with_exact_pinned_commit",
            priority: 2,
        },
        "manifest_hash" => PluginFailureHint {
            code: "manifest_hash_drift",
            action: "reinstall_plugin_or_validate_local_files",
            priority: 2,
        },
        "signature_hash" => PluginFailureHint {
            code: "signature_hash_drift",
            action: "restore_manifest_sig_or_reinstall_plugin",
            priority: 2,
        },
        "version" => PluginFailureHint {
            code: "version_drift",
            action: "sync_lockfile_and_installed_plugin_version",
            priority: 3,
        },
        _ => PluginFailureHint::unknown(),
    }
}

pub fn plugin_primary_failure_hint_from_drifts(
    drifts: &[PluginTestDrift],
) -> Option<PluginFailureHint> {
    drifts
        .iter()
        .map(|drift| plugin_failure_hint_from_drift_field(&drift.field))
        .min_by_key(|hint| hint.priority)
}

pub fn plugin_failure_hint_message(code: &str, language: &str) -> String {
    let locale = normalize_language(language);
    match code {
        "trust_or_signature_failed" => {
            rust_i18n::t!("plugin.hints.trust_or_signature_failed", locale = locale).to_string()
        }
        "core_compat_failed" => {
            rust_i18n::t!("plugin.hints.core_compat_failed", locale = locale).to_string()
        }
        "action_api_unsupported" => {
            rust_i18n::t!("plugin.hints.action_api_unsupported", locale = locale).to_string()
        }
        "os_target_failed" => {
            rust_i18n::t!("plugin.hints.os_target_failed", locale = locale).to_string()
        }
        "source_checkout_failed" => {
            rust_i18n::t!("plugin.hints.source_checkout_failed", locale = locale).to_string()
        }
        "pack_load_failed" => {
            rust_i18n::t!("plugin.hints.pack_load_failed", locale = locale).to_string()
        }
        "invalid_spec" => rust_i18n::t!("plugin.hints.invalid_spec", locale = locale).to_string(),
        "aggregate_failed" => {
            rust_i18n::t!("plugin.hints.aggregate_failed", locale = locale).to_string()
        }
        "resolved_rev_drift" => {
            rust_i18n::t!("plugin.hints.resolved_rev_drift", locale = locale).to_string()
        }
        "manifest_hash_drift" => {
            rust_i18n::t!("plugin.hints.manifest_hash_drift", locale = locale).to_string()
        }
        "signature_hash_drift" => {
            rust_i18n::t!("plugin.hints.signature_hash_drift", locale = locale).to_string()
        }
        "version_drift" => rust_i18n::t!("plugin.hints.version_drift", locale = locale).to_string(),
        "registry_or_source_resolve_failed" => {
            rust_i18n::t!("plugin.hints.invalid_spec", locale = locale).to_string()
        }
        _ => rust_i18n::t!("plugin.hints.unknown_failure", locale = locale).to_string(),
    }
}

pub fn plugin_localized_error_message(
    detail_code: Option<&str>,
    message: &str,
    language: &str,
) -> String {
    let locale = normalize_language(language);
    if let Some(detail_code) = detail_code {
        if let Some(code) = PluginDetailCode::parse(detail_code) {
            if code.is_preflight_checkout_failure() {
                return rust_i18n::t!(
                    "plugin.errors.detail.preflight_clone_failed",
                    locale = locale
                )
                .to_string();
            }
            if code.is_install_checkout_failure() {
                return rust_i18n::t!("plugin.errors.detail.install_clone_failed", locale = locale)
                    .to_string();
            }
        }
        return match detail_code {
            "preflight_spec_invalid" => rust_i18n::t!(
                "plugin.errors.detail.preflight_spec_invalid",
                locale = locale
            )
            .to_string(),
            "preflight_pack_load_failed" => rust_i18n::t!(
                "plugin.errors.detail.preflight_pack_load_failed",
                locale = locale
            )
            .to_string(),
            "verify_pack_load_failed" => rust_i18n::t!(
                "plugin.errors.detail.preflight_pack_load_failed",
                locale = locale
            )
            .to_string(),
            "preflight_os_target_failed" => rust_i18n::t!(
                "plugin.errors.detail.preflight_os_target_failed",
                locale = locale
            )
            .to_string(),
            "preflight_core_compat_failed" => rust_i18n::t!(
                "plugin.errors.detail.preflight_core_compat_failed",
                locale = locale
            )
            .to_string(),
            "preflight_action_api_unsupported" => rust_i18n::t!(
                "plugin.errors.detail.preflight_action_api_unsupported",
                locale = locale
            )
            .to_string(),
            "preflight_signature_or_trust_failed" => rust_i18n::t!(
                "plugin.errors.detail.preflight_signature_or_trust_failed",
                locale = locale
            )
            .to_string(),
            "verify_signature_or_trust_failed" | "test_signature_or_trust_failed" => rust_i18n::t!(
                "plugin.errors.detail.preflight_signature_or_trust_failed",
                locale = locale
            )
            .to_string(),
            "verify_core_compat_failed" | "test_core_compat_failed" => rust_i18n::t!(
                "plugin.errors.detail.preflight_core_compat_failed",
                locale = locale
            )
            .to_string(),
            "verify_action_api_unsupported" | "test_action_api_unsupported" => rust_i18n::t!(
                "plugin.errors.detail.preflight_action_api_unsupported",
                locale = locale
            )
            .to_string(),
            "verify_os_target_failed" | "test_os_target_failed" => rust_i18n::t!(
                "plugin.errors.detail.preflight_os_target_failed",
                locale = locale
            )
            .to_string(),
            "test_all_failed" => {
                rust_i18n::t!("plugin.errors.detail.test_all_failed", locale = locale).to_string()
            }
            "preflight_all_failed" => {
                rust_i18n::t!("plugin.errors.detail.preflight_all_failed", locale = locale)
                    .to_string()
            }
            _ => message.to_string(),
        };
    }
    match message {
        "plugin not found" => {
            rust_i18n::t!("plugin.errors.message.plugin_not_found", locale = locale).to_string()
        }
        "unsupported action_api" => rust_i18n::t!(
            "plugin.errors.message.unsupported_action_api",
            locale = locale
        )
        .to_string(),
        "identity not allowed" => rust_i18n::t!(
            "plugin.errors.message.identity_not_allowed",
            locale = locale
        )
        .to_string(),
        "target is required unless --all is set" => rust_i18n::t!(
            "plugin.errors.message.target_required_unless_all",
            locale = locale
        )
        .to_string(),
        "spec is required unless --all is set" => rust_i18n::t!(
            "plugin.errors.message.spec_required_unless_all",
            locale = locale
        )
        .to_string(),
        _ => message.to_string(),
    }
}

pub fn plugin_error_kind_label(kind: &str, language: &str) -> String {
    let locale = normalize_language(language);
    match kind {
        "validation" => {
            rust_i18n::t!("plugin.errors.kind_labels.validation", locale = locale).to_string()
        }
        "not_found" => {
            rust_i18n::t!("plugin.errors.kind_labels.not_found", locale = locale).to_string()
        }
        "trust" => rust_i18n::t!("plugin.errors.kind_labels.trust", locale = locale).to_string(),
        "verification" => {
            rust_i18n::t!("plugin.errors.kind_labels.verification", locale = locale).to_string()
        }
        "io" => rust_i18n::t!("plugin.errors.kind_labels.io", locale = locale).to_string(),
        "network" => {
            rust_i18n::t!("plugin.errors.kind_labels.network", locale = locale).to_string()
        }
        "unsupported" => {
            rust_i18n::t!("plugin.errors.kind_labels.unsupported", locale = locale).to_string()
        }
        "internal" => {
            rust_i18n::t!("plugin.errors.kind_labels.internal", locale = locale).to_string()
        }
        _ => rust_i18n::t!("plugin.errors.kind_labels.internal", locale = locale).to_string(),
    }
}

fn normalize_language(language: &str) -> &'static str {
    let lower = language.to_lowercase();
    if lower.starts_with("de") {
        "de-DE"
    } else {
        "en-US"
    }
}

pub fn plugin_check_label(id: PluginCheckId, language: &str) -> String {
    let locale = normalize_language(language);
    match id {
        PluginCheckId::VersionMatchesLock => {
            rust_i18n::t!("plugin.checks.version_matches_lock", locale = locale).to_string()
        }
        PluginCheckId::SignatureVerified => {
            rust_i18n::t!("plugin.checks.signature_verified", locale = locale).to_string()
        }
        PluginCheckId::TrustVerified => {
            rust_i18n::t!("plugin.checks.trust_verified", locale = locale).to_string()
        }
        PluginCheckId::CoreCompatVerified => {
            rust_i18n::t!("plugin.checks.core_compat_verified", locale = locale).to_string()
        }
        PluginCheckId::ActionApiVerified => {
            rust_i18n::t!("plugin.checks.action_api_verified", locale = locale).to_string()
        }
        PluginCheckId::OsTargetVerified => {
            rust_i18n::t!("plugin.checks.os_target_verified", locale = locale).to_string()
        }
    }
}

pub fn plugin_check_severity(id: PluginCheckId) -> PluginCheckSeverity {
    match id {
        PluginCheckId::SignatureVerified | PluginCheckId::TrustVerified => {
            PluginCheckSeverity::Critical
        }
        PluginCheckId::CoreCompatVerified
        | PluginCheckId::ActionApiVerified
        | PluginCheckId::OsTargetVerified => PluginCheckSeverity::Warning,
        PluginCheckId::VersionMatchesLock => PluginCheckSeverity::Info,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliJsonEnvelope<T> {
    pub schema_version: u32,
    pub kind: String,
    pub data: T,
}

pub fn parse_cli_json_envelope(input: &str) -> Result<CliJsonEnvelope<serde_json::Value>, String> {
    serde_json::from_str(input).map_err(|e| format!("invalid json payload: {e}"))
}

pub fn parse_plugin_run_summary_from_cli_json(input: &str) -> Result<PluginRunSummary, String> {
    let envelope = parse_cli_json_envelope(input)?;
    let kind = envelope.kind.as_str();
    let data = &envelope.data;

    if kind == "error" {
        let detail_code = data
            .get("detail_code")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        return Ok(PluginRunSummary {
            overall_passed: false,
            duration_ms: 0,
            checks: Vec::new(),
            detail_code,
        });
    }

    let duration_ms = data
        .get("duration_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "missing duration_ms".to_string())?;
    let detail_code = data
        .get("detail_code")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let checks: Vec<PluginCheckStatus> = serde_json::from_value(
        data.get("checks")
            .cloned()
            .ok_or_else(|| "missing checks".to_string())?,
    )
    .map_err(|e| format!("invalid checks payload: {e}"))?;
    let overall_passed = match kind {
        "plugin.test" | "plugin.test_spec" => data
            .get("overall_passed")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| "missing overall_passed".to_string())?,
        "plugin.preflight" => checks.iter().all(|c| c.passed),
        _ => return Err(format!("unsupported kind: {kind}")),
    };
    Ok(PluginRunSummary {
        overall_passed,
        duration_ms,
        checks,
        detail_code,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginTestDrift {
    pub field: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginPreflightReport {
    pub spec: String,
    pub source: String,
    pub url: String,
    pub requested_rev: String,
    pub resolved_rev: String,
    pub pack_id: String,
    pub version: String,
    pub signature_verified: bool,
    pub trust_verified: bool,
    pub core_compat_verified: bool,
    pub action_api_verified: bool,
    pub os_target_verified: bool,
    pub checks: Vec<PluginCheckStatus>,
    pub suggested_actions: Vec<String>,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginPreflightFailure {
    pub spec: String,
    pub error_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginPreflightAllReport {
    pub overall_passed: bool,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<PluginPreflightReport>,
    pub failures: Vec<PluginPreflightFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginTestReport {
    pub pack_id: String,
    pub overall_passed: bool,
    pub version_matches_lock: bool,
    pub manifest_hash_verified: bool,
    pub signature_hash_verified: bool,
    pub resolved_rev_verified: bool,
    pub signature_verified: bool,
    pub trust_verified: bool,
    pub core_compat_verified: bool,
    pub action_api_verified: bool,
    pub os_target_verified: bool,
    pub checks: Vec<PluginCheckStatus>,
    pub suggested_actions: Vec<String>,
    pub duration_ms: u64,
    pub drifts: Vec<PluginTestDrift>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginTestFailure {
    pub pack_id: String,
    pub error_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginTestAllReport {
    pub overall_passed: bool,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<PluginTestReport>,
    pub failures: Vec<PluginTestFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginTestSpecReport {
    pub overall_passed: bool,
    pub spec: String,
    pub source: String,
    pub url: String,
    pub requested_rev: String,
    pub resolved_rev: String,
    pub pack_id: String,
    pub version: String,
    pub signature_verified: bool,
    pub trust_verified: bool,
    pub core_compat_verified: bool,
    pub action_api_verified: bool,
    pub os_target_verified: bool,
    pub checks: Vec<PluginCheckStatus>,
    pub suggested_actions: Vec<String>,
    pub duration_ms: u64,
}

pub trait SignatureVerifier {
    fn verify(&self, input: VerificationInput) -> Result<VerificationOutcome, VerifyError>;
}

impl TrustPolicy {
    pub fn is_identity_allowed(&self, identity: &str) -> bool {
        self.allowlist.iter().any(|item| item == identity)
    }
}

pub fn verify_with_policy(
    verifier: &dyn SignatureVerifier,
    policy: &TrustPolicy,
    input: VerificationInput,
) -> Result<VerificationOutcome, VerifyError> {
    let outcome = verifier.verify(input)?;
    if !policy.allowlist.is_empty() && !policy.is_identity_allowed(&outcome.identity) {
        return Err(VerifyError::NotTrusted {
            identity: outcome.identity,
        });
    }
    Ok(outcome)
}

impl FromStr for Manifest {
    type Err = ValidationError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let manifest: Manifest = toml::from_str(input).map_err(|e| ValidationError::Parse {
            context: "manifest".to_string(),
            message: e.to_string(),
        })?;
        manifest.validate_basic()?;
        Ok(manifest)
    }
}

impl Manifest {
    pub fn validate_basic(&self) -> Result<(), ValidationError> {
        if self.schema_version != MANIFEST_SCHEMA_V1 {
            return Err(ValidationError::SchemaVersionUnsupported {
                found: self.schema_version,
                expected: MANIFEST_SCHEMA_V1,
            });
        }
        if self.pack_id.trim().is_empty() {
            return Err(ValidationError::MissingField {
                field: "pack_id".to_string(),
            });
        }
        if self.name.trim().is_empty() {
            return Err(ValidationError::MissingField {
                field: "name".to_string(),
            });
        }
        if self.version.trim().is_empty() {
            return Err(ValidationError::MissingField {
                field: "version".to_string(),
            });
        }
        if self.core_compat.trim().is_empty() {
            return Err(ValidationError::MissingField {
                field: "core_compat".to_string(),
            });
        }
        if self.action_api == 0 {
            return Err(ValidationError::MissingField {
                field: "action_api".to_string(),
            });
        }
        if self.rules.is_empty() {
            return Err(ValidationError::MissingField {
                field: "rules".to_string(),
            });
        }

        let mut ids = HashSet::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                return Err(ValidationError::MissingField {
                    field: "rules[].id".to_string(),
                });
            }
            if !ids.insert(rule.id.clone()) {
                return Err(ValidationError::DuplicateRuleId {
                    id: rule.id.clone(),
                });
            }
            if rule.rule_file.trim().is_empty() {
                return Err(ValidationError::MissingField {
                    field: "rules[].rule_file".to_string(),
                });
            }
        }

        Ok(())
    }

    pub fn validate_with_core_version(&self, core_version: &str) -> Result<(), ValidationError> {
        self.validate_basic()?;
        let req = semver::VersionReq::parse(&self.core_compat).map_err(|e| {
            ValidationError::InvalidCoreCompat {
                message: e.to_string(),
            }
        })?;
        let version = semver::Version::parse(core_version).map_err(|e| {
            ValidationError::InvalidCoreCompat {
                message: e.to_string(),
            }
        })?;
        if !req.matches(&version) {
            return Err(ValidationError::InvalidCoreCompat {
                message: format!("core version {} not in {}", core_version, self.core_compat),
            });
        }
        Ok(())
    }
}

impl FromStr for RuleFile {
    type Err = ValidationError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let rule: RuleFile = toml::from_str(input).map_err(|e| ValidationError::Parse {
            context: "rule".to_string(),
            message: e.to_string(),
        })?;
        rule.validate_basic()?;
        Ok(rule)
    }
}

impl RuleFile {
    pub fn validate_basic(&self) -> Result<(), ValidationError> {
        if self.schema_version != RULE_SCHEMA_V1 {
            return Err(ValidationError::SchemaVersionUnsupported {
                found: self.schema_version,
                expected: RULE_SCHEMA_V1,
            });
        }
        if self.id.trim().is_empty() {
            return Err(ValidationError::MissingField {
                field: "id".to_string(),
            });
        }
        if self.name.trim().is_empty() {
            return Err(ValidationError::MissingField {
                field: "name".to_string(),
            });
        }
        self.matcher.validate_basic()?;
        self.action.validate_basic()?;
        Ok(())
    }
}

impl MatchSpec {
    pub fn validate_basic(&self) -> Result<(), ValidationError> {
        match self.mode {
            MatchMode::Paths => {
                if self.paths.is_empty() {
                    return Err(ValidationError::InvalidMatchSpec {
                        reason: "paths is empty".to_string(),
                    });
                }
            }
            MatchMode::Command => {
                if self.command.is_empty() {
                    return Err(ValidationError::InvalidMatchSpec {
                        reason: "command is empty".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl ActionSpec {
    pub fn validate_basic(&self) -> Result<(), ValidationError> {
        match self.action_type {
            ActionType::RunCommand => {
                if self.command.is_empty() {
                    return Err(ValidationError::InvalidActionSpec {
                        reason: "run_command requires command".to_string(),
                    });
                }
            }
            ActionType::TrashPaths
            | ActionType::DeletePaths
            | ActionType::PruneEmptyDirs
            | ActionType::ScanPaths
            | ActionType::MatchRegex
            | ActionType::OlderThanDays => {
                if self.paths.is_empty() {
                    return Err(ValidationError::InvalidActionSpec {
                        reason: "paths is empty".to_string(),
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }
}

pub fn validate_ruleset(manifest: &Manifest, rules: &[RuleFile]) -> Result<(), ValidationError> {
    let mut rule_map = HashSet::new();
    for rule in rules {
        rule_map.insert(rule.id.as_str());
    }
    for rule_ref in &manifest.rules {
        if !rule_map.contains(rule_ref.id.as_str()) {
            return Err(ValidationError::RuleRefMissing {
                id: rule_ref.id.clone(),
            });
        }
    }
    Ok(())
}
