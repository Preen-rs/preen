use async_trait::async_trait;
use std::fmt::{Display, Write as FmtWrite};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use clap::{Parser, Subcommand};
use preen_core::ItemCategory;
use preen_core::action_runtime::{
    ActionAuditEvent, ActionAuditSink, ActionExecutorPort, DefaultSafetyPolicy, ExecutionMode,
    RuntimeExecutionError, execute_action_with_audit, execution_error_detail_code,
    plan_error_detail_code,
};
use preen_core::error::CoreError;
use preen_core::metrics::NoopMetrics;
use preen_core::plugin::{
    ActionSpec, ActionType, Capability, CliJsonEnvelope, Manifest, MatchMode, MatchSpec, OsTarget,
    PluginCheckId, PluginCheckStatus, PluginFailureHint,
    PluginPreflightAllReport as PluginPreflightAllOutput,
    PluginPreflightFailure as PluginPreflightFailureOutput,
    PluginPreflightReport as PluginPreflightOutput, PluginTestAllReport as PluginTestAllOutput,
    PluginTestDrift, PluginTestFailure as PluginTestFailureOutput,
    PluginTestReport as PluginTestOutput, PluginTestSpecReport as PluginTestSpecOutput, RiskLevel,
    RuleFile, RuleRef, SignatureBundle, SignatureVerifier, TrustPolicy, VerificationInput,
    VerifyError, plugin_check_label, plugin_check_severity, plugin_error_kind_label,
    plugin_failure_hint_from_detail_code, plugin_failure_hint_message,
    plugin_localized_error_message, plugin_primary_detail_code_from_drifts,
    plugin_primary_failure_hint_from_drifts,
};
use preen_core::plugin_loader::{LoadedRulePack, load_rule_pack_from_dir};
use preen_core::plugin_lock::{LockedPlugin, PluginLockfile};
use preen_core::plugin_registry::{RegistryIndex, ResolvedRegistryPlugin};
use preen_core::rules::{ScanRule, ScanStrategy};
use preen_core::store::{ItemRecord, ScanRecord, ScanStorePort};
use preen_core::{
    FileSystemPort, ScanResult, config::AppConfig, system_error_kind_label,
    system_localized_error_message,
};
use preen_os::OsFileSystemAdapter;
use preen_os::action_executor::OsActionExecutor;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const REGISTRY_ALLOWED_IDENTITY_PREFIX: &str = "https://github.com/Preen-rs/";
const REGISTRY_ALLOWED_ISSUER: &str = "https://token.actions.githubusercontent.com";
const DEFAULT_REGISTRY_IDENTITY: &str =
    "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main";
const CLI_JSON_SCHEMA_V1: u32 = 1;
const ERROR_KIND_PREFIX: &str = "__preen_kind:";
const ERROR_CODE_TOKEN: &str = "preen_code:";
const DEFAULT_REGISTRY_MAX_AGE_DAYS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliErrorKind {
    Validation,
    NotFound,
    Trust,
    Verification,
    Io,
    Network,
    Unsupported,
    Internal,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{message}")]
pub struct CliError {
    pub kind: CliErrorKind,
    pub detail_code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ErrorOutput {
    error_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail_code: Option<String>,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PluginInfoOutput {
    pack_id: String,
    version: String,
    rev: String,
    source: String,
    url: String,
    manifest_hash: String,
    signature: String,
    trusted_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RegistrySearchOutput {
    pack_id: String,
    latest_version: String,
    description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PluginListItemOutput {
    pack_id: String,
    version: String,
    rev: String,
    source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PluginVerifyOutput {
    pack_id: String,
    manifest_hash_verified: bool,
    signature_hash_verified: bool,
    resolved_rev_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PluginInstallOutput {
    pack_id: String,
    version: String,
    source: String,
    rev: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CleanCommandOutput {
    mode: String,
    strategy: String,
    scanned_items: usize,
    target_count: usize,
    estimated_freed_bytes: u64,
    preview_paths: Vec<String>,
    affected_items: u64,
    freed_bytes: u64,
    risk_summary: CleanRiskSummary,
    warnings: Vec<String>,
    audit_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CleanRiskSummary {
    high_targets: usize,
    requires_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanSelectedItem {
    path: String,
    size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PluginRemoveOutput {
    pack_id: String,
    removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RegistryUpdateOutput {
    entries: usize,
    path: String,
    stale_mode: String,
    max_age_days: i64,
    source: String,
    used_signature_source: String,
    identity: String,
    issuer: String,
    strict_applied: bool,
    backup_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryStaleMode {
    Off,
    Warn,
    Error,
}

pub fn run(cli: Cli) -> Result<(), String> {
    run_typed(cli).map_err(|err| err.to_string())
}

pub fn run_typed(cli: Cli) -> Result<(), CliError> {
    let clean_executor = OsActionExecutor;
    run_typed_with_verifier_and_clean_executor(&cli, &SigstoreVerifier, &clean_executor)
}

fn run_typed_with_verifier(cli: &Cli, verifier: &dyn SignatureVerifier) -> Result<(), CliError> {
    let clean_executor = OsActionExecutor;
    run_typed_with_verifier_and_clean_executor(cli, verifier, &clean_executor)
}

fn run_typed_with_verifier_and_clean_executor(
    cli: &Cli,
    verifier: &dyn SignatureVerifier,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<(), CliError> {
    match &cli.command {
        CliCommand::Plugin { cmd } => run_plugin(cmd, verifier).map_err(CliError::from),
        CliCommand::Clean {
            dry_run,
            confirm,
            strategy,
            json,
        } => run_clean_with_executor(*dry_run, *confirm, *strategy, *json, clean_executor)
            .map_err(CliError::from),
        CliCommand::Uninstall { .. } => Err(command_not_implemented_error("uninstall")),
        CliCommand::Optimize { .. } => Err(command_not_implemented_error("optimize")),
        CliCommand::Analyze { .. } => Err(command_not_implemented_error("analyze")),
        CliCommand::Status { .. } => Err(command_not_implemented_error("status")),
        CliCommand::Purge { .. } => Err(command_not_implemented_error("purge")),
        CliCommand::Installer { .. } => Err(command_not_implemented_error("installer")),
        CliCommand::Check { .. } => Err(command_not_implemented_error("check")),
        CliCommand::Touchid { .. } => Err(command_not_implemented_error("touchid")),
        CliCommand::Completion { .. } => Err(command_not_implemented_error("completion")),
        CliCommand::Update { .. } => Err(command_not_implemented_error("update")),
        CliCommand::Remove { .. } => Err(command_not_implemented_error("remove")),
    }
}

pub fn run_typed_with_verifier_for_test(
    cli: Cli,
    verifier: &dyn SignatureVerifier,
) -> Result<(), CliError> {
    run_typed_with_verifier(&cli, verifier)
}

pub fn run_typed_with_verifier_and_clean_executor_for_test(
    cli: Cli,
    verifier: &dyn SignatureVerifier,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<(), CliError> {
    run_typed_with_verifier_and_clean_executor(&cli, verifier, clean_executor)
}

fn command_not_implemented_error(command: &str) -> CliError {
    CliError {
        kind: CliErrorKind::Unsupported,
        detail_code: Some("command_not_implemented".to_string()),
        message: format!("{command} command is not implemented yet"),
    }
}

fn run_plugin(cmd: &PluginCommand, verifier: &dyn SignatureVerifier) -> Result<(), String> {
    match cmd {
        PluginCommand::Install {
            spec,
            lockfile,
            json,
        } => install_plugin(spec, lockfile.clone(), *json, verifier),
        PluginCommand::Preflight {
            spec,
            all,
            lockfile,
            json,
        } => preflight_plugin(spec.as_deref(), *all, lockfile.clone(), *json, verifier),
        PluginCommand::List { lockfile, json } => list_plugins(lockfile.clone(), *json),
        PluginCommand::Info {
            pack_id,
            lockfile,
            json,
        } => info_plugin(pack_id, lockfile.clone(), *json),
        PluginCommand::Verify {
            pack_id,
            lockfile,
            json,
        } => verify_plugin(pack_id, lockfile.clone(), *json, verifier),
        PluginCommand::Test {
            target,
            all,
            lockfile,
            json,
        } => test_plugin(target.as_deref(), *all, lockfile.clone(), *json, verifier),
        PluginCommand::Update {
            pack_id,
            lockfile,
            json,
        } => update_plugin(pack_id, lockfile.clone(), *json, verifier),
        PluginCommand::Remove {
            pack_id,
            lockfile,
            json,
        } => remove_plugin(pack_id, lockfile.clone(), *json),
        PluginCommand::Search { query, json } => search_registry(query.clone(), *json),
        PluginCommand::RegistryUpdate {
            source,
            signature_source,
            identity,
            issuer,
            strict,
            json,
        } => update_registry_index(
            source.clone(),
            signature_source.clone(),
            identity.clone(),
            issuer.clone(),
            *strict,
            *json,
            verifier,
        ),
    }
}

#[derive(Default)]
struct CollectingAuditSink {
    events: Mutex<Vec<ActionAuditEvent>>,
}

impl CollectingAuditSink {
    fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl ActionAuditSink for CollectingAuditSink {
    fn record(&self, event: ActionAuditEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanStrategy {
    Delete,
    Trash,
}

impl CleanStrategy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Trash => "trash",
        }
    }

    const fn action_type(self) -> ActionType {
        match self {
            Self::Delete => ActionType::DeletePaths,
            Self::Trash => ActionType::TrashPaths,
        }
    }

    const fn capability(self) -> Capability {
        match self {
            Self::Delete => Capability::FsDelete,
            Self::Trash => Capability::FsTrash,
        }
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum CleanStrategyArg {
    Delete,
    Trash,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum TouchIdActionArg {
    Enable,
    Disable,
    Status,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum CompletionShellArg {
    Bash,
    Zsh,
    Fish,
}

#[derive(Default)]
struct EphemeralScanStore {
    items: Mutex<std::collections::HashMap<String, ItemRecord>>,
}

#[async_trait]
impl ScanStorePort for EphemeralScanStore {
    async fn save_scan(&self, _scan_id: &str, _result: &ScanResult) -> Result<(), CoreError> {
        Ok(())
    }

    async fn load_item(&self, item_id: &str) -> Result<Option<ItemRecord>, CoreError> {
        Ok(self.items.lock().unwrap().get(item_id).cloned())
    }

    async fn save_items(&self, items: &[ItemRecord]) -> Result<(), CoreError> {
        let mut guard = self.items.lock().unwrap();
        for item in items {
            guard.insert(item.item_id.clone(), item.clone());
        }
        Ok(())
    }

    async fn list_scans(&self, _limit: usize) -> Result<Vec<ScanRecord>, CoreError> {
        Ok(Vec::new())
    }

    async fn purge_scan(&self, _scan_id: &str) -> Result<(), CoreError> {
        Ok(())
    }
}

fn run_clean_with_executor(
    dry_run: bool,
    confirm: bool,
    strategy_arg: Option<CleanStrategyArg>,
    json: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<(), String> {
    let output = run_clean_output_with_executor(dry_run, confirm, strategy_arg, clean_executor)?;

    if json {
        println!(
            "{}",
            clean_json(output).map_err(|e| err_with(
                CliErrorKind::Internal,
                "clean json serialize failed",
                e
            ))?
        );
    } else if output.target_count == 0 {
        println!("clean completed: no cleanable items selected");
    } else {
        println!(
            "clean {} completed: strategy={} scanned={} targets={} estimated_freed_bytes={} affected_items={} freed_bytes={} audit_events={}",
            output.mode,
            output.strategy,
            output.scanned_items,
            output.target_count,
            format_bytes(output.estimated_freed_bytes),
            output.affected_items,
            format_bytes(output.freed_bytes),
            output.audit_events
        );
        println!(
            "risk: high_targets={} requires_confirmation={}",
            output.risk_summary.high_targets, output.risk_summary.requires_confirmation
        );
        for preview_item in &output.preview_paths {
            println!("selected: {preview_item}");
        }
        for warning in &output.warnings {
            println!("warning: {warning}");
        }
    }

    Ok(())
}

fn run_clean_output(
    dry_run: bool,
    confirm: bool,
    strategy_arg: Option<CleanStrategyArg>,
) -> Result<CleanCommandOutput, String> {
    let clean_executor = OsActionExecutor;
    run_clean_output_with_executor(dry_run, confirm, strategy_arg, &clean_executor)
}

fn run_clean_output_with_executor(
    dry_run: bool,
    confirm: bool,
    strategy_arg: Option<CleanStrategyArg>,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<CleanCommandOutput, String> {
    if !dry_run && !confirm {
        return Err(err_code(
            CliErrorKind::Validation,
            "clean_confirmation_required",
            "clean apply mode requires --confirm",
        ));
    }

    let clean_paths = normalize_clean_paths(resolve_clean_paths());
    if clean_paths.is_empty() {
        return Err(err_code(
            CliErrorKind::Unsupported,
            "clean_dry_run_unsupported_os",
            "clean dry-run is not supported on this OS",
        ));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| err_with(CliErrorKind::Internal, "tokio runtime init failed", e))?;
    let scan_result = runtime
        .block_on(scan_clean_candidates(&clean_paths))
        .map_err(|e| err_with(CliErrorKind::Internal, "clean scan failed", e))?;
    let selection = build_clean_selection(&scan_result, &clean_paths, clean_max_items());
    let selected_paths = selection
        .iter()
        .map(|item| item.path.clone())
        .collect::<Vec<_>>();
    let estimated_freed_bytes = selection.iter().map(|item| item.size).sum();
    enforce_clean_scope(&selected_paths, &clean_paths)?;
    let strategy = resolve_clean_strategy(strategy_arg);
    let preview = clean_preview_paths(&selected_paths, clean_preview_limit());
    let risk_summary = CleanRiskSummary {
        high_targets: selected_paths.len(),
        requires_confirmation: !dry_run,
    };

    if selected_paths.is_empty() {
        return Ok(CleanCommandOutput {
            mode: if dry_run {
                "dry_run".to_string()
            } else {
                "apply".to_string()
            },
            strategy: strategy.as_str().to_string(),
            scanned_items: scan_result.items.len(),
            target_count: 0,
            estimated_freed_bytes: 0,
            preview_paths: Vec::new(),
            affected_items: 0,
            freed_bytes: 0,
            risk_summary,
            warnings: vec!["no cleanable items selected".to_string()],
            audit_events: 0,
        });
    }

    let manifest = Manifest {
        schema_version: 1,
        pack_id: "preen.builtin.clean".to_string(),
        name: "Built-in Clean".to_string(),
        version: "0.1.0".to_string(),
        description: "Built-in clean dry-run plan".to_string(),
        author: "Preen".to_string(),
        license: "MIT".to_string(),
        homepage: None,
        core_compat: ">=0.1.0,<2.0.0".to_string(),
        action_api: 1,
        os_targets: vec![if cfg!(target_os = "macos") {
            OsTarget::Macos
        } else {
            OsTarget::Linux
        }],
        capabilities: vec![Capability::FsRead, strategy.capability()],
        signing: None,
        rules: vec![RuleRef {
            id: "builtin-clean".to_string(),
            name: "Built-in Clean".to_string(),
            rule_file: "builtin".to_string(),
        }],
    };
    let rule = RuleFile {
        schema_version: 1,
        id: "builtin-clean".to_string(),
        name: "Built-in Clean".to_string(),
        category: ItemCategory::Cache,
        risk: RiskLevel::High,
        enabled: true,
        matcher: MatchSpec {
            mode: MatchMode::Paths,
            paths: selected_paths.clone(),
            strategy: Some(ScanStrategy::Recursive),
            command: Vec::new(),
            parser: None,
        },
        action: ActionSpec {
            action_type: strategy.action_type(),
            paths: selected_paths.clone(),
            command: Vec::new(),
            mode: None,
            timeout_sec: Some(300),
            allow_globs: false,
            max_items: Some(10_000),
            package_manager: None,
            project_types: Vec::new(),
            params: std::collections::HashMap::new(),
        },
    };

    let policy = DefaultSafetyPolicy::default();
    let sink = CollectingAuditSink::default();
    let mode = if dry_run {
        ExecutionMode::DryRun
    } else {
        ExecutionMode::Apply
    };
    let result = runtime
        .block_on(execute_action_with_audit(
            &manifest,
            &rule,
            mode,
            if confirm { Some("confirmed") } else { None },
            &policy,
            clean_executor,
            Some(&sink),
        ))
        .map_err(map_clean_runtime_error)?;

    Ok(CleanCommandOutput {
        mode: if dry_run {
            "dry_run".to_string()
        } else {
            "apply".to_string()
        },
        strategy: strategy.as_str().to_string(),
        scanned_items: scan_result.items.len(),
        target_count: selected_paths.len(),
        estimated_freed_bytes,
        preview_paths: preview,
        affected_items: result.affected_items,
        freed_bytes: result.freed_bytes,
        risk_summary,
        warnings: result.warnings,
        audit_events: sink.event_count(),
    })
}

fn map_clean_runtime_error(error: RuntimeExecutionError) -> String {
    match error {
        RuntimeExecutionError::Plan(plan_error) => err_code(
            CliErrorKind::Validation,
            &format!("clean_{}", plan_error_detail_code(&plan_error)),
            plan_error.to_string(),
        ),
        RuntimeExecutionError::Execute(execution_error) => err_code(
            CliErrorKind::Internal,
            &format!("clean_{}", execution_error_detail_code(&execution_error)),
            execution_error.to_string(),
        ),
    }
}

fn clean_json(out: CleanCommandOutput) -> Result<String, String> {
    to_json_envelope("system.clean", out)
}

fn resolve_clean_paths() -> Vec<String> {
    if let Some(from_env) = std::env::var_os("PREEN_CLEAN_PATHS") {
        let out: Vec<String> = from_env
            .to_string_lossy()
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !out.is_empty() {
            return out;
        }
    }

    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    match std::env::consts::OS {
        "macos" => vec![
            home.join("Library")
                .join("Caches")
                .to_string_lossy()
                .to_string(),
        ],
        "linux" => vec![home.join(".cache").to_string_lossy().to_string()],
        _ => Vec::new(),
    }
}

fn clean_max_items() -> usize {
    std::env::var("PREEN_CLEAN_MAX_ITEMS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(10_000)
}

async fn scan_clean_candidates(clean_paths: &[String]) -> Result<ScanResult, CoreError> {
    let rules = clean_paths
        .iter()
        .enumerate()
        .map(|(idx, path)| ScanRule {
            id: format!("builtin-clean-{idx}"),
            name: "Built-in Clean Rule".to_string(),
            category: ItemCategory::Cache,
            path_pattern: path.clone(),
            strategy: ScanStrategy::Recursive,
            description: "Built-in clean scan rule".to_string(),
        })
        .collect::<Vec<_>>();
    let config = AppConfig {
        ignore_list: Vec::new(),
        follow_symlinks: false,
        max_scan_depth: None,
        allowlist: clean_paths.to_vec(),
        max_file_age_days: 30,
        scan_system_dirs: false,
        language: "en-US".to_string(),
    };
    let store: Arc<dyn ScanStorePort> = Arc::new(EphemeralScanStore::default());
    let metrics = Arc::new(NoopMetrics);
    let adapter = OsFileSystemAdapter::with_metrics(store, metrics);
    adapter.scan_cleanable_items(&rules, &config).await
}

fn build_clean_selection(
    scan_result: &ScanResult,
    roots: &[String],
    max_items: usize,
) -> Vec<CleanSelectedItem> {
    let mut items = scan_result.items.clone();
    items.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));

    let root_set = roots
        .iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    let mut seen = std::collections::HashSet::<String>::new();
    let mut selected: Vec<CleanSelectedItem> = Vec::new();
    for item in items {
        if selected.len() >= max_items {
            break;
        }
        let path = item.path.to_string_lossy().to_string();
        if root_set.contains(&path) {
            continue;
        }
        if !seen.insert(path.clone()) {
            continue;
        }
        selected.push(CleanSelectedItem {
            path,
            size: item.size,
        });
    }
    selected
}

fn resolve_clean_strategy(strategy_arg: Option<CleanStrategyArg>) -> CleanStrategy {
    if let Some(arg) = strategy_arg {
        return match arg {
            CleanStrategyArg::Delete => CleanStrategy::Delete,
            CleanStrategyArg::Trash => CleanStrategy::Trash,
        };
    }
    if let Ok(raw) = std::env::var("PREEN_CLEAN_STRATEGY") {
        return match raw.trim().to_ascii_lowercase().as_str() {
            "trash" => CleanStrategy::Trash,
            _ => CleanStrategy::Delete,
        };
    }
    CleanStrategy::Delete
}

fn clean_preview_limit() -> usize {
    std::env::var("PREEN_CLEAN_PREVIEW_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20)
}

fn clean_preview_paths(selected_paths: &[String], limit: usize) -> Vec<String> {
    selected_paths.iter().take(limit).cloned().collect()
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    const GB: f64 = 1024.0 * MB;
    let value = bytes as f64;
    if value >= GB {
        return format!("{:.2} GiB", value / GB);
    }
    if value >= MB {
        return format!("{:.2} MiB", value / MB);
    }
    if value >= KB {
        return format!("{:.2} KiB", value / KB);
    }
    format!("{bytes} B")
}

fn enforce_clean_scope(selected_paths: &[String], roots: &[String]) -> Result<(), String> {
    let canonical_roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| fs::canonicalize(root).ok())
        .collect();
    for path in selected_paths {
        let candidate = PathBuf::from(path);
        if !candidate.is_absolute() {
            return Err(err_code(
                CliErrorKind::Validation,
                "clean_relative_path",
                format!("selected clean path must be absolute: {path}"),
            ));
        }
        if candidate == PathBuf::from("/") {
            return Err(err_code(
                CliErrorKind::Validation,
                "clean_path_scope_violation",
                "selected clean path cannot be root",
            ));
        }
        if let Ok(meta) = fs::symlink_metadata(&candidate)
            && meta.file_type().is_symlink()
        {
            return Err(err_code(
                CliErrorKind::Validation,
                "clean_symlink_not_allowed",
                format!("selected clean path cannot be symlink: {path}"),
            ));
        }
        let Some(canonical) = fs::canonicalize(&candidate).ok() else {
            continue;
        };
        let in_scope = canonical_roots
            .iter()
            .any(|root| canonical.starts_with(root));
        if !in_scope {
            return Err(err_code(
                CliErrorKind::Validation,
                "clean_path_scope_violation",
                format!("selected clean path is outside configured roots: {path}"),
            ));
        }
    }
    Ok(())
}

fn normalize_clean_paths(paths: Vec<String>) -> Vec<String> {
    paths
        .into_iter()
        .map(|path| {
            let candidate = PathBuf::from(&path);
            if candidate.exists()
                && let Ok(canonical) = fs::canonicalize(&candidate)
            {
                return canonical.to_string_lossy().to_string();
            }
            path
        })
        .collect()
}

fn err(kind: CliErrorKind, message: impl Into<String>) -> String {
    let kind = kind.as_str();
    let message: String = message.into();
    format!("{ERROR_KIND_PREFIX}{kind}__{message}")
}

fn err_code(kind: CliErrorKind, detail_code: &str, message: impl Into<String>) -> String {
    let kind = kind.as_str();
    let message: String = message.into();
    format!("{ERROR_KIND_PREFIX}{kind}__{ERROR_CODE_TOKEN}{detail_code}__{message}")
}

fn decode_tagged_error(message: &str) -> Option<(CliErrorKind, Option<String>, String)> {
    let rest = message.strip_prefix(ERROR_KIND_PREFIX)?;
    let (kind_raw, detail) = rest.split_once("__")?;
    let kind = CliErrorKind::from_str(kind_raw)?;
    if let Some(detail_tail) = detail.strip_prefix(ERROR_CODE_TOKEN) {
        let (code, msg) = detail_tail.split_once("__")?;
        return Some((kind, Some(code.to_string()), msg.to_string()));
    }
    Some((kind, None, detail.to_string()))
}

fn err_with<E: Display>(kind: CliErrorKind, context: &str, source: E) -> String {
    err(kind, format!("{context}: {source}"))
}

fn install_plugin(
    spec: &str,
    lockfile: Option<PathBuf>,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let locked = install_plugin_internal_with_verifier(spec, lockfile, verifier)?;
    if json {
        println!(
            "{}",
            plugin_install_json(PluginInstallOutput {
                pack_id: locked.pack_id,
                version: locked.version,
                source: locked.source,
                rev: locked.rev,
            })?
        );
    }
    Ok(())
}

fn preflight_plugin(
    spec: Option<&str>,
    all: bool,
    lockfile: Option<PathBuf>,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    if all {
        return preflight_all_plugins(lockfile, json, verifier);
    }
    let spec = spec.ok_or_else(|| {
        err(
            CliErrorKind::Validation,
            "spec is required unless --all is set",
        )
    })?;
    let out = preflight_single(spec, verifier)?;
    if json {
        println!("{}", plugin_preflight_json(out)?);
        return Ok(());
    }
    print_preflight_output(&out);
    Ok(())
}

fn preflight_all_plugins(
    lockfile: Option<PathBuf>,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let out = build_preflight_all_output(lockfile.as_deref(), verifier)?;
    if json {
        println!("{}", plugin_preflight_all_json(out.clone())?);
    } else {
        let language = cli_language();
        println!(
            "summary: kind=preflight_all overall_passed={} total={} passed={} failed={} summary_label={}",
            out.overall_passed,
            out.total,
            out.passed,
            out.failed,
            cli_label(&language, "summary")
        );
        for result in &out.results {
            print_preflight_output(result);
        }
        if out.failures.is_empty() {
            println!(
                "failures: [] failures_label={}",
                cli_label(&language, "failures")
            );
        } else {
            for failure in &out.failures {
                println!("{}", format_preflight_failure_row(failure, &language));
            }
        }
    }
    if !out.overall_passed {
        return Err(err_code(
            CliErrorKind::Verification,
            "preflight_all_failed",
            format!("{} plugin preflight checks failed", out.failures.len()),
        ));
    }
    Ok(())
}

fn build_preflight_all_output(
    lockfile: Option<&Path>,
    verifier: &dyn SignatureVerifier,
) -> Result<PluginPreflightAllOutput, String> {
    let lock = load_lockfile(lockfile)?;
    let mut results = Vec::with_capacity(lock.plugins.len());
    let mut failures = Vec::new();
    for plugin in &lock.plugins {
        let spec = format!("{}@{}", plugin.url, plugin.rev);
        match preflight_single(&spec, verifier) {
            Ok(out) => results.push(out),
            Err(error) => {
                let (error_kind, detail_code, message) = parse_error_metadata(&error);
                failures.push(PluginPreflightFailureOutput {
                    spec,
                    error_kind,
                    detail_code,
                    message,
                });
            }
        }
    }
    let passed = results.len();
    let failed = failures.len();
    Ok(PluginPreflightAllOutput {
        overall_passed: failures.is_empty(),
        total: passed + failed,
        passed,
        failed,
        results,
        failures,
    })
}

fn preflight_single(
    spec: &str,
    verifier: &dyn SignatureVerifier,
) -> Result<PluginPreflightOutput, String> {
    let started = Instant::now();
    let parsed = parse_plugin_spec(spec)
        .map_err(|e| err_code(CliErrorKind::Validation, "preflight_spec_invalid", e))?;
    let (source, url, rev) = resolve_install_source(parsed)?;
    let temp_dir = TempDir::new()
        .map_err(|e| err_with(CliErrorKind::Io, "preflight temp dir create failed", e))?;
    let pack_dir = temp_dir.path().join("repo");
    let resolved_rev = clone_rule_pack_at(&url, &rev, &pack_dir, "preflight_clone_failed")?;
    let loaded = load_rule_pack_from_dir(&pack_dir).map_err(|e| {
        err_code(
            CliErrorKind::Validation,
            "preflight_pack_load_failed",
            format!("load failed: {e:?}"),
        )
    })?;
    validate_os_targets(&loaded)
        .map_err(|e| err_code(CliErrorKind::Validation, "preflight_os_target_failed", e))?;
    loaded
        .manifest
        .validate_with_core_version("0.1.0")
        .map_err(|e| {
            err_code(
                CliErrorKind::Validation,
                "preflight_core_compat_failed",
                format!("core compatibility check failed: {e:?}"),
            )
        })?;
    if loaded.manifest.action_api != 1 {
        return Err(err_code(
            CliErrorKind::Validation,
            "preflight_action_api_unsupported",
            "unsupported action_api",
        ));
    }
    let trust = load_trust_policy()?;
    verify_rule_pack_with_verifier(&loaded, &trust, verifier).map_err(|e| {
        err_code(
            CliErrorKind::Verification,
            "preflight_signature_or_trust_failed",
            e,
        )
    })?;
    Ok(PluginPreflightOutput {
        spec: spec.to_string(),
        source,
        url,
        requested_rev: rev,
        resolved_rev,
        pack_id: loaded.manifest.pack_id.clone(),
        version: loaded.manifest.version.clone(),
        signature_verified: true,
        trust_verified: true,
        core_compat_verified: true,
        action_api_verified: true,
        os_target_verified: true,
        checks: build_plugin_checks(true, true, true, true, true, None),
        duration_ms: started.elapsed().as_millis() as u64,
        detail_code: None,
    })
}

fn print_preflight_output(out: &PluginPreflightOutput) {
    println!("summary: kind=preflight overall_passed=true");
    println!("spec: {}", out.spec);
    println!("source: {}", out.source);
    println!("url: {}", out.url);
    println!("requested_rev: {}", out.requested_rev);
    println!("resolved_rev: {}", out.resolved_rev);
    println!("pack_id: {}", out.pack_id);
    println!("version: {}", out.version);
    println!("duration_ms: {}", out.duration_ms);
    let language = cli_language();
    print_check_rows(&out.checks, &language);
}

fn install_plugin_internal_with_verifier(
    spec: &str,
    lockfile: Option<PathBuf>,
    verifier: &dyn SignatureVerifier,
) -> Result<LockedPlugin, String> {
    let install_dir = ensure_install_base_dir()?;
    install_plugin_internal_in_dir(spec, lockfile, &install_dir, verifier)
}

fn install_plugin_internal_in_dir(
    spec: &str,
    lockfile: Option<PathBuf>,
    install_dir: &Path,
    verifier: &dyn SignatureVerifier,
) -> Result<LockedPlugin, String> {
    let parsed = parse_plugin_spec(spec)?;
    let (source, url, rev) = resolve_install_source(parsed)?;
    let mut lock = load_lockfile(lockfile.as_deref())?;
    fs::create_dir_all(install_dir)
        .map_err(|e| err_with(CliErrorKind::Io, "plugin base dir create failed", e))?;
    let temp_dir = TempDir::new_in(install_dir)
        .map_err(|e| err_with(CliErrorKind::Io, "temp dir create failed", e))?;
    let pack_dir = temp_dir.path().join("repo");
    let resolved_rev = clone_rule_pack_at(&url, &rev, &pack_dir, "install_clone_failed")?;
    let loaded = load_rule_pack_from_dir(&pack_dir)
        .map_err(|e| err(CliErrorKind::Validation, format!("load failed: {e:?}")))?;
    validate_os_targets(&loaded)?;
    let trust = load_trust_policy()?;
    verify_rule_pack_with_verifier(&loaded, &trust, verifier)?;
    let manifest_hash = hash_file(&pack_dir.join("manifest.toml"))?;
    let signature_hash = hash_file(&pack_dir.join("manifest.sig"))?;

    let final_dir = install_dir.join(&loaded.manifest.pack_id);
    if final_dir.exists() {
        fs::remove_dir_all(&final_dir)
            .map_err(|e| err_with(CliErrorKind::Io, "existing plugin remove failed", e))?;
    }
    fs::rename(&pack_dir, &final_dir)
        .map_err(|e| err_with(CliErrorKind::Io, "plugin move failed", e))?;
    temp_dir
        .close()
        .map_err(|e| err_with(CliErrorKind::Io, "temp dir close failed", e))?;
    let locked = LockedPlugin {
        pack_id: loaded.manifest.pack_id.clone(),
        source,
        url,
        rev,
        resolved_rev: Some(resolved_rev),
        version: loaded.manifest.version.clone(),
        manifest_hash,
        signature: signature_hash,
        trusted_identity: loaded
            .manifest
            .signing
            .as_ref()
            .and_then(|s| s.identity.clone())
            .unwrap_or_default(),
    };
    upsert_lockfile(&mut lock, locked.clone());
    save_lockfile(lockfile.as_deref(), &lock)?;
    Ok(locked)
}

fn list_plugins(lockfile: Option<PathBuf>, json: bool) -> Result<(), String> {
    let lock = load_lockfile(lockfile.as_deref())?;
    if json {
        println!("{}", plugin_list_json(&lock.plugins)?);
        return Ok(());
    }
    for plugin in lock.plugins {
        println!("{} {} {}", plugin.pack_id, plugin.version, plugin.rev);
    }
    Ok(())
}

fn info_plugin(pack_id: &str, lockfile: Option<PathBuf>, json: bool) -> Result<(), String> {
    let lock = load_lockfile(lockfile.as_deref())?;
    let plugin = lock
        .plugins
        .iter()
        .find(|p| p.pack_id == pack_id)
        .ok_or_else(|| err(CliErrorKind::NotFound, "plugin not found"))?;
    if json {
        println!("{}", plugin_info_json(plugin)?);
        return Ok(());
    }
    println!("pack_id: {}", plugin.pack_id);
    println!("version: {}", plugin.version);
    println!("rev: {}", plugin.rev);
    println!("source: {}", plugin.source);
    println!("url: {}", plugin.url);
    println!("manifest_hash: {}", plugin.manifest_hash);
    println!("signature: {}", plugin.signature);
    println!("trusted_identity: {}", plugin.trusted_identity);
    Ok(())
}

fn verify_plugin(
    pack_id: &str,
    lockfile: Option<PathBuf>,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let checks = plugin_checks(pack_id, lockfile, verifier)?;
    if json {
        println!(
            "{}",
            plugin_verify_json(PluginVerifyOutput {
                pack_id: checks.pack_id,
                manifest_hash_verified: checks.manifest_hash_verified,
                signature_hash_verified: checks.signature_hash_verified,
                resolved_rev_verified: checks.resolved_rev_verified,
            })?
        );
        return Ok(());
    }
    let language = cli_language();
    print_plugin_verify_output(&checks, &language);
    Ok(())
}

fn test_plugin(
    pack_id: Option<&str>,
    all: bool,
    lockfile: Option<PathBuf>,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    if all {
        return test_all_plugins(lockfile, json, verifier);
    }
    let target = pack_id.ok_or_else(|| {
        err(
            CliErrorKind::Validation,
            "target is required unless --all is set",
        )
    })?;
    if parse_plugin_spec(target).is_ok() {
        return test_plugin_spec(target, json, verifier);
    }
    let pack_id = target;
    let checks = plugin_test_report(pack_id, lockfile, verifier)?;
    if json {
        println!("{}", plugin_test_json(checks)?);
        return Ok(());
    }
    let language = cli_language();
    print_plugin_test_output(&checks, &language);
    Ok(())
}

fn cli_language() -> String {
    std::env::var("PREEN_LANG")
        .or_else(|_| std::env::var("PREEN_LANGUAGE"))
        .unwrap_or_else(|_| "en-US".to_string())
}

fn cli_locale(language: &str) -> &'static str {
    let lower = language.to_lowercase();
    if lower.starts_with("de") {
        "de-DE"
    } else {
        "en-US"
    }
}

fn cli_label(language: &str, key: &str) -> &'static str {
    match (cli_locale(language), key) {
        ("de-DE", "summary") => "Zusammenfassung",
        ("de-DE", "verify") => "Verifizierung",
        ("de-DE", "checks") => "Pruefungen",
        ("de-DE", "drifts") => "Abweichungen",
        ("de-DE", "failures") => "Fehler",
        ("de-DE", "primary_failure") => "Hauptfehler",
        (_, "summary") => "Summary",
        (_, "verify") => "Verification",
        (_, "checks") => "Checks",
        (_, "drifts") => "Drifts",
        (_, "failures") => "Failures",
        (_, "primary_failure") => "Primary failure",
        _ => "Label",
    }
}

fn format_human_error(err: &CliError, language: &str) -> String {
    let is_system_error = is_system_detail_code(err.detail_code.as_deref());
    let message = if is_system_error {
        system_localized_error_message(err.detail_code.as_deref(), &err.message, language)
    } else {
        plugin_localized_error_message(err.detail_code.as_deref(), &err.message, language)
    };
    let kind_label = if is_system_error {
        system_error_kind_label(err.kind.as_str(), language)
    } else {
        plugin_error_kind_label(err.kind.as_str(), language)
    };
    let mut line = format!(
        "error: kind={} kind_label={} message={}",
        err.kind.as_str(),
        kind_label,
        message
    );
    if let Some(detail_code) = &err.detail_code {
        line.push_str(&format!(" detail_code={detail_code}"));
        if !is_system_error {
            let hint = plugin_failure_hint_from_detail_code(detail_code);
            line.push_str(&format!(" hint_code={}", hint.code));
            line.push_str(&format!(" hint_action={}", hint.action));
            line.push_str(&format!(
                " hint_message={}",
                plugin_failure_hint_message(hint.code, language)
            ));
        }
    }
    line
}

fn is_system_detail_code(code: Option<&str>) -> bool {
    match code {
        Some("command_not_implemented") => true,
        Some(value) if value.starts_with("clean_") => true,
        _ => false,
    }
}

fn test_plugin_spec(
    spec: &str,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let out = preflight_single(spec, verifier)?;
    let test = PluginTestSpecOutput {
        overall_passed: true,
        spec: out.spec,
        source: out.source,
        url: out.url,
        requested_rev: out.requested_rev,
        resolved_rev: out.resolved_rev,
        pack_id: out.pack_id,
        version: out.version,
        signature_verified: out.signature_verified,
        trust_verified: out.trust_verified,
        core_compat_verified: out.core_compat_verified,
        action_api_verified: out.action_api_verified,
        os_target_verified: out.os_target_verified,
        checks: out.checks,
        duration_ms: out.duration_ms,
    };
    if json {
        println!("{}", plugin_test_spec_json(test)?);
        return Ok(());
    }
    println!(
        "summary: kind=test_spec overall_passed={}",
        test.overall_passed
    );
    println!("spec: {}", test.spec);
    println!("source: {}", test.source);
    println!("url: {}", test.url);
    println!("requested_rev: {}", test.requested_rev);
    println!("resolved_rev: {}", test.resolved_rev);
    println!("pack_id: {}", test.pack_id);
    println!("version: {}", test.version);
    println!("duration_ms: {}", test.duration_ms);
    let language = cli_language();
    print_check_rows(&test.checks, &language);
    Ok(())
}

fn test_all_plugins(
    lockfile: Option<PathBuf>,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let out = build_test_all_output(lockfile.as_deref(), None, verifier)?;
    if json {
        println!("{}", plugin_test_all_json(out.clone())?);
    } else {
        let language = cli_language();
        println!(
            "summary: kind=test_all overall_passed={} total={} passed={} failed={} summary_label={}",
            out.overall_passed,
            out.total,
            out.passed,
            out.failed,
            cli_label(&language, "summary")
        );
        for result in &out.results {
            print_plugin_test_output(result, &language);
        }
        if out.failures.is_empty() {
            println!(
                "failures: [] failures_label={}",
                cli_label(&language, "failures")
            );
        } else {
            for failure in &out.failures {
                println!("{}", format_test_failure_row(failure, &language));
            }
        }
    }
    if !out.overall_passed {
        return Err(err_code(
            CliErrorKind::Verification,
            "test_all_failed",
            format!("{} plugin test checks failed", out.failed),
        ));
    }
    Ok(())
}

fn build_test_all_output(
    lockfile: Option<&Path>,
    install_dir: Option<&Path>,
    verifier: &dyn SignatureVerifier,
) -> Result<PluginTestAllOutput, String> {
    let lock = load_lockfile(lockfile)?;
    let mut results = Vec::with_capacity(lock.plugins.len());
    let mut failures = Vec::new();
    for plugin in &lock.plugins {
        let report_result = if let Some(dir) = install_dir {
            plugin_test_report_in_dir(&plugin.pack_id, lockfile, dir, verifier)
        } else {
            plugin_test_report(&plugin.pack_id, lockfile.map(|p| p.to_path_buf()), verifier)
        };
        match report_result {
            Ok(report) => {
                if !report.overall_passed {
                    failures.push(plugin_test_failure_from_report(&report));
                }
                results.push(report);
            }
            Err(error) => {
                let (error_kind, detail_code, message) = parse_error_metadata(&error);
                failures.push(PluginTestFailureOutput {
                    pack_id: plugin.pack_id.clone(),
                    error_kind,
                    detail_code,
                    message,
                });
            }
        }
    }
    let total = lock.plugins.len();
    let failed = failures.len();
    let passed = total.saturating_sub(failed);
    Ok(PluginTestAllOutput {
        overall_passed: failed == 0,
        total,
        passed,
        failed,
        results,
        failures,
    })
}

fn plugin_test_failure_from_report(report: &PluginTestOutput) -> PluginTestFailureOutput {
    let detail_code = report
        .detail_code
        .clone()
        .or_else(|| plugin_primary_detail_code_from_drifts(&report.drifts).map(ToOwned::to_owned));
    let message = detail_code
        .clone()
        .map(|code| format!("plugin test report failed: {code}"))
        .unwrap_or_else(|| "plugin test report failed".to_string());
    PluginTestFailureOutput {
        pack_id: report.pack_id.clone(),
        error_kind: CliErrorKind::Verification.as_str().to_string(),
        detail_code,
        message,
    }
}

fn check_id_key(id: PluginCheckId) -> &'static str {
    match id {
        PluginCheckId::VersionMatchesLock => "version_matches_lock",
        PluginCheckId::SignatureVerified => "signature_verified",
        PluginCheckId::TrustVerified => "trust_verified",
        PluginCheckId::CoreCompatVerified => "core_compat_verified",
        PluginCheckId::ActionApiVerified => "action_api_verified",
        PluginCheckId::OsTargetVerified => "os_target_verified",
    }
}

fn print_check_rows(checks: &[PluginCheckStatus], language: &str) {
    println!("checks: label={}", cli_label(language, "checks"));
    for check in checks {
        println!(
            "check: id={} label={} severity={} passed={}",
            check_id_key(check.check),
            plugin_check_label(check.check, language),
            plugin_check_severity(check.check).as_str(),
            check.passed
        );
    }
}

fn print_plugin_test_output(report: &PluginTestOutput, language: &str) {
    print!("{}", format_plugin_test_output(report, language));
}

fn format_plugin_test_output(report: &PluginTestOutput, language: &str) -> String {
    let mut out = String::new();
    writeln!(
        &mut out,
        "summary: kind=test pack_id={} overall_passed={} duration_ms={} summary_label={}",
        report.pack_id,
        report.overall_passed,
        report.duration_ms,
        cli_label(language, "summary")
    )
    .expect("writing to String should be infallible");
    writeln!(
        &mut out,
        "verify: version_matches_lock={} manifest_hash_verified={} signature_hash_verified={} resolved_rev_verified={} verify_label={}",
        report.version_matches_lock,
        report.manifest_hash_verified,
        report.signature_hash_verified,
        report.resolved_rev_verified,
        cli_label(language, "verify")
    )
    .expect("writing to String should be infallible");
    writeln!(&mut out, "checks: label={}", cli_label(language, "checks"))
        .expect("writing to String should be infallible");
    for check in &report.checks {
        writeln!(
            &mut out,
            "check: id={} label={} severity={} passed={}",
            check_id_key(check.check),
            plugin_check_label(check.check, language),
            plugin_check_severity(check.check).as_str(),
            check.passed
        )
        .expect("writing to String should be infallible");
    }
    if report.drifts.is_empty() {
        writeln!(
            &mut out,
            "drifts: [] drifts_label={}",
            cli_label(language, "drifts")
        )
        .expect("writing to String should be infallible");
    } else {
        for drift in &report.drifts {
            writeln!(
                &mut out,
                "drift: field={} expected={} actual={}",
                drift.field, drift.expected, drift.actual
            )
            .expect("writing to String should be infallible");
        }
    }
    if !report.overall_passed {
        if let Some(detail_code) = report.detail_code.as_deref() {
            let hint = plugin_failure_hint_from_detail_code(detail_code);
            writeln!(
                &mut out,
                "primary_failure: detail_code={} hint_code={} hint_action={} hint_message={} label={}",
                detail_code,
                hint.code,
                hint.action,
                plugin_failure_hint_message(hint.code, language),
                cli_label(language, "primary_failure")
            )
            .expect("writing to String should be infallible");
        } else if let Some(hint) = plugin_primary_failure_hint_from_drifts(&report.drifts) {
            writeln!(
                &mut out,
                "primary_failure: hint_code={} hint_action={} hint_message={} label={}",
                hint.code,
                hint.action,
                plugin_failure_hint_message(hint.code, language),
                cli_label(language, "primary_failure")
            )
            .expect("writing to String should be infallible");
        }
    }
    out
}

fn format_plugin_verify_output(report: &PluginTestOutput, language: &str) -> String {
    let mut out = String::new();
    writeln!(
        &mut out,
        "summary: kind=verify pack_id={} overall_passed={} duration_ms={} summary_label={}",
        report.pack_id,
        report.overall_passed,
        report.duration_ms,
        cli_label(language, "summary")
    )
    .expect("writing to String should be infallible");
    writeln!(
        &mut out,
        "verify: version_matches_lock={} manifest_hash_verified={} signature_hash_verified={} resolved_rev_verified={} verify_label={}",
        report.version_matches_lock,
        report.manifest_hash_verified,
        report.signature_hash_verified,
        report.resolved_rev_verified,
        cli_label(language, "verify")
    )
    .expect("writing to String should be infallible");
    writeln!(&mut out, "checks: label={}", cli_label(language, "checks"))
        .expect("writing to String should be infallible");
    for check in &report.checks {
        writeln!(
            &mut out,
            "check: id={} label={} severity={} passed={}",
            check_id_key(check.check),
            plugin_check_label(check.check, language),
            plugin_check_severity(check.check).as_str(),
            check.passed
        )
        .expect("writing to String should be infallible");
    }
    out
}

fn print_plugin_verify_output(report: &PluginTestOutput, language: &str) {
    print!("{}", format_plugin_verify_output(report, language));
}

fn format_preflight_failure_row(failure: &PluginPreflightFailureOutput, language: &str) -> String {
    let hint = failure
        .detail_code
        .as_deref()
        .map(plugin_failure_hint_from_detail_code)
        .unwrap_or(PluginFailureHint::unknown());
    format!(
        "failure: spec={} error_kind={} detail_code={} message={} hint_code={} hint_action={} hint_message={}",
        failure.spec,
        failure.error_kind,
        failure
            .detail_code
            .clone()
            .unwrap_or_else(|| "none".to_string()),
        failure.message,
        hint.code,
        hint.action,
        plugin_failure_hint_message(hint.code, language)
    )
}

fn format_test_failure_row(failure: &PluginTestFailureOutput, language: &str) -> String {
    let hint = failure
        .detail_code
        .as_deref()
        .map(plugin_failure_hint_from_detail_code)
        .unwrap_or(PluginFailureHint::unknown());
    format!(
        "failure: pack_id={} error_kind={} detail_code={} message={} hint_code={} hint_action={} hint_message={}",
        failure.pack_id,
        failure.error_kind,
        failure
            .detail_code
            .clone()
            .unwrap_or_else(|| "none".to_string()),
        failure.message,
        hint.code,
        hint.action,
        plugin_failure_hint_message(hint.code, language)
    )
}

fn parse_error_metadata(message: &str) -> (String, Option<String>, String) {
    if let Some((kind, detail_code, msg)) = decode_tagged_error(message) {
        return (kind.as_str().to_string(), detail_code, msg);
    }
    (
        CliErrorKind::Internal.as_str().to_string(),
        None,
        message.to_string(),
    )
}

fn plugin_checks(
    pack_id: &str,
    lockfile: Option<PathBuf>,
    verifier: &dyn SignatureVerifier,
) -> Result<PluginTestOutput, String> {
    let base_dir = ensure_install_base_dir()?;
    plugin_checks_in_dir(pack_id, lockfile.as_deref(), &base_dir, verifier)
}

fn plugin_checks_in_dir(
    pack_id: &str,
    lockfile: Option<&Path>,
    base_dir: &Path,
    verifier: &dyn SignatureVerifier,
) -> Result<PluginTestOutput, String> {
    let started = Instant::now();
    let lock = load_lockfile(lockfile)?;
    let plugin = lock
        .plugins
        .iter()
        .find(|p| p.pack_id == pack_id)
        .ok_or_else(|| err(CliErrorKind::NotFound, "plugin not found"))?;
    let pack_dir = base_dir.join(&plugin.pack_id);
    let loaded = load_rule_pack_from_dir(&pack_dir).map_err(|e| {
        err_code(
            CliErrorKind::Validation,
            "verify_pack_load_failed",
            format!("load failed: {e:?}"),
        )
    })?;
    let trust = load_trust_policy()?;
    verify_rule_pack_with_verifier(&loaded, &trust, verifier).map_err(|e| {
        err_code(
            CliErrorKind::Verification,
            "verify_signature_or_trust_failed",
            e,
        )
    })?;
    if loaded.manifest.version != plugin.version {
        return Err(err_code(
            CliErrorKind::Verification,
            "verify_version_drift",
            format!(
                "version mismatch: expected={}, actual={}",
                plugin.version, loaded.manifest.version
            ),
        ));
    }
    loaded
        .manifest
        .validate_with_core_version("0.1.0")
        .map_err(|e| {
            err_code(
                CliErrorKind::Validation,
                "verify_core_compat_failed",
                format!("core compatibility check failed: {e:?}"),
            )
        })?;
    if loaded.manifest.action_api != 1 {
        return Err(err_code(
            CliErrorKind::Validation,
            "verify_action_api_unsupported",
            "unsupported action_api",
        ));
    }
    validate_os_targets(&loaded)
        .map_err(|e| err_code(CliErrorKind::Validation, "verify_os_target_failed", e))?;
    let mut resolved_rev_verified = true;
    if let Some(expected) = &plugin.resolved_rev {
        let head = git_resolve_head(&pack_dir)?;
        if &head != expected {
            return Err(err_code(
                CliErrorKind::Verification,
                "verify_resolved_rev_drift",
                format!("git head mismatch: expected={}, actual={}", expected, head),
            ));
        }
        resolved_rev_verified = true;
    }
    let manifest_hash = hash_file(&pack_dir.join("manifest.toml"))?;
    if manifest_hash != plugin.manifest_hash {
        return Err(err_code(
            CliErrorKind::Verification,
            "verify_manifest_hash_drift",
            format!(
                "manifest hash mismatch: expected={}, actual={}",
                plugin.manifest_hash, manifest_hash
            ),
        ));
    }
    let signature_hash = hash_file(&pack_dir.join("manifest.sig"))?;
    if signature_hash != plugin.signature {
        return Err(err_code(
            CliErrorKind::Verification,
            "verify_signature_hash_drift",
            format!(
                "signature hash mismatch: expected={}, actual={}",
                plugin.signature, signature_hash
            ),
        ));
    }
    Ok(PluginTestOutput {
        pack_id: plugin.pack_id.clone(),
        overall_passed: true,
        version_matches_lock: true,
        manifest_hash_verified: true,
        signature_hash_verified: true,
        resolved_rev_verified,
        signature_verified: true,
        trust_verified: true,
        core_compat_verified: true,
        action_api_verified: true,
        os_target_verified: true,
        checks: build_plugin_checks(true, true, true, true, true, Some(true)),
        duration_ms: started.elapsed().as_millis() as u64,
        drifts: Vec::new(),
        detail_code: None,
    })
}

fn plugin_test_report(
    pack_id: &str,
    lockfile: Option<PathBuf>,
    verifier: &dyn SignatureVerifier,
) -> Result<PluginTestOutput, String> {
    let base_dir = ensure_install_base_dir()?;
    plugin_test_report_in_dir(pack_id, lockfile.as_deref(), &base_dir, verifier)
}

fn plugin_test_report_in_dir(
    pack_id: &str,
    lockfile: Option<&Path>,
    base_dir: &Path,
    verifier: &dyn SignatureVerifier,
) -> Result<PluginTestOutput, String> {
    let started = Instant::now();
    let lock = load_lockfile(lockfile)?;
    let plugin = lock
        .plugins
        .iter()
        .find(|p| p.pack_id == pack_id)
        .ok_or_else(|| err(CliErrorKind::NotFound, "plugin not found"))?;
    let pack_dir = base_dir.join(&plugin.pack_id);
    let loaded = load_rule_pack_from_dir(&pack_dir)
        .map_err(|e| err(CliErrorKind::Validation, format!("load failed: {e:?}")))?;
    let trust = load_trust_policy()?;

    let mut drifts = Vec::new();
    let version_matches_lock = loaded.manifest.version == plugin.version;
    if !version_matches_lock {
        drifts.push(PluginTestDrift {
            field: "version".to_string(),
            expected: plugin.version.clone(),
            actual: loaded.manifest.version.clone(),
        });
    }

    let resolved_rev_verified = if let Some(expected) = &plugin.resolved_rev {
        let head = git_resolve_head(&pack_dir)?;
        if &head == expected {
            true
        } else {
            drifts.push(PluginTestDrift {
                field: "resolved_rev".to_string(),
                expected: expected.clone(),
                actual: head,
            });
            false
        }
    } else {
        true
    };

    let manifest_hash_actual = hash_file(&pack_dir.join("manifest.toml"))?;
    let manifest_hash_verified = manifest_hash_actual == plugin.manifest_hash;
    if !manifest_hash_verified {
        drifts.push(PluginTestDrift {
            field: "manifest_hash".to_string(),
            expected: plugin.manifest_hash.clone(),
            actual: manifest_hash_actual,
        });
    }

    let signature_hash_actual = hash_file(&pack_dir.join("manifest.sig"))?;
    let signature_hash_verified = signature_hash_actual == plugin.signature;
    if !signature_hash_verified {
        drifts.push(PluginTestDrift {
            field: "signature_hash".to_string(),
            expected: plugin.signature.clone(),
            actual: signature_hash_actual,
        });
    }

    let verify_err = verify_rule_pack_with_verifier(&loaded, &trust, verifier).err();
    let signature_verified = verify_err.is_none();
    let trust_verified = verify_err.is_none();
    if let Some(message) = verify_err {
        drifts.push(PluginTestDrift {
            field: "signature_or_trust".to_string(),
            expected: "verified".to_string(),
            actual: message,
        });
    }

    let core_compat_verified = loaded.manifest.validate_with_core_version("0.1.0").is_ok();
    if !core_compat_verified {
        drifts.push(PluginTestDrift {
            field: "core_compat".to_string(),
            expected: "compatible_with_0.1.0".to_string(),
            actual: loaded.manifest.core_compat.clone(),
        });
    }

    let action_api_verified = loaded.manifest.action_api == 1;
    if !action_api_verified {
        drifts.push(PluginTestDrift {
            field: "action_api".to_string(),
            expected: "1".to_string(),
            actual: loaded.manifest.action_api.to_string(),
        });
    }

    let os_target_verified = validate_os_targets(&loaded).is_ok();
    if !os_target_verified {
        drifts.push(PluginTestDrift {
            field: "os_targets".to_string(),
            expected: std::env::consts::OS.to_string(),
            actual: format!("{:?}", loaded.manifest.os_targets),
        });
    }

    let overall_passed = version_matches_lock
        && manifest_hash_verified
        && signature_hash_verified
        && resolved_rev_verified
        && signature_verified
        && trust_verified
        && core_compat_verified
        && action_api_verified
        && os_target_verified;
    let detail_code = if overall_passed {
        None
    } else {
        plugin_primary_detail_code_from_drifts(&drifts).map(ToOwned::to_owned)
    };

    Ok(PluginTestOutput {
        pack_id: plugin.pack_id.clone(),
        overall_passed,
        version_matches_lock,
        manifest_hash_verified,
        signature_hash_verified,
        resolved_rev_verified,
        signature_verified,
        trust_verified,
        core_compat_verified,
        action_api_verified,
        os_target_verified,
        checks: build_plugin_checks(
            signature_verified,
            trust_verified,
            core_compat_verified,
            action_api_verified,
            os_target_verified,
            Some(version_matches_lock),
        ),
        duration_ms: started.elapsed().as_millis() as u64,
        drifts,
        detail_code,
    })
}

fn update_plugin(
    pack_id: &str,
    lockfile: Option<PathBuf>,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let lock = load_lockfile(lockfile.as_deref())?;
    let existing = lock
        .plugins
        .iter()
        .find(|p| p.pack_id == pack_id)
        .ok_or_else(|| err(CliErrorKind::NotFound, "plugin not found"))?
        .clone();
    let locked = install_plugin_internal_with_verifier(
        &format!("{}@{}", existing.url, existing.rev),
        lockfile,
        verifier,
    )?;
    if json {
        println!(
            "{}",
            plugin_update_json(PluginInstallOutput {
                pack_id: locked.pack_id,
                version: locked.version,
                source: locked.source,
                rev: locked.rev,
            })?
        );
    }
    Ok(())
}

fn remove_plugin(pack_id: &str, lockfile: Option<PathBuf>, json: bool) -> Result<(), String> {
    let mut lock = load_lockfile(lockfile.as_deref())?;
    let base_dir = ensure_install_base_dir()?;
    let pack_dir = base_dir.join(pack_id);
    let mut removed = false;
    if pack_dir.exists() {
        fs::remove_dir_all(&pack_dir)
            .map_err(|e| err_with(CliErrorKind::Io, "plugin remove failed", e))?;
        removed = true;
    }
    lock.plugins.retain(|p| p.pack_id != pack_id);
    save_lockfile(lockfile.as_deref(), &lock)?;
    if json {
        println!(
            "{}",
            plugin_remove_json(PluginRemoveOutput {
                pack_id: pack_id.to_string(),
                removed,
            })?
        );
    }
    Ok(())
}

pub fn parse_install_spec(spec: &str) -> Result<(String, String), String> {
    match parse_plugin_spec(spec)? {
        InstallSpec::Git { url, rev } => Ok((url, rev)),
        InstallSpec::Registry { .. } => Err(err(
            CliErrorKind::Validation,
            "registry spec is not a direct git install spec",
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallSpec {
    Git { url: String, rev: String },
    Registry { pack_id: String, version: String },
}

pub fn parse_plugin_spec(spec: &str) -> Result<InstallSpec, String> {
    let (url, rev) = spec.rsplit_once('@').ok_or_else(|| {
        err(
            CliErrorKind::Validation,
            "missing @<tag|commit> in install spec",
        )
    })?;
    if url.trim().is_empty() || rev.trim().is_empty() {
        return Err(err(
            CliErrorKind::Validation,
            "install spec must include URL and tag/commit",
        ));
    }
    if url.contains("://") || url.starts_with("git@") {
        return Ok(InstallSpec::Git {
            url: url.to_string(),
            rev: rev.to_string(),
        });
    }
    Ok(InstallSpec::Registry {
        pack_id: url.to_string(),
        version: rev.to_string(),
    })
}

fn resolve_install_source(spec: InstallSpec) -> Result<(String, String, String), String> {
    match spec {
        InstallSpec::Git { url, rev } => Ok(("git".to_string(), url, rev)),
        InstallSpec::Registry { pack_id, version } => {
            let resolved = resolve_registry_plugin(&pack_id, &version)?;
            Ok(("registry".to_string(), resolved.url, resolved.rev))
        }
    }
}

fn resolve_registry_plugin(pack_id: &str, version: &str) -> Result<ResolvedRegistryPlugin, String> {
    let path = registry_index_path()?;
    let content = fs::read_to_string(&path).map_err(|e| {
        err(
            CliErrorKind::Io,
            format!("registry index read failed ({}): {}", path.display(), e),
        )
    })?;
    let index = content.parse::<RegistryIndex>().map_err(|e| {
        err(
            CliErrorKind::Validation,
            format!("registry index parse failed: {e:?}"),
        )
    })?;
    index.resolve(pack_id, Some(version)).map_err(|e| {
        err(
            CliErrorKind::Validation,
            format!("registry resolve failed: {e:?}"),
        )
    })
}

fn search_registry(query: Option<String>, json: bool) -> Result<(), String> {
    let path = registry_index_path()?;
    let content = fs::read_to_string(&path).map_err(|e| {
        err(
            CliErrorKind::Io,
            format!("registry index read failed ({}): {}", path.display(), e),
        )
    })?;
    let entries = search_registry_entries(&content, query.as_deref())?;
    if json {
        println!("{}", registry_search_json(&entries)?);
        return Ok(());
    }
    for row in entries {
        println!("{} {} {}", row.pack_id, row.latest_version, row.description);
    }
    Ok(())
}

fn update_registry_index(
    source: Option<String>,
    signature_source: Option<String>,
    identity: Option<String>,
    issuer: Option<String>,
    strict: bool,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let source = match source {
        Some(value) => value,
        None => std::env::var("PREEN_REGISTRY_SOURCE").map_err(|_| {
            err(
                CliErrorKind::Validation,
                "missing registry source; pass --source or set PREEN_REGISTRY_SOURCE",
            )
        })?,
    };
    let signature_source = match signature_source {
        Some(value) => value,
        None => std::env::var("PREEN_REGISTRY_SIGNATURE_SOURCE")
            .unwrap_or_else(|_| default_signature_source(&source)),
    };
    let identity = match identity {
        Some(value) => value,
        None => std::env::var("PREEN_REGISTRY_IDENTITY")
            .unwrap_or_else(|_| DEFAULT_REGISTRY_IDENTITY.to_string()),
    };
    let issuer = match issuer {
        Some(value) => value,
        None => std::env::var("PREEN_REGISTRY_ISSUER")
            .unwrap_or_else(|_| REGISTRY_ALLOWED_ISSUER.to_string()),
    };
    validate_registry_trust_inputs(&identity, &issuer)?;
    let content = read_registry_source(&source)?;
    let signature = read_registry_source(&signature_source)?;
    verify_registry_index_signature(
        content.as_bytes().to_vec(),
        signature,
        &identity,
        &issuer,
        verifier,
    )?;
    let index = content.parse::<RegistryIndex>().map_err(|e| {
        err(
            CliErrorKind::Validation,
            format!("registry index parse failed: {e:?}"),
        )
    })?;
    let stale_mode = effective_registry_stale_mode(strict)?;
    let max_age_days = registry_max_age_days()?;
    check_registry_freshness(index.generated_at.as_deref(), stale_mode, max_age_days)?;
    let path = registry_index_path()?;
    let backup_path = write_registry_index_with_backup(&path, &content)?;
    if json {
        println!(
            "{}",
            registry_update_json(RegistryUpdateOutput {
                entries: index.entries.len(),
                path: path.display().to_string(),
                stale_mode: stale_mode.as_str().to_string(),
                max_age_days,
                source,
                used_signature_source: signature_source,
                identity,
                issuer,
                strict_applied: strict,
                backup_path: backup_path.map(|value| value.display().to_string()),
            })?
        );
    } else {
        println!(
            "registry index updated: {} entries ({})",
            index.entries.len(),
            path.display()
        );
    }
    Ok(())
}

fn parse_registry_stale_mode(value: &str) -> Result<RegistryStaleMode, String> {
    match value {
        "off" => Ok(RegistryStaleMode::Off),
        "warn" => Ok(RegistryStaleMode::Warn),
        "error" => Ok(RegistryStaleMode::Error),
        _ => Err(err(
            CliErrorKind::Validation,
            "invalid PREEN_REGISTRY_STALE_MODE (expected off|warn|error)",
        )),
    }
}

fn registry_stale_mode() -> Result<RegistryStaleMode, String> {
    match std::env::var("PREEN_REGISTRY_STALE_MODE") {
        Ok(value) => parse_registry_stale_mode(value.trim()),
        Err(_) => Ok(RegistryStaleMode::Warn),
    }
}

fn effective_registry_stale_mode(strict: bool) -> Result<RegistryStaleMode, String> {
    if strict {
        return Ok(RegistryStaleMode::Error);
    }
    registry_stale_mode()
}

fn registry_max_age_days() -> Result<i64, String> {
    match std::env::var("PREEN_REGISTRY_MAX_AGE_DAYS") {
        Ok(raw) => {
            let value = raw.trim().parse::<i64>().map_err(|_| {
                err(
                    CliErrorKind::Validation,
                    "invalid PREEN_REGISTRY_MAX_AGE_DAYS (expected positive integer)",
                )
            })?;
            if value <= 0 {
                return Err(err(
                    CliErrorKind::Validation,
                    "invalid PREEN_REGISTRY_MAX_AGE_DAYS (must be > 0)",
                ));
            }
            Ok(value)
        }
        Err(_) => Ok(DEFAULT_REGISTRY_MAX_AGE_DAYS),
    }
}

fn check_registry_freshness(
    generated_at: Option<&str>,
    mode: RegistryStaleMode,
    max_age_days: i64,
) -> Result<(), String> {
    if mode == RegistryStaleMode::Off {
        return Ok(());
    }
    let generated_at = match generated_at {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            let message = "registry index missing generated_at; freshness check skipped";
            if mode == RegistryStaleMode::Error {
                return Err(err(CliErrorKind::Validation, message));
            }
            eprintln!("warning: {message}");
            return Ok(());
        }
    };
    let generated = OffsetDateTime::parse(generated_at, &Rfc3339).map_err(|_| {
        err(
            CliErrorKind::Validation,
            "registry generated_at is not valid RFC3339",
        )
    })?;
    let age_days = (OffsetDateTime::now_utc() - generated).whole_days();
    if age_days > max_age_days {
        let message = format!(
            "registry index is stale: age={}d exceeds max={}d",
            age_days, max_age_days
        );
        if mode == RegistryStaleMode::Error {
            return Err(err(CliErrorKind::Validation, message));
        }
        eprintln!("warning: {message}");
    }
    Ok(())
}

fn registry_backup_path(path: &Path) -> PathBuf {
    path.with_extension("toml.bak")
}

fn write_registry_index_with_backup(path: &Path, content: &str) -> Result<Option<PathBuf>, String> {
    let parent = path
        .parent()
        .ok_or_else(|| err(CliErrorKind::Io, "registry index has no parent directory"))?;
    fs::create_dir_all(parent)
        .map_err(|e| err_with(CliErrorKind::Io, "registry index dir create failed", e))?;
    let temp_path = parent.join(format!(".registry-index.tmp-{}", std::process::id()));
    let mut temp_file = fs::File::create(&temp_path)
        .map_err(|e| err_with(CliErrorKind::Io, "registry temp create failed", e))?;
    temp_file
        .write_all(content.as_bytes())
        .map_err(|e| err_with(CliErrorKind::Io, "registry temp write failed", e))?;
    temp_file
        .sync_all()
        .map_err(|e| err_with(CliErrorKind::Io, "registry temp sync failed", e))?;

    let backup_path = registry_backup_path(path);
    let had_previous = path.exists();
    if had_previous {
        if backup_path.exists() {
            fs::remove_file(&backup_path)
                .map_err(|e| err_with(CliErrorKind::Io, "registry backup cleanup failed", e))?;
        }
        fs::rename(path, &backup_path)
            .map_err(|e| err_with(CliErrorKind::Io, "registry backup create failed", e))?;
    }
    if let Err(write_err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        if had_previous {
            let _ = fs::rename(&backup_path, path);
        }
        return Err(err_with(
            CliErrorKind::Io,
            "registry index write failed",
            write_err,
        ));
    }
    if had_previous {
        return Ok(Some(backup_path));
    }
    Ok(None)
}

fn verify_registry_index_signature(
    index_bytes: Vec<u8>,
    signature: String,
    identity: &str,
    issuer: &str,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let policy = TrustPolicy {
        allowlist: vec![identity.to_string()],
        remote_policy_url: None,
        remote_policy_identity: None,
        require_signed: true,
    };
    let input = VerificationInput {
        manifest_bytes: index_bytes,
        signature: SignatureBundle {
            signature,
            certificate: String::new(),
            rekor_log_id: None,
        },
        expected_identity: Some(identity.to_string()),
        expected_issuer: Some(issuer.to_string()),
    };
    preen_core::plugin::verify_with_policy(verifier, &policy, input).map_err(|verify_err| {
        err(
            CliErrorKind::Verification,
            format!("registry signature verification failed: {verify_err:?}"),
        )
    })?;
    Ok(())
}

fn default_signature_source(source: &str) -> String {
    format!("{source}.sig")
}

fn read_registry_source(source: &str) -> Result<String, String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| {
                err(
                    CliErrorKind::Network,
                    format!("http client init failed: {e}"),
                )
            })?;
        let response = client
            .get(source)
            .send()
            .map_err(|e| err(CliErrorKind::Network, format!("registry fetch failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(err(
                CliErrorKind::Network,
                format!("registry fetch failed with status {status}"),
            ));
        }
        return response.text().map_err(|e| {
            err(
                CliErrorKind::Network,
                format!("registry read body failed: {e}"),
            )
        });
    }
    if let Some(path) = source.strip_prefix("file://") {
        return fs::read_to_string(path)
            .map_err(|e| err_with(CliErrorKind::Io, "registry file read failed", e));
    }
    fs::read_to_string(source)
        .map_err(|e| err_with(CliErrorKind::Io, "registry source read failed", e))
}

fn validate_registry_trust_inputs(identity: &str, issuer: &str) -> Result<(), String> {
    if !identity.starts_with(REGISTRY_ALLOWED_IDENTITY_PREFIX) {
        return Err(err(
            CliErrorKind::Trust,
            format!(
                "registry identity must start with {}",
                REGISTRY_ALLOWED_IDENTITY_PREFIX
            ),
        ));
    }
    if issuer != REGISTRY_ALLOWED_ISSUER {
        return Err(err(
            CliErrorKind::Trust,
            format!("registry issuer must be {}", REGISTRY_ALLOWED_ISSUER),
        ));
    }
    Ok(())
}

fn search_registry_entries(
    index_toml: &str,
    query: Option<&str>,
) -> Result<Vec<RegistrySearchOutput>, String> {
    let index = index_toml.parse::<RegistryIndex>().map_err(|e| {
        err(
            CliErrorKind::Validation,
            format!("registry index parse failed: {e:?}"),
        )
    })?;
    let needle = query.map(|q| q.to_lowercase());
    let mut rows = Vec::new();
    for entry in index.entries {
        let searchable = format!(
            "{} {} {}",
            entry.pack_id.to_lowercase(),
            entry.name.to_lowercase(),
            entry.description.to_lowercase()
        );
        if let Some(needle) = &needle
            && !searchable.contains(needle)
        {
            continue;
        }
        rows.push(RegistrySearchOutput {
            pack_id: entry.pack_id,
            latest_version: entry.latest_version,
            description: entry.description,
        });
    }
    Ok(rows)
}

fn registry_search_json(entries: &[RegistrySearchOutput]) -> Result<String, String> {
    to_json_envelope("plugin.search", entries)
}

fn plugin_info_json(plugin: &LockedPlugin) -> Result<String, String> {
    let out = PluginInfoOutput {
        pack_id: plugin.pack_id.clone(),
        version: plugin.version.clone(),
        rev: plugin.rev.clone(),
        source: plugin.source.clone(),
        url: plugin.url.clone(),
        manifest_hash: plugin.manifest_hash.clone(),
        signature: plugin.signature.clone(),
        trusted_identity: plugin.trusted_identity.clone(),
    };
    to_json_envelope("plugin.info", &out)
}

fn plugin_list_json(plugins: &[LockedPlugin]) -> Result<String, String> {
    let mut out = Vec::with_capacity(plugins.len());
    for plugin in plugins {
        out.push(PluginListItemOutput {
            pack_id: plugin.pack_id.clone(),
            version: plugin.version.clone(),
            rev: plugin.rev.clone(),
            source: plugin.source.clone(),
        });
    }
    to_json_envelope("plugin.list", &out)
}

fn plugin_verify_json(out: PluginVerifyOutput) -> Result<String, String> {
    to_json_envelope("plugin.verify", out)
}

fn plugin_test_json(out: PluginTestOutput) -> Result<String, String> {
    to_json_envelope("plugin.test", out)
}

fn plugin_test_all_json(out: PluginTestAllOutput) -> Result<String, String> {
    to_json_envelope("plugin.test_all", out)
}

fn plugin_test_spec_json(out: PluginTestSpecOutput) -> Result<String, String> {
    to_json_envelope("plugin.test_spec", out)
}

fn plugin_preflight_json(out: PluginPreflightOutput) -> Result<String, String> {
    to_json_envelope("plugin.preflight", out)
}

fn plugin_preflight_all_json(out: PluginPreflightAllOutput) -> Result<String, String> {
    to_json_envelope("plugin.preflight_all", out)
}

fn plugin_install_json(out: PluginInstallOutput) -> Result<String, String> {
    to_json_envelope("plugin.install", out)
}

fn plugin_update_json(out: PluginInstallOutput) -> Result<String, String> {
    to_json_envelope("plugin.update", out)
}

fn plugin_remove_json(out: PluginRemoveOutput) -> Result<String, String> {
    to_json_envelope("plugin.remove", out)
}

fn registry_update_json(out: RegistryUpdateOutput) -> Result<String, String> {
    to_json_envelope("plugin.registry_update", out)
}

fn to_json_envelope<T: Serialize>(kind: &'static str, data: T) -> Result<String, String> {
    let envelope = CliJsonEnvelope {
        schema_version: CLI_JSON_SCHEMA_V1,
        kind: kind.to_string(),
        data,
    };
    serde_json::to_string(&envelope).map_err(|e| {
        err(
            CliErrorKind::Internal,
            format!("json serialize failed: {e}"),
        )
    })
}

fn error_json(err: &CliError) -> Result<String, String> {
    to_json_envelope(
        "error",
        ErrorOutput {
            error_kind: err.kind.as_str().to_string(),
            detail_code: err.detail_code.clone(),
            message: err.message.clone(),
        },
    )
}

pub fn resolve_registry_for_test(
    index_toml: &str,
    pack_id: &str,
    version: &str,
) -> Result<(String, String), String> {
    let index = index_toml.parse::<RegistryIndex>().map_err(|e| {
        err(
            CliErrorKind::Validation,
            format!("registry index parse failed: {e:?}"),
        )
    })?;
    let resolved = index.resolve(pack_id, Some(version)).map_err(|e| {
        err(
            CliErrorKind::Validation,
            format!("registry resolve failed: {e:?}"),
        )
    })?;
    Ok((resolved.url, resolved.rev))
}

pub fn search_registry_for_test(
    index_toml: &str,
    query: Option<&str>,
) -> Result<Vec<String>, String> {
    let entries = search_registry_entries(index_toml, query)?;
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        rows.push(format!(
            "{} {} {}",
            entry.pack_id, entry.latest_version, entry.description
        ));
    }
    Ok(rows)
}

pub fn default_signature_source_for_test(source: &str) -> String {
    default_signature_source(source)
}

pub fn validate_registry_trust_inputs_for_test(identity: &str, issuer: &str) -> Result<(), String> {
    validate_registry_trust_inputs(identity, issuer)
}

pub fn search_registry_json_for_test(
    index_toml: &str,
    query: Option<&str>,
) -> Result<String, String> {
    let entries = search_registry_entries(index_toml, query)?;
    registry_search_json(&entries)
}

pub fn check_registry_freshness_for_test(
    generated_at: Option<&str>,
    mode: &str,
    max_age_days: i64,
) -> Result<(), String> {
    let mode = parse_registry_stale_mode(mode)?;
    check_registry_freshness(generated_at, mode, max_age_days)
}

pub fn write_registry_index_with_backup_for_test(path: &Path, content: &str) -> Result<(), String> {
    write_registry_index_with_backup(path, content).map(|_| ())
}

pub fn registry_backup_path_for_test(path: &Path) -> PathBuf {
    registry_backup_path(path)
}

pub fn plugin_info_json_for_test(plugin: &LockedPlugin) -> Result<String, String> {
    plugin_info_json(plugin)
}

pub fn plugin_list_json_for_test(plugins: &[LockedPlugin]) -> Result<String, String> {
    plugin_list_json(plugins)
}

pub fn plugin_verify_json_for_test(
    pack_id: &str,
    manifest_hash_verified: bool,
    signature_hash_verified: bool,
    resolved_rev_verified: bool,
) -> Result<String, String> {
    plugin_verify_json(PluginVerifyOutput {
        pack_id: pack_id.to_string(),
        manifest_hash_verified,
        signature_hash_verified,
        resolved_rev_verified,
    })
}

pub fn plugin_verify_text_for_test(pack_id: &str, language: &str) -> String {
    format_plugin_verify_output(
        &PluginTestOutput {
            pack_id: pack_id.to_string(),
            overall_passed: true,
            version_matches_lock: true,
            manifest_hash_verified: true,
            signature_hash_verified: true,
            resolved_rev_verified: true,
            signature_verified: true,
            trust_verified: true,
            core_compat_verified: true,
            action_api_verified: true,
            os_target_verified: true,
            checks: build_plugin_checks(true, true, true, true, true, Some(true)),
            duration_ms: 0,
            drifts: Vec::new(),
            detail_code: None,
        },
        language,
    )
}

pub fn plugin_verify_for_test(
    pack_id: &str,
    lockfile: Option<&Path>,
    install_dir: &Path,
    json: bool,
    language: &str,
    verifier: &dyn SignatureVerifier,
) -> Result<String, String> {
    let checks = plugin_checks_in_dir(pack_id, lockfile, install_dir, verifier)?;
    if json {
        return plugin_verify_json(PluginVerifyOutput {
            pack_id: checks.pack_id,
            manifest_hash_verified: checks.manifest_hash_verified,
            signature_hash_verified: checks.signature_hash_verified,
            resolved_rev_verified: checks.resolved_rev_verified,
        });
    }
    Ok(format_plugin_verify_output(&checks, language))
}

pub fn plugin_test_for_test(
    pack_id: &str,
    lockfile: Option<&Path>,
    install_dir: &Path,
    json: bool,
    language: &str,
    verifier: &dyn SignatureVerifier,
) -> Result<String, String> {
    let report = plugin_test_report_in_dir(pack_id, lockfile, install_dir, verifier)?;
    if json {
        return plugin_test_json(report);
    }
    Ok(format_plugin_test_output(&report, language))
}

pub fn plugin_test_all_for_test(
    lockfile: Option<&Path>,
    install_dir: &Path,
    json: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<String, String> {
    let out = build_test_all_output(lockfile, Some(install_dir), verifier)?;
    if json {
        return plugin_test_all_json(out);
    }
    Ok(format!(
        "summary: kind=test_all overall_passed={} total={} passed={} failed={}",
        out.overall_passed, out.total, out.passed, out.failed
    ))
}

pub fn plugin_test_json_for_test(pack_id: &str) -> Result<String, String> {
    plugin_test_json(PluginTestOutput {
        pack_id: pack_id.to_string(),
        overall_passed: true,
        version_matches_lock: true,
        manifest_hash_verified: true,
        signature_hash_verified: true,
        resolved_rev_verified: true,
        signature_verified: true,
        trust_verified: true,
        core_compat_verified: true,
        action_api_verified: true,
        os_target_verified: true,
        checks: build_plugin_checks(true, true, true, true, true, Some(true)),
        duration_ms: 0,
        drifts: Vec::new(),
        detail_code: None,
    })
}

pub fn plugin_test_all_json_for_test() -> Result<String, String> {
    plugin_test_all_json(PluginTestAllOutput {
        overall_passed: true,
        total: 0,
        passed: 0,
        failed: 0,
        results: Vec::new(),
        failures: Vec::new(),
    })
}

pub fn plugin_test_spec_json_for_test(spec: &str, pack_id: &str) -> Result<String, String> {
    plugin_test_spec_json(PluginTestSpecOutput {
        overall_passed: true,
        spec: spec.to_string(),
        source: "registry".to_string(),
        url: "https://github.com/Preen-rs/preen-rulepack-homebrew".to_string(),
        requested_rev: "v1.2.0".to_string(),
        resolved_rev: "abc123".to_string(),
        pack_id: pack_id.to_string(),
        version: "1.2.0".to_string(),
        signature_verified: true,
        trust_verified: true,
        core_compat_verified: true,
        action_api_verified: true,
        os_target_verified: true,
        checks: build_plugin_checks(true, true, true, true, true, None),
        duration_ms: 0,
    })
}

pub fn plugin_preflight_json_for_test(spec: &str, pack_id: &str) -> Result<String, String> {
    plugin_preflight_json(PluginPreflightOutput {
        spec: spec.to_string(),
        source: "registry".to_string(),
        url: "https://github.com/Preen-rs/preen-rulepack-homebrew".to_string(),
        requested_rev: "v1.2.0".to_string(),
        resolved_rev: "abc123".to_string(),
        pack_id: pack_id.to_string(),
        version: "1.2.0".to_string(),
        signature_verified: true,
        trust_verified: true,
        core_compat_verified: true,
        action_api_verified: true,
        os_target_verified: true,
        checks: build_plugin_checks(true, true, true, true, true, None),
        duration_ms: 0,
        detail_code: None,
    })
}

pub fn plugin_preflight_all_json_for_test() -> Result<String, String> {
    plugin_preflight_all_json(PluginPreflightAllOutput {
        overall_passed: true,
        total: 0,
        passed: 0,
        failed: 0,
        results: Vec::new(),
        failures: Vec::new(),
    })
}

pub fn plugin_preflight_all_for_test(
    lockfile: Option<&Path>,
    verifier: &dyn SignatureVerifier,
) -> Result<String, String> {
    plugin_preflight_all_json(build_preflight_all_output(lockfile, verifier)?)
}

pub fn preflight_failure_row_for_test(
    spec: &str,
    error_kind: &str,
    detail_code: Option<&str>,
    message: &str,
    language: &str,
) -> String {
    format_preflight_failure_row(
        &PluginPreflightFailureOutput {
            spec: spec.to_string(),
            error_kind: error_kind.to_string(),
            detail_code: detail_code.map(ToOwned::to_owned),
            message: message.to_string(),
        },
        language,
    )
}

pub fn test_failure_row_for_test(
    pack_id: &str,
    error_kind: &str,
    detail_code: Option<&str>,
    message: &str,
    language: &str,
) -> String {
    format_test_failure_row(
        &PluginTestFailureOutput {
            pack_id: pack_id.to_string(),
            error_kind: error_kind.to_string(),
            detail_code: detail_code.map(ToOwned::to_owned),
            message: message.to_string(),
        },
        language,
    )
}

pub fn plugin_install_json_for_test(
    pack_id: &str,
    version: &str,
    source: &str,
    rev: &str,
) -> Result<String, String> {
    plugin_install_json(PluginInstallOutput {
        pack_id: pack_id.to_string(),
        version: version.to_string(),
        source: source.to_string(),
        rev: rev.to_string(),
    })
}

pub fn plugin_update_json_for_test(
    pack_id: &str,
    version: &str,
    source: &str,
    rev: &str,
) -> Result<String, String> {
    plugin_update_json(PluginInstallOutput {
        pack_id: pack_id.to_string(),
        version: version.to_string(),
        source: source.to_string(),
        rev: rev.to_string(),
    })
}

pub fn plugin_remove_json_for_test(pack_id: &str, removed: bool) -> Result<String, String> {
    plugin_remove_json(PluginRemoveOutput {
        pack_id: pack_id.to_string(),
        removed,
    })
}

pub fn hint_for_detail_code_for_test(code: &str) -> (String, String, u8) {
    let hint = plugin_failure_hint_from_detail_code(code);
    (
        hint.code.to_string(),
        hint.action.to_string(),
        hint.priority,
    )
}

pub fn hint_message_for_test(code: &str, language: &str) -> String {
    plugin_failure_hint_message(code, language)
}

pub fn cli_label_for_test(language: &str, key: &str) -> String {
    cli_label(language, key).to_string()
}

pub fn primary_hint_for_drift_fields_for_test(fields: &[&str]) -> Option<(String, String, u8)> {
    let drifts = fields
        .iter()
        .map(|field| PluginTestDrift {
            field: (*field).to_string(),
            expected: "expected".to_string(),
            actual: "actual".to_string(),
        })
        .collect::<Vec<_>>();
    let report = PluginTestOutput {
        pack_id: "test.pack".to_string(),
        overall_passed: drifts.is_empty(),
        version_matches_lock: true,
        manifest_hash_verified: true,
        signature_hash_verified: true,
        resolved_rev_verified: true,
        signature_verified: true,
        trust_verified: true,
        core_compat_verified: true,
        action_api_verified: true,
        os_target_verified: true,
        checks: build_plugin_checks(true, true, true, true, true, Some(true)),
        duration_ms: 0,
        drifts,
        detail_code: None,
    };
    plugin_primary_failure_hint_from_drifts(&report.drifts).map(|hint| {
        (
            hint.code.to_string(),
            hint.action.to_string(),
            hint.priority,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub fn registry_update_json_for_test(
    entries: usize,
    path: &str,
    stale_mode: &str,
    max_age_days: i64,
    source: &str,
    used_signature_source: &str,
    identity: &str,
    issuer: &str,
    strict_applied: bool,
    backup_path: Option<&str>,
) -> Result<String, String> {
    registry_update_json(RegistryUpdateOutput {
        entries,
        path: path.to_string(),
        stale_mode: stale_mode.to_string(),
        max_age_days,
        source: source.to_string(),
        used_signature_source: used_signature_source.to_string(),
        identity: identity.to_string(),
        issuer: issuer.to_string(),
        strict_applied,
        backup_path: backup_path.map(|v| v.to_string()),
    })
}

pub fn error_json_for_test(message: &str) -> Result<String, String> {
    let err = CliError::from(message.to_string());
    error_json(&err)
}

fn registry_index_path() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("PREEN_REGISTRY_INDEX") {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() {
            return Ok(path);
        }
    }
    Ok(preen_state_dir()?.join("registry-index.toml"))
}

fn load_lockfile(path: Option<&Path>) -> Result<PluginLockfile, String> {
    let path = resolve_lockfile_read_path(path)?;
    load_lockfile_at(&path)
}

pub fn load_lockfile_at(path: &Path) -> Result<PluginLockfile, String> {
    if !path.exists() {
        return Ok(PluginLockfile {
            schema_version: PluginLockfile::SCHEMA_V1,
            plugins: Vec::new(),
        });
    }
    let content = fs::read_to_string(path)
        .map_err(|e| err_with(CliErrorKind::Io, "lockfile read failed", e))?;
    content.parse::<PluginLockfile>().map_err(|e| {
        err(
            CliErrorKind::Validation,
            format!("lockfile parse error: {e:?}"),
        )
    })
}

fn resolve_lockfile_read_path(path: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = path {
        return Ok(path.to_path_buf());
    }
    let default = default_lockfile_path()?;
    let legacy = legacy_lockfile_path();
    Ok(preferred_lockfile_read_path(&default, legacy))
}

fn preferred_lockfile_read_path(default_path: &Path, legacy_path: &Path) -> PathBuf {
    if default_path.exists() {
        return default_path.to_path_buf();
    }
    if legacy_path.exists() {
        return legacy_path.to_path_buf();
    }
    default_path.to_path_buf()
}

pub fn preferred_lockfile_read_path_for_test(default_path: &Path, legacy_path: &Path) -> PathBuf {
    preferred_lockfile_read_path(default_path, legacy_path)
}

fn default_lockfile_path() -> Result<PathBuf, String> {
    Ok(preen_state_dir()?.join("plugins.lock"))
}

fn legacy_lockfile_path() -> &'static Path {
    Path::new("preen-plugins.lock")
}

fn save_lockfile(path: Option<&Path>, lock: &PluginLockfile) -> Result<(), String> {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => default_lockfile_path()?,
    };
    save_lockfile_at(&path, lock)
}

pub fn save_lockfile_at(path: &Path, lock: &PluginLockfile) -> Result<(), String> {
    let content = lock.to_string().map_err(|e| {
        err(
            CliErrorKind::Internal,
            format!("lockfile serialize error: {e:?}"),
        )
    })?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| err_with(CliErrorKind::Io, "lockfile dir create failed", e))?;
    }
    fs::write(path, content).map_err(|e| err_with(CliErrorKind::Io, "lockfile write failed", e))
}

pub fn verify_lockfile_hashes(lock: &PluginLockfile, base_dir: &Path) -> Result<(), String> {
    for plugin in &lock.plugins {
        let pack_dir = base_dir.join(&plugin.pack_id);
        let manifest_hash = hash_file(&pack_dir.join("manifest.toml"))?;
        if manifest_hash != plugin.manifest_hash {
            return Err(err(
                CliErrorKind::Verification,
                format!("hash mismatch: {}", plugin.pack_id),
            ));
        }
        let signature_hash = hash_file(&pack_dir.join("manifest.sig"))?;
        if signature_hash != plugin.signature {
            return Err(err(
                CliErrorKind::Verification,
                format!("signature mismatch: {}", plugin.pack_id),
            ));
        }
    }
    Ok(())
}

pub fn hash_file_for_test(path: &Path) -> Result<String, String> {
    hash_file(path)
}

pub fn clean_selection_summary_for_test(
    scan_result: &ScanResult,
    roots: &[String],
    max_items: usize,
) -> (Vec<String>, u64) {
    let selection = build_clean_selection(scan_result, roots, max_items);
    let paths = selection.iter().map(|item| item.path.clone()).collect();
    let bytes = selection.iter().map(|item| item.size).sum();
    (paths, bytes)
}

pub fn format_bytes_for_test(bytes: u64) -> String {
    format_bytes(bytes)
}

pub fn enforce_clean_scope_for_test(
    selected_paths: &[String],
    roots: &[String],
) -> Result<(), String> {
    enforce_clean_scope(selected_paths, roots)
}

pub fn clean_output_for_test(
    dry_run: bool,
    confirm: bool,
    strategy: Option<&str>,
) -> Result<serde_json::Value, String> {
    let strategy_arg = match strategy.map(|item| item.trim().to_ascii_lowercase()) {
        Some(ref value) if value == "delete" => Some(CleanStrategyArg::Delete),
        Some(ref value) if value == "trash" => Some(CleanStrategyArg::Trash),
        Some(other) => {
            return Err(err(
                CliErrorKind::Validation,
                format!("unsupported clean strategy for test: {other}"),
            ));
        }
        None => None,
    };
    let output = run_clean_output(dry_run, confirm, strategy_arg)?;
    let json = clean_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "clean output parse failed", e))
}

pub fn clean_runtime_error_detail_code_for_test(error: RuntimeExecutionError) -> Option<String> {
    let encoded = map_clean_runtime_error(error);
    decode_tagged_error(&encoded).and_then(|(_, detail_code, _)| detail_code)
}

pub fn clone_rule_pack_for_test(url: &str, rev: &str, dest: &Path) -> Result<String, String> {
    clone_rule_pack_at(url, rev, dest, "install_clone_failed")
}

pub fn install_plugin_in_dir_for_test(
    spec: &str,
    lockfile: Option<&Path>,
    install_dir: &Path,
    verifier: &dyn SignatureVerifier,
) -> Result<LockedPlugin, String> {
    install_plugin_internal_in_dir(
        spec,
        lockfile.map(|p| p.to_path_buf()),
        install_dir,
        verifier,
    )
}

fn ensure_install_base_dir() -> Result<PathBuf, String> {
    let base = preen_state_dir()?.join("plugins");
    fs::create_dir_all(&base)
        .map_err(|e| err_with(CliErrorKind::Io, "plugin base dir create failed", e))?;
    Ok(base)
}

fn preen_state_dir() -> Result<PathBuf, String> {
    match std::env::consts::OS {
        "macos" => {
            let dir = dirs::home_dir().ok_or_else(|| err(CliErrorKind::Io, "missing home dir"))?;
            Ok(dir
                .join("Library")
                .join("Application Support")
                .join("Preen"))
        }
        "linux" => {
            let dir =
                dirs::config_dir().ok_or_else(|| err(CliErrorKind::Io, "missing config dir"))?;
            Ok(dir.join("preen"))
        }
        other => Err(err(
            CliErrorKind::Unsupported,
            format!("unsupported OS: {other}"),
        )),
    }
}

fn git_clone_at(url: &str, rev: &str, dest: &Path) -> Result<String, String> {
    match git_clone_checkout(url, rev, dest, true) {
        Ok(head) => Ok(head),
        Err(shallow_err) => {
            if dest.exists() {
                fs::remove_dir_all(dest)
                    .map_err(|e| err_with(CliErrorKind::Io, "temp clone dir cleanup failed", e))?;
            }
            git_clone_checkout(url, rev, dest, false).map_err(|full_err| {
                err(
                    CliErrorKind::Internal,
                    format!(
                    "git shallow clone failed: {shallow_err}; full clone retry failed: {full_err}"
                    ),
                )
            })
        }
    }
}

fn clone_rule_pack_at(
    url: &str,
    rev: &str,
    dest: &Path,
    detail_code: &'static str,
) -> Result<String, String> {
    git_clone_at(url, rev, dest).map_err(|e| err_code(CliErrorKind::Internal, detail_code, e))
}

fn git_clone_checkout(url: &str, rev: &str, dest: &Path, shallow: bool) -> Result<String, String> {
    let dest_str = dest.to_string_lossy().to_string();
    if shallow {
        run_git(&["clone", "--depth", "1", "--no-checkout", url, &dest_str])?;
        run_git_in(dest, &["fetch", "--depth", "1", "origin", rev])?;
        run_git_in(dest, &["checkout", "--detach", "FETCH_HEAD"])?;
    } else {
        run_git(&["clone", url, &dest_str])?;
        run_git_in(dest, &["checkout", rev])?;
    }
    git_resolve_head(dest)
}

fn run_git(args: &[&str]) -> Result<(), String> {
    let output = ProcessCommand::new("git")
        .args(args)
        .output()
        .map_err(|e| err_with(CliErrorKind::Internal, "git execution failed", e))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        return Err(err(
            CliErrorKind::Internal,
            format!("git command failed: {}", args.join(" ")),
        ));
    }
    Err(err(
        CliErrorKind::Internal,
        format!("git command failed: {}: {}", args.join(" "), stderr),
    ))
}

fn run_git_in(repo: &Path, args: &[&str]) -> Result<(), String> {
    let output = ProcessCommand::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| err_with(CliErrorKind::Internal, "git execution failed", e))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let cmd = args.join(" ");
    if stderr.is_empty() {
        return Err(err(
            CliErrorKind::Internal,
            format!("git command failed in repo: {cmd}"),
        ));
    }
    Err(err(
        CliErrorKind::Internal,
        format!("git command failed in repo: {cmd}: {stderr}"),
    ))
}

fn git_resolve_head(path: &Path) -> Result<String, String> {
    let output = ProcessCommand::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| err_with(CliErrorKind::Internal, "git rev-parse failed", e))?;
    if !output.status.success() {
        return Err(err(CliErrorKind::Internal, "git rev-parse failed"));
    }
    let head = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if head.is_empty() {
        return Err(err(
            CliErrorKind::Internal,
            "git rev-parse returned empty head",
        ));
    }
    Ok(head)
}

fn build_plugin_checks(
    signature_verified: bool,
    trust_verified: bool,
    core_compat_verified: bool,
    action_api_verified: bool,
    os_target_verified: bool,
    version_matches_lock: Option<bool>,
) -> Vec<PluginCheckStatus> {
    let mut checks = Vec::new();
    if let Some(value) = version_matches_lock {
        checks.push(PluginCheckStatus::new(
            PluginCheckId::VersionMatchesLock,
            value,
        ));
    }
    checks.push(PluginCheckStatus::new(
        PluginCheckId::SignatureVerified,
        signature_verified,
    ));
    checks.push(PluginCheckStatus::new(
        PluginCheckId::TrustVerified,
        trust_verified,
    ));
    checks.push(PluginCheckStatus::new(
        PluginCheckId::CoreCompatVerified,
        core_compat_verified,
    ));
    checks.push(PluginCheckStatus::new(
        PluginCheckId::ActionApiVerified,
        action_api_verified,
    ));
    checks.push(PluginCheckStatus::new(
        PluginCheckId::OsTargetVerified,
        os_target_verified,
    ));
    checks
}

fn validate_os_targets(loaded: &LoadedRulePack) -> Result<(), String> {
    let os = std::env::consts::OS;
    let ok = loaded.manifest.os_targets.iter().any(|t| {
        matches!(
            (os, t),
            ("macos", preen_core::plugin::OsTarget::Macos)
                | ("linux", preen_core::plugin::OsTarget::Linux)
        )
    });
    if !ok {
        return Err(err(
            CliErrorKind::Validation,
            "rule pack not compatible with this OS",
        ));
    }
    Ok(())
}

fn verify_rule_pack(loaded: &LoadedRulePack, policy: &TrustPolicy) -> Result<(), String> {
    verify_rule_pack_with_verifier(loaded, policy, &SigstoreVerifier)
}

fn verify_rule_pack_with_verifier(
    loaded: &LoadedRulePack,
    policy: &TrustPolicy,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    if !loaded
        .manifest
        .signing
        .as_ref()
        .map(|s| s.sigstore)
        .unwrap_or(false)
    {
        return Err(err(CliErrorKind::Trust, "signature required"));
    }
    let input = VerificationInput {
        manifest_bytes: fs::read(loaded.base_dir.join("manifest.toml"))
            .map_err(|e| err_with(CliErrorKind::Io, "manifest read failed", e))?,
        signature: SignatureBundle {
            signature: fs::read_to_string(loaded.base_dir.join("manifest.sig"))
                .map_err(|e| err_with(CliErrorKind::Io, "manifest.sig read failed", e))?,
            certificate: fs::read_to_string(loaded.base_dir.join("manifest.cert"))
                .map_err(|e| err_with(CliErrorKind::Io, "manifest.cert read failed", e))?,
            rekor_log_id: None,
        },
        expected_identity: loaded
            .manifest
            .signing
            .as_ref()
            .and_then(|s| s.identity.clone()),
        expected_issuer: loaded
            .manifest
            .signing
            .as_ref()
            .and_then(|s| s.issuer.clone()),
    };
    let outcome =
        preen_core::plugin::verify_with_policy(verifier, policy, input).map_err(|verify_err| {
            err(
                CliErrorKind::Verification,
                format!("verification failed: {verify_err:?}"),
            )
        })?;
    if !policy.allowlist.is_empty() && !policy.is_identity_allowed(&outcome.identity) {
        return Err(err(CliErrorKind::Trust, "identity not allowed"));
    }
    Ok(())
}

pub fn verify_rule_pack_for_test(
    loaded: &LoadedRulePack,
    policy: &TrustPolicy,
) -> Result<(), String> {
    verify_rule_pack(loaded, policy)
}

struct SigstoreVerifier;

impl SignatureVerifier for SigstoreVerifier {
    fn verify(
        &self,
        input: VerificationInput,
    ) -> Result<preen_core::plugin::VerificationOutcome, VerifyError> {
        let expected = input
            .expected_identity
            .clone()
            .ok_or_else(|| VerifyError::SignatureInvalid("missing identity".to_string()))?;
        let issuer = input
            .expected_issuer
            .clone()
            .ok_or_else(|| VerifyError::SignatureInvalid("missing issuer".to_string()))?;
        let temp_dir = TempDir::new().map_err(|e| VerifyError::PolicyUnavailable(e.to_string()))?;
        let manifest_path = temp_dir.path().join("manifest.toml");
        let sig_path = temp_dir.path().join("manifest.sig");
        fs::write(&manifest_path, input.manifest_bytes)
            .map_err(|e| VerifyError::PolicyUnavailable(e.to_string()))?;
        fs::write(&sig_path, input.signature.signature)
            .map_err(|e| VerifyError::PolicyUnavailable(e.to_string()))?;
        if input.signature.certificate.trim().is_empty() {
            match run_cosign_verify_with_bundle(
                &manifest_path,
                &sig_path,
                &expected,
                &issuer,
                false,
            ) {
                Ok(()) => Ok(preen_core::plugin::VerificationOutcome { identity: expected }),
                Err(primary_err) if is_rekor_lookup_failure(&primary_err) => {
                    run_cosign_verify_with_bundle(
                        &manifest_path,
                        &sig_path,
                        &expected,
                        &issuer,
                        true,
                    )
                    .map_err(VerifyError::SignatureInvalid)?;
                    Ok(preen_core::plugin::VerificationOutcome { identity: expected })
                }
                Err(err) => Err(VerifyError::SignatureInvalid(err)),
            }
        } else {
            let cert_path = temp_dir.path().join("manifest.cert");
            fs::write(&cert_path, input.signature.certificate)
                .map_err(|e| VerifyError::PolicyUnavailable(e.to_string()))?;
            match run_cosign_verify(
                &manifest_path,
                &sig_path,
                &cert_path,
                &expected,
                &issuer,
                false,
            ) {
                Ok(()) => Ok(preen_core::plugin::VerificationOutcome { identity: expected }),
                Err(primary_err) if is_rekor_lookup_failure(&primary_err) => {
                    run_cosign_verify(
                        &manifest_path,
                        &sig_path,
                        &cert_path,
                        &expected,
                        &issuer,
                        true,
                    )
                    .map_err(VerifyError::SignatureInvalid)?;
                    Ok(preen_core::plugin::VerificationOutcome { identity: expected })
                }
                Err(err) => Err(VerifyError::SignatureInvalid(err)),
            }
        }
    }
}

fn run_cosign_verify(
    manifest_path: &Path,
    sig_path: &Path,
    cert_path: &Path,
    expected: &str,
    issuer: &str,
    ignore_tlog: bool,
) -> Result<(), String> {
    let mut cmd = ProcessCommand::new("cosign");
    cmd.arg("verify-blob")
        .arg("--certificate-identity")
        .arg(expected)
        .arg("--certificate-oidc-issuer")
        .arg(issuer)
        .arg("--certificate")
        .arg(cert_path)
        .arg("--signature")
        .arg(sig_path);
    if ignore_tlog {
        cmd.arg("--insecure-ignore-tlog");
    }
    cmd.arg(manifest_path);
    let output = cmd.output().map_err(|e| e.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "cosign verify failed".to_string()
    };
    Err(details)
}

fn run_cosign_verify_with_bundle(
    manifest_path: &Path,
    bundle_path: &Path,
    expected: &str,
    issuer: &str,
    ignore_tlog: bool,
) -> Result<(), String> {
    let mut cmd = ProcessCommand::new("cosign");
    cmd.arg("verify-blob")
        .arg("--certificate-identity")
        .arg(expected)
        .arg("--certificate-oidc-issuer")
        .arg(issuer)
        .arg("--bundle")
        .arg(bundle_path);
    if ignore_tlog {
        cmd.arg("--insecure-ignore-tlog");
    }
    cmd.arg(manifest_path);
    let output = cmd.output().map_err(|e| e.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "cosign verify failed".to_string()
    };
    Err(details)
}

fn is_rekor_lookup_failure(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("searching log query")
        || lower.contains("retrieve")
        || lower.contains("invalid signature when validating asn.1")
}

fn upsert_lockfile(lock: &mut PluginLockfile, plugin: LockedPlugin) {
    if let Some(existing) = lock
        .plugins
        .iter_mut()
        .find(|p| p.pack_id == plugin.pack_id)
    {
        *existing = plugin;
        return;
    }
    lock.plugins.push(plugin);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TrustConfig {
    allowlist: Vec<String>,
    #[serde(default = "default_require_signed")]
    require_signed: bool,
}

fn default_require_signed() -> bool {
    true
}

fn load_trust_policy() -> Result<TrustPolicy, String> {
    let path = trust_policy_path()?;
    if !path.exists() {
        return Ok(TrustPolicy {
            allowlist: Vec::new(),
            remote_policy_url: None,
            remote_policy_identity: None,
            require_signed: true,
        });
    }
    let content = fs::read_to_string(path)
        .map_err(|e| err_with(CliErrorKind::Io, "trust policy read failed", e))?;
    trust_policy_from_str(&content)
}

fn trust_policy_path() -> Result<PathBuf, String> {
    let path = match std::env::consts::OS {
        "macos" => {
            let dir = dirs::home_dir().ok_or_else(|| err(CliErrorKind::Io, "missing home dir"))?;
            dir.join("Library")
                .join("Application Support")
                .join("Preen")
                .join("trust.toml")
        }
        "linux" => {
            let dir =
                dirs::config_dir().ok_or_else(|| err(CliErrorKind::Io, "missing config dir"))?;
            dir.join("preen").join("trust.toml")
        }
        other => {
            return Err(err(
                CliErrorKind::Unsupported,
                format!("unsupported OS: {other}"),
            ));
        }
    };
    Ok(path)
}

pub fn trust_policy_from_str(input: &str) -> Result<TrustPolicy, String> {
    let cfg: TrustConfig = toml::from_str(input).map_err(|e| {
        err(
            CliErrorKind::Validation,
            format!("trust policy parse failed: {e}"),
        )
    })?;
    if !cfg.require_signed {
        return Err(err(
            CliErrorKind::Validation,
            "require_signed=false is not allowed",
        ));
    }
    Ok(TrustPolicy {
        allowlist: cfg.allowlist,
        remote_policy_url: None,
        remote_policy_identity: None,
        require_signed: true,
    })
}

fn hash_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|e| err_with(CliErrorKind::Io, "hash input read failed", e))?;
    let hash = Sha256::digest(&bytes);
    Ok(format!("sha256:{}", hex::encode(hash)))
}

#[derive(Parser, Clone)]
#[command(name = "preen")]
#[command(version = "0.1.0")]
#[command(about = "Preen CLI")]
pub struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Clone)]
enum CliCommand {
    Plugin {
        #[command(subcommand)]
        cmd: PluginCommand,
    },
    Clean {
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: bool,
        #[arg(long, value_enum)]
        strategy: Option<CleanStrategyArg>,
        #[arg(long)]
        json: bool,
    },
    Uninstall {
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    Optimize {
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    Analyze {
        path: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    Purge {
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long)]
        paths: bool,
        #[arg(long)]
        json: bool,
    },
    Installer {
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    Check {
        #[arg(long)]
        fix: bool,
        #[arg(long)]
        json: bool,
    },
    Touchid {
        action: Option<TouchIdActionArg>,
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    Completion {
        shell: Option<CompletionShellArg>,
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    Update {
        #[arg(long, short = 'f')]
        force: bool,
        #[arg(long)]
        nightly: bool,
        #[arg(long)]
        json: bool,
    },
    Remove {
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Clone)]
enum PluginCommand {
    Install {
        spec: String,
        #[arg(long)]
        lockfile: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Preflight {
        spec: Option<String>,
        #[arg(long, conflicts_with = "spec")]
        all: bool,
        #[arg(long)]
        lockfile: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    List {
        #[arg(long)]
        lockfile: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Info {
        pack_id: String,
        #[arg(long)]
        lockfile: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Verify {
        pack_id: String,
        #[arg(long)]
        lockfile: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Test {
        target: Option<String>,
        #[arg(long, conflicts_with = "target")]
        all: bool,
        #[arg(long)]
        lockfile: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Update {
        pack_id: String,
        #[arg(long)]
        lockfile: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Remove {
        pack_id: String,
        #[arg(long)]
        lockfile: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Search {
        query: Option<String>,
        #[arg(long)]
        json: bool,
    },
    RegistryUpdate {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        signature_source: Option<String>,
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        json: bool,
    },
}

impl Cli {
    pub fn wants_json_output(&self) -> bool {
        match &self.command {
            CliCommand::Plugin { cmd } => match cmd {
                PluginCommand::Install { json, .. } => *json,
                PluginCommand::Preflight { json, .. } => *json,
                PluginCommand::List { json, .. } => *json,
                PluginCommand::Info { json, .. } => *json,
                PluginCommand::Verify { json, .. } => *json,
                PluginCommand::Test { json, .. } => *json,
                PluginCommand::Update { json, .. } => *json,
                PluginCommand::Remove { json, .. } => *json,
                PluginCommand::Search { json, .. } => *json,
                PluginCommand::RegistryUpdate { json, .. } => *json,
            },
            CliCommand::Clean { json, .. } => *json,
            CliCommand::Uninstall { json, .. } => *json,
            CliCommand::Optimize { json, .. } => *json,
            CliCommand::Analyze { json, .. } => *json,
            CliCommand::Status { json, .. } => *json,
            CliCommand::Purge { json, .. } => *json,
            CliCommand::Installer { json, .. } => *json,
            CliCommand::Check { json, .. } => *json,
            CliCommand::Touchid { json, .. } => *json,
            CliCommand::Completion { json, .. } => *json,
            CliCommand::Update { json, .. } => *json,
            CliCommand::Remove { json, .. } => *json,
        }
    }

    pub fn format_error(&self, err: &CliError) -> String {
        if self.wants_json_output() {
            return error_json(err).unwrap_or_else(|_| err.to_string());
        }
        format_human_error(err, &cli_language())
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        if let Some((kind, detail_code, message)) = decode_tagged_error(&message) {
            return CliError {
                kind,
                detail_code,
                message,
            };
        }
        let lower = message.to_lowercase();
        let kind = if lower.contains("not found") {
            CliErrorKind::NotFound
        } else if lower.contains("signature")
            || lower.contains("identity")
            || lower.contains("issuer")
            || lower.contains("trust")
        {
            CliErrorKind::Trust
        } else if lower.contains("verify") {
            CliErrorKind::Verification
        } else if lower.contains("unsupported os") {
            CliErrorKind::Unsupported
        } else if lower.contains("read failed")
            || lower.contains("write")
            || lower.contains("parse")
            || lower.contains("lockfile")
        {
            CliErrorKind::Io
        } else if lower.contains("http")
            || lower.contains("network")
            || lower.contains("fetch")
            || lower.contains("curl")
        {
            CliErrorKind::Network
        } else if lower.contains("missing")
            || lower.contains("invalid")
            || lower.contains("must")
            || lower.contains("install spec")
        {
            CliErrorKind::Validation
        } else {
            CliErrorKind::Internal
        };
        CliError {
            kind,
            detail_code: None,
            message,
        }
    }
}

impl CliErrorKind {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "validation" => Some(CliErrorKind::Validation),
            "not_found" => Some(CliErrorKind::NotFound),
            "trust" => Some(CliErrorKind::Trust),
            "verification" => Some(CliErrorKind::Verification),
            "io" => Some(CliErrorKind::Io),
            "network" => Some(CliErrorKind::Network),
            "unsupported" => Some(CliErrorKind::Unsupported),
            "internal" => Some(CliErrorKind::Internal),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            CliErrorKind::Validation => "validation",
            CliErrorKind::NotFound => "not_found",
            CliErrorKind::Trust => "trust",
            CliErrorKind::Verification => "verification",
            CliErrorKind::Io => "io",
            CliErrorKind::Network => "network",
            CliErrorKind::Unsupported => "unsupported",
            CliErrorKind::Internal => "internal",
        }
    }
}

impl RegistryStaleMode {
    fn as_str(&self) -> &'static str {
        match self {
            RegistryStaleMode::Off => "off",
            RegistryStaleMode::Warn => "warn",
            RegistryStaleMode::Error => "error",
        }
    }
}
