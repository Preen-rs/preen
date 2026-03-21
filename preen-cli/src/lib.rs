use async_trait::async_trait;
use std::fmt::{Display, Write as FmtWrite};
use std::fs;
use std::io::IsTerminal;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

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
const DEFAULT_PURGE_SCAN_DEPTH: usize = 6;
const DEFAULT_PURGE_PREVIEW_LIMIT: usize = 20;
const DEFAULT_INSTALLER_SCAN_DEPTH: usize = 5;
const DEFAULT_INSTALLER_PREVIEW_LIMIT: usize = 20;
const DEFAULT_UNINSTALL_SCAN_DEPTH: usize = 4;
const DEFAULT_UNINSTALL_PREVIEW_LIMIT: usize = 20;
const DEFAULT_OPTIMIZE_TIMEOUT_SEC: u64 = 60;
const DEFAULT_ANALYZE_MAX_DEPTH: usize = 8;
const DEFAULT_ANALYZE_TOP_ENTRIES: usize = 20;
const DEFAULT_PURGE_ARTIFACT_NAMES: [&str; 10] = [
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    "venv",
    ".venv",
    "__pycache__",
];
const DEFAULT_INSTALLER_EXTENSIONS: [&str; 12] = [
    "dmg", "pkg", "zip", "tar", "tgz", "gz", "bz2", "xz", "deb", "rpm", "appimage", "iso",
];

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
    resolved_rev: String,
    installed_path: String,
    lockfile_path: String,
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
struct PurgeCommandOutput {
    mode: String,
    scanned_roots: usize,
    scanned_dirs: usize,
    target_count: usize,
    estimated_freed_bytes: u64,
    preview_paths: Vec<String>,
    affected_items: u64,
    freed_bytes: u64,
    warnings: Vec<String>,
    audit_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PurgePathsOutput {
    roots: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct InstallerCommandOutput {
    mode: String,
    scanned_roots: usize,
    scanned_files: usize,
    target_count: usize,
    estimated_freed_bytes: u64,
    preview_paths: Vec<String>,
    affected_items: u64,
    freed_bytes: u64,
    warnings: Vec<String>,
    audit_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct InstallerPathsOutput {
    roots: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UninstallCommandOutput {
    mode: String,
    target: String,
    scanned_roots: usize,
    scanned_entries: usize,
    target_count: usize,
    estimated_freed_bytes: u64,
    preview_paths: Vec<String>,
    affected_items: u64,
    freed_bytes: u64,
    warnings: Vec<String>,
    audit_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UninstallPathsOutput {
    roots: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct OptimizeCommandOutput {
    mode: String,
    os: String,
    task_count: usize,
    executed_tasks: Vec<String>,
    affected_items: u64,
    post_check_run: bool,
    post_check_overall_passed: Option<bool>,
    post_check_suggested_actions: Vec<String>,
    warnings: Vec<String>,
    audit_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SystemCheckRowOutput {
    id: String,
    label: String,
    severity: String,
    passed: bool,
    message: String,
    fixed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SystemCheckOutput {
    mode: String,
    overall_passed: bool,
    checks: Vec<SystemCheckRowOutput>,
    fixes_applied: u64,
    suggested_actions: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AnalyzeEntryOutput {
    name: String,
    path: String,
    item_type: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AnalyzeOutput {
    root: String,
    path: String,
    max_depth: usize,
    scanned_entries: usize,
    total_files: u64,
    total_dirs: u64,
    total_size_bytes: u64,
    total_size: u64,
    truncated_dirs: u64,
    entries: Vec<AnalyzeEntryOutput>,
    top_entries: Vec<AnalyzeEntryOutput>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnalyzeStats {
    files: u64,
    dirs: u64,
    size_bytes: u64,
    truncated_dirs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SystemStatusCheckOutput {
    id: String,
    label: String,
    severity: String,
    passed: bool,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StatusOutput {
    mode: String,
    os: String,
    arch: String,
    health_score: u8,
    state_dir: String,
    plugin_count: Option<usize>,
    registry_index_present: bool,
    registry_generated_at: Option<String>,
    registry_age_days: Option<i64>,
    metrics: SystemMetricsOutput,
    overall_passed: bool,
    checks: Vec<SystemStatusCheckOutput>,
    suggested_actions: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SystemMetricsOutput {
    cpu_cores: Option<usize>,
    load_avg_1m_milli: Option<u64>,
    load_avg_5m_milli: Option<u64>,
    load_avg_15m_milli: Option<u64>,
    uptime_seconds: Option<u64>,
    memory_total_bytes: Option<u64>,
    memory_used_bytes: Option<u64>,
    memory_used_pct: Option<u64>,
    disk_total_bytes: Option<u64>,
    disk_available_bytes: Option<u64>,
    disk_free_pct: Option<u64>,
    process_count: Option<u64>,
    network_rx_bytes: Option<u64>,
    network_tx_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TouchIdOutput {
    mode: String,
    action: String,
    supported_os: bool,
    configured: bool,
    would_change: bool,
    applied: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CompletionOutput {
    mode: String,
    shell: String,
    generated: bool,
    installed: bool,
    changed: bool,
    config_path: Option<String>,
    snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script: Option<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UpdateOutput {
    mode: String,
    channel: String,
    force: bool,
    current_version: String,
    latest_version: Option<String>,
    update_available: Option<bool>,
    install_source: String,
    suggested_command: String,
    executed: bool,
    checks: Vec<SystemStatusCheckOutput>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RemoveOutput {
    mode: String,
    executable: String,
    detected_paths: Vec<String>,
    removed_paths: Vec<String>,
    skipped_paths: Vec<String>,
    manual_steps: Vec<String>,
    warnings: Vec<String>,
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
        CliCommand::Purge {
            dry_run,
            confirm,
            paths,
            json,
        } => run_purge_with_executor(*dry_run, *confirm, *paths, *json, clean_executor)
            .map_err(CliError::from),
        CliCommand::Installer {
            dry_run,
            confirm,
            paths,
            json,
        } => run_installer_with_executor(*dry_run, *confirm, *paths, *json, clean_executor)
            .map_err(CliError::from),
        CliCommand::Uninstall {
            target,
            dry_run,
            confirm,
            paths,
            json,
        } => run_uninstall_with_executor(
            target.as_deref(),
            *dry_run,
            *confirm,
            *paths,
            *json,
            clean_executor,
        )
        .map_err(CliError::from),
        CliCommand::Optimize {
            dry_run,
            confirm,
            json,
        } => run_optimize_with_executor(*dry_run, *confirm, *json, clean_executor)
            .map_err(CliError::from),
        CliCommand::Analyze {
            path,
            max_depth,
            json,
        } => run_analyze(path.clone(), *max_depth, *json).map_err(CliError::from),
        CliCommand::Status { json } => run_status(*json).map_err(CliError::from),
        CliCommand::Check { fix, json } => run_check(*fix, *json).map_err(CliError::from),
        CliCommand::Touchid {
            action,
            dry_run,
            json,
        } => run_touchid(*action, *dry_run, *json).map_err(CliError::from),
        CliCommand::Completion {
            shell,
            dry_run,
            json,
        } => run_completion(*shell, *dry_run, *json).map_err(CliError::from),
        CliCommand::Update {
            force,
            nightly,
            json,
        } => run_update(*force, *nightly, *json).map_err(CliError::from),
        CliCommand::Remove { dry_run, json } => run_remove(*dry_run, *json).map_err(CliError::from),
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

fn run_plugin(cmd: &PluginCommand, verifier: &dyn SignatureVerifier) -> Result<(), String> {
    match cmd {
        PluginCommand::Install {
            spec,
            lockfile,
            verbose,
            json,
        } => install_plugin(spec, lockfile.clone(), *json, *verbose, verifier),
        PluginCommand::Preflight {
            spec,
            all,
            lockfile,
            json,
            verbose,
        } => preflight_plugin(
            spec.as_deref(),
            *all,
            lockfile.clone(),
            *json,
            *verbose,
            verifier,
        ),
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
            verbose,
        } => test_plugin(
            target.as_deref(),
            *all,
            lockfile.clone(),
            *json,
            *verbose,
            verifier,
        ),
        PluginCommand::Update {
            pack_id,
            lockfile,
            verbose,
            json,
        } => update_plugin(pack_id, lockfile.clone(), *json, *verbose, verifier),
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

fn new_cli_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| err_with(CliErrorKind::Internal, "tokio runtime init failed", e))
}

fn execute_action_with_default_policy(
    runtime: &tokio::runtime::Runtime,
    manifest: &Manifest,
    rule: &RuleFile,
    dry_run: bool,
    confirm: bool,
    clean_executor: &dyn ActionExecutorPort,
    map_runtime_error: fn(RuntimeExecutionError) -> String,
) -> Result<(u64, u64, Vec<String>, usize), String> {
    let policy = DefaultSafetyPolicy::default();
    let sink = CollectingAuditSink::default();
    let mode = if dry_run {
        ExecutionMode::DryRun
    } else {
        ExecutionMode::Apply
    };
    let result = runtime
        .block_on(execute_action_with_audit(
            manifest,
            rule,
            mode,
            if confirm { Some("confirmed") } else { None },
            &policy,
            clean_executor,
            Some(&sink),
        ))
        .map_err(map_runtime_error)?;
    Ok((
        result.affected_items,
        result.freed_bytes,
        result.warnings,
        sink.event_count(),
    ))
}

#[derive(Debug, Clone, Copy)]
struct OptimizeTaskSpec {
    id: &'static str,
    label: &'static str,
    command: &'static [&'static str],
}

fn optimize_task_specs() -> Vec<OptimizeTaskSpec> {
    if cfg!(target_os = "macos") {
        return vec![
            OptimizeTaskSpec {
                id: "flush_dns_cache",
                label: "Flush DNS cache",
                command: &["dscacheutil", "-flushcache"],
            },
            OptimizeTaskSpec {
                id: "restart_mdns_responder",
                label: "Restart mDNSResponder",
                command: &["killall", "-HUP", "mDNSResponder"],
            },
        ];
    }
    if cfg!(target_os = "linux") {
        return vec![OptimizeTaskSpec {
            id: "sync_filesystem_buffers",
            label: "Sync filesystem buffers",
            command: &["sync"],
        }];
    }
    Vec::new()
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

fn run_purge_with_executor(
    dry_run: bool,
    confirm: bool,
    paths: bool,
    json: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<(), String> {
    if paths {
        let roots = normalize_purge_roots(resolve_purge_roots());
        if json {
            println!(
                "{}",
                to_json_envelope("system.purge.paths", PurgePathsOutput { roots })?
            );
            return Ok(());
        }
        println!("Purge scan roots:");
        for root in &roots {
            println!("- {root}");
        }
        return Ok(());
    }

    let output = run_purge_output_with_executor(dry_run, confirm, clean_executor)?;
    if json {
        println!("{}", purge_json(output.clone())?);
        return Ok(());
    }

    println!("Purge ({})", if dry_run { "dry-run" } else { "apply" });
    println!("Scanned roots: {}", output.scanned_roots);
    println!("Scanned directories: {}", output.scanned_dirs);
    println!("Targets: {}", output.target_count);
    println!(
        "Estimated reclaimable: {}",
        format_bytes(output.estimated_freed_bytes)
    );
    if !output.preview_paths.is_empty() {
        println!("Preview:");
        for path in &output.preview_paths {
            println!("- {path}");
        }
    }
    println!("Affected items: {}", output.affected_items);
    println!("Freed bytes: {}", format_bytes(output.freed_bytes));
    if !output.warnings.is_empty() {
        println!("Warnings:");
        for warning in &output.warnings {
            println!("- {warning}");
        }
    }
    println!("Audit events: {}", output.audit_events);

    Ok(())
}

fn run_installer_with_executor(
    dry_run: bool,
    confirm: bool,
    paths: bool,
    json: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<(), String> {
    if paths {
        let roots = normalize_installer_roots(resolve_installer_roots());
        if json {
            println!(
                "{}",
                to_json_envelope("system.installer.paths", InstallerPathsOutput { roots })?
            );
            return Ok(());
        }
        println!("Installer scan roots:");
        for root in &roots {
            println!("- {root}");
        }
        return Ok(());
    }

    let output = run_installer_output_with_executor(dry_run, confirm, clean_executor)?;
    if json {
        println!("{}", installer_json(output.clone())?);
        return Ok(());
    }

    println!("Installer ({})", if dry_run { "dry-run" } else { "apply" });
    println!("Scanned roots: {}", output.scanned_roots);
    println!("Scanned files: {}", output.scanned_files);
    println!("Targets: {}", output.target_count);
    println!(
        "Estimated reclaimable: {}",
        format_bytes(output.estimated_freed_bytes)
    );
    if !output.preview_paths.is_empty() {
        println!("Preview:");
        for path in &output.preview_paths {
            println!("- {path}");
        }
    }
    println!("Affected items: {}", output.affected_items);
    println!("Freed bytes: {}", format_bytes(output.freed_bytes));
    if !output.warnings.is_empty() {
        println!("Warnings:");
        for warning in &output.warnings {
            println!("- {warning}");
        }
    }
    println!("Audit events: {}", output.audit_events);

    Ok(())
}

fn run_installer_output_with_executor(
    dry_run: bool,
    confirm: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<InstallerCommandOutput, String> {
    if !dry_run && !confirm {
        return Err(err_code(
            CliErrorKind::Validation,
            "installer_confirmation_required",
            "installer apply mode requires --confirm",
        ));
    }

    let roots = normalize_installer_roots(resolve_installer_roots());
    if roots.is_empty() {
        return Err(err_code(
            CliErrorKind::Unsupported,
            "installer_no_roots",
            "installer has no configured scan roots",
        ));
    }

    let (selection, scanned_files, mut warnings) =
        scan_installer_candidates(&roots, installer_scan_depth(), installer_min_size_bytes());
    let selected_paths = selection
        .iter()
        .map(|item| item.path.clone())
        .collect::<Vec<_>>();
    let estimated_freed_bytes: u64 = selection.iter().map(|item| item.size).sum();
    enforce_installer_scope(&selected_paths, &roots)?;
    let preview_paths = clean_preview_paths(&selected_paths, installer_preview_limit());

    if selected_paths.is_empty() {
        warnings.push("no installer files selected".to_string());
        return Ok(InstallerCommandOutput {
            mode: if dry_run {
                "dry_run".to_string()
            } else {
                "apply".to_string()
            },
            scanned_roots: roots.len(),
            scanned_files,
            target_count: 0,
            estimated_freed_bytes: 0,
            preview_paths: Vec::new(),
            affected_items: 0,
            freed_bytes: 0,
            warnings,
            audit_events: 0,
        });
    }

    let manifest = Manifest {
        schema_version: 1,
        pack_id: "preen.builtin.installer".to_string(),
        name: "Built-in Installer Cleanup".to_string(),
        version: "0.1.0".to_string(),
        description: "Built-in installer cleanup plan".to_string(),
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
        capabilities: vec![Capability::FsRead, Capability::FsDelete],
        signing: None,
        rules: vec![RuleRef {
            id: "builtin-installer".to_string(),
            name: "Built-in Installer Cleanup".to_string(),
            rule_file: "builtin".to_string(),
        }],
    };
    let rule = RuleFile {
        schema_version: 1,
        id: "builtin-installer".to_string(),
        name: "Built-in Installer Cleanup".to_string(),
        category: ItemCategory::OldDownloads,
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
            action_type: ActionType::DeletePaths,
            paths: selected_paths.clone(),
            command: Vec::new(),
            mode: None,
            timeout_sec: Some(600),
            allow_globs: false,
            max_items: Some(25_000),
            package_manager: None,
            project_types: Vec::new(),
            params: std::collections::HashMap::new(),
        },
    };

    let runtime = new_cli_runtime()?;
    let (affected_items, freed_bytes, runtime_warnings, audit_events) =
        execute_action_with_default_policy(
            &runtime,
            &manifest,
            &rule,
            dry_run,
            confirm,
            clean_executor,
            map_installer_runtime_error,
        )?;
    warnings.extend(runtime_warnings);

    Ok(InstallerCommandOutput {
        mode: if dry_run {
            "dry_run".to_string()
        } else {
            "apply".to_string()
        },
        scanned_roots: roots.len(),
        scanned_files,
        target_count: selected_paths.len(),
        estimated_freed_bytes,
        preview_paths,
        affected_items,
        freed_bytes,
        warnings,
        audit_events,
    })
}

fn run_uninstall_with_executor(
    target: Option<&str>,
    dry_run: bool,
    confirm: bool,
    paths: bool,
    json: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<(), String> {
    if paths {
        let roots = normalize_uninstall_roots(resolve_uninstall_roots());
        if json {
            println!(
                "{}",
                to_json_envelope("system.uninstall.paths", UninstallPathsOutput { roots })?
            );
            return Ok(());
        }
        println!("Uninstall scan roots:");
        for root in &roots {
            println!("- {root}");
        }
        return Ok(());
    }

    let output = run_uninstall_output_with_executor(target, dry_run, confirm, clean_executor)?;
    if json {
        println!("{}", uninstall_json(output.clone())?);
        return Ok(());
    }

    println!("Uninstall ({})", if dry_run { "dry-run" } else { "apply" });
    println!("Target: {}", output.target);
    println!("Scanned roots: {}", output.scanned_roots);
    println!("Scanned entries: {}", output.scanned_entries);
    println!("Targets: {}", output.target_count);
    println!(
        "Estimated reclaimable: {}",
        format_bytes(output.estimated_freed_bytes)
    );
    if !output.preview_paths.is_empty() {
        println!("Preview:");
        for path in &output.preview_paths {
            println!("- {path}");
        }
    }
    println!("Affected items: {}", output.affected_items);
    println!("Freed bytes: {}", format_bytes(output.freed_bytes));
    if !output.warnings.is_empty() {
        println!("Warnings:");
        for warning in &output.warnings {
            println!("- {warning}");
        }
    }
    println!("Audit events: {}", output.audit_events);

    Ok(())
}

fn run_uninstall_output_with_executor(
    target: Option<&str>,
    dry_run: bool,
    confirm: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<UninstallCommandOutput, String> {
    let target = target
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            err_code(
                CliErrorKind::Validation,
                "uninstall_target_required",
                "uninstall requires a target argument",
            )
        })?;
    if !dry_run && !confirm {
        return Err(err_code(
            CliErrorKind::Validation,
            "uninstall_confirmation_required",
            "uninstall apply mode requires --confirm",
        ));
    }

    let roots = normalize_uninstall_roots(resolve_uninstall_roots());
    if roots.is_empty() {
        return Err(err_code(
            CliErrorKind::Unsupported,
            "uninstall_no_roots",
            "uninstall has no configured scan roots",
        ));
    }

    let (selection, scanned_entries, mut warnings) =
        scan_uninstall_candidates(&roots, target, uninstall_scan_depth());
    let selected_paths = selection
        .iter()
        .map(|item| item.path.clone())
        .collect::<Vec<_>>();
    let estimated_freed_bytes: u64 = selection.iter().map(|item| item.size).sum();
    enforce_uninstall_scope(&selected_paths, &roots)?;
    let preview_paths = clean_preview_paths(&selected_paths, uninstall_preview_limit());

    if selected_paths.is_empty() {
        warnings.push("no uninstall targets selected".to_string());
        return Ok(UninstallCommandOutput {
            mode: if dry_run {
                "dry_run".to_string()
            } else {
                "apply".to_string()
            },
            target: target.to_string(),
            scanned_roots: roots.len(),
            scanned_entries,
            target_count: 0,
            estimated_freed_bytes: 0,
            preview_paths: Vec::new(),
            affected_items: 0,
            freed_bytes: 0,
            warnings,
            audit_events: 0,
        });
    }

    let manifest = Manifest {
        schema_version: 1,
        pack_id: "preen.builtin.uninstall".to_string(),
        name: "Built-in Uninstall".to_string(),
        version: "0.1.0".to_string(),
        description: "Built-in uninstall plan".to_string(),
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
        capabilities: vec![Capability::FsRead, Capability::FsDelete],
        signing: None,
        rules: vec![RuleRef {
            id: "builtin-uninstall".to_string(),
            name: "Built-in Uninstall".to_string(),
            rule_file: "builtin".to_string(),
        }],
    };
    let rule = RuleFile {
        schema_version: 1,
        id: "builtin-uninstall".to_string(),
        name: "Built-in Uninstall".to_string(),
        category: ItemCategory::Other("app_uninstall".to_string()),
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
            action_type: ActionType::DeletePaths,
            paths: selected_paths.clone(),
            command: Vec::new(),
            mode: None,
            timeout_sec: Some(600),
            allow_globs: false,
            max_items: Some(25_000),
            package_manager: None,
            project_types: Vec::new(),
            params: std::collections::HashMap::new(),
        },
    };

    let runtime = new_cli_runtime()?;
    let (affected_items, freed_bytes, runtime_warnings, audit_events) =
        execute_action_with_default_policy(
            &runtime,
            &manifest,
            &rule,
            dry_run,
            confirm,
            clean_executor,
            map_uninstall_runtime_error,
        )?;
    warnings.extend(runtime_warnings);

    Ok(UninstallCommandOutput {
        mode: if dry_run {
            "dry_run".to_string()
        } else {
            "apply".to_string()
        },
        target: target.to_string(),
        scanned_roots: roots.len(),
        scanned_entries,
        target_count: selected_paths.len(),
        estimated_freed_bytes,
        preview_paths,
        affected_items,
        freed_bytes,
        warnings,
        audit_events,
    })
}

fn run_optimize_with_executor(
    dry_run: bool,
    confirm: bool,
    json: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<(), String> {
    let output = run_optimize_output_with_executor(dry_run, confirm, clean_executor)?;
    if json {
        println!("{}", optimize_json(output.clone())?);
        return Ok(());
    }

    println!("Optimize ({})", if dry_run { "dry-run" } else { "apply" });
    println!("OS: {}", output.os);
    println!("Tasks: {}", output.task_count);
    if !output.executed_tasks.is_empty() {
        println!("Executed tasks:");
        for task in &output.executed_tasks {
            println!("- {task}");
        }
    }
    println!("Affected items: {}", output.affected_items);
    println!("Post-check run: {}", output.post_check_run);
    if let Some(value) = output.post_check_overall_passed {
        println!("Post-check overall_passed: {value}");
    }
    if !output.post_check_suggested_actions.is_empty() {
        println!(
            "Post-check suggested actions: {}",
            output.post_check_suggested_actions.len()
        );
        for action in &output.post_check_suggested_actions {
            println!("- {action}");
        }
    }
    if !output.warnings.is_empty() {
        println!("Warnings:");
        for warning in &output.warnings {
            println!("- {warning}");
        }
    }
    println!("Audit events: {}", output.audit_events);
    Ok(())
}

fn run_optimize_output_with_executor(
    dry_run: bool,
    confirm: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<OptimizeCommandOutput, String> {
    if !dry_run && !confirm {
        return Err(err_code(
            CliErrorKind::Validation,
            "optimize_confirmation_required",
            "optimize apply mode requires --confirm",
        ));
    }

    let tasks = optimize_task_specs();
    if tasks.is_empty() {
        return Err(err_code(
            CliErrorKind::Unsupported,
            "optimize_no_tasks",
            "optimize is not supported on this OS",
        ));
    }

    let manifest = Manifest {
        schema_version: 1,
        pack_id: "preen.builtin.optimize".to_string(),
        name: "Built-in Optimize".to_string(),
        version: "0.1.0".to_string(),
        description: "Built-in optimize plan".to_string(),
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
        capabilities: vec![Capability::RunCommand, Capability::SystemOptimize],
        signing: None,
        rules: tasks
            .iter()
            .map(|task| RuleRef {
                id: format!("builtin-optimize-{}", task.id),
                name: format!("Built-in Optimize {}", task.label),
                rule_file: "builtin".to_string(),
            })
            .collect(),
    };

    let mode = if dry_run {
        ExecutionMode::DryRun
    } else {
        ExecutionMode::Apply
    };
    let policy = DefaultSafetyPolicy::default();
    let sink = CollectingAuditSink::default();
    let runtime = new_cli_runtime()?;

    let mut affected_items = 0_u64;
    let mut warnings = Vec::new();
    let mut executed_tasks = Vec::with_capacity(tasks.len());
    for task in &tasks {
        let mut params = std::collections::HashMap::new();
        params.insert("command_allowlist".to_string(), task.command[0].to_string());
        let rule = RuleFile {
            schema_version: 1,
            id: format!("builtin-optimize-{}", task.id),
            name: format!("Built-in Optimize {}", task.label),
            category: ItemCategory::Other("system_optimization".to_string()),
            risk: RiskLevel::Medium,
            enabled: true,
            matcher: MatchSpec {
                mode: MatchMode::Command,
                paths: Vec::new(),
                strategy: None,
                command: task.command.iter().map(|part| part.to_string()).collect(),
                parser: None,
            },
            action: ActionSpec {
                action_type: ActionType::RunCommand,
                paths: Vec::new(),
                command: task.command.iter().map(|part| part.to_string()).collect(),
                mode: None,
                timeout_sec: Some(DEFAULT_OPTIMIZE_TIMEOUT_SEC),
                allow_globs: false,
                max_items: Some(1),
                package_manager: None,
                project_types: Vec::new(),
                params,
            },
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
            .map_err(map_optimize_runtime_error)?;
        affected_items += result.affected_items;
        warnings.extend(result.warnings);
        executed_tasks.push(task.label.to_string());
    }

    let (post_check_run, post_check_overall_passed, post_check_suggested_actions) = if dry_run {
        (false, None, Vec::new())
    } else {
        let post_check = run_check_output(false);
        let suggested_actions = post_check
            .suggested_actions
            .into_iter()
            .filter(|action| action != "preen optimize --dry-run")
            .collect::<Vec<_>>();
        if !post_check.overall_passed {
            warnings.push(
                "post-optimize check found remaining issues; review suggested actions".to_string(),
            );
        }
        (true, Some(post_check.overall_passed), suggested_actions)
    };

    Ok(OptimizeCommandOutput {
        mode: if dry_run {
            "dry_run".to_string()
        } else {
            "apply".to_string()
        },
        os: std::env::consts::OS.to_string(),
        task_count: tasks.len(),
        executed_tasks,
        affected_items,
        post_check_run,
        post_check_overall_passed,
        post_check_suggested_actions,
        warnings,
        audit_events: sink.event_count(),
    })
}

fn run_check(fix: bool, json: bool) -> Result<(), String> {
    let output = run_check_output(fix);
    if json {
        println!("{}", check_json(output.clone())?);
        return Ok(());
    }
    print_check_output(&output);
    Ok(())
}

fn run_check_output(fix: bool) -> SystemCheckOutput {
    let mode = if fix { "check_and_fix" } else { "check" }.to_string();
    let mut checks = Vec::new();
    let mut warnings = Vec::new();
    let mut fixes_applied = 0_u64;

    let os_supported = matches!(std::env::consts::OS, "macos" | "linux");
    checks.push(SystemCheckRowOutput {
        id: "os_supported".to_string(),
        label: "Supported OS".to_string(),
        severity: "critical".to_string(),
        passed: os_supported,
        message: if os_supported {
            format!("{} is supported", std::env::consts::OS)
        } else {
            format!("{} is not supported", std::env::consts::OS)
        },
        fixed: false,
    });
    if !os_supported {
        warnings.push(format!("unsupported os: {}", std::env::consts::OS));
    }

    let state_dir = preen_state_dir();
    let mut state_dir_path = None;
    match state_dir {
        Ok(path) => {
            let mut state_dir_passed = path.exists();
            let mut state_dir_fixed = false;
            let state_dir_message = if state_dir_passed {
                format!("state dir exists: {}", path.display())
            } else if fix {
                match fs::create_dir_all(&path) {
                    Ok(_) => {
                        state_dir_passed = true;
                        state_dir_fixed = true;
                        fixes_applied += 1;
                        format!("state dir created: {}", path.display())
                    }
                    Err(err) => {
                        warnings.push(format!("state dir create failed: {err}"));
                        format!("state dir create failed: {err}")
                    }
                }
            } else {
                format!("state dir missing: {}", path.display())
            };
            checks.push(SystemCheckRowOutput {
                id: "state_dir_exists".to_string(),
                label: "State directory exists".to_string(),
                severity: "critical".to_string(),
                passed: state_dir_passed,
                message: state_dir_message,
                fixed: state_dir_fixed,
            });
            state_dir_path = Some(path);
        }
        Err(message) => {
            warnings.push(message.clone());
            checks.push(SystemCheckRowOutput {
                id: "state_dir_exists".to_string(),
                label: "State directory exists".to_string(),
                severity: "critical".to_string(),
                passed: false,
                message,
                fixed: false,
            });
        }
    }

    if let Some(state_dir) = state_dir_path {
        let mut writable = true;
        let mut writable_message = "state dir is writable".to_string();
        if let Err(err) = fs::create_dir_all(&state_dir) {
            writable = false;
            writable_message = format!("state dir create check failed: {err}");
        } else {
            let probe = state_dir.join(".preen-check-write-probe");
            match fs::write(&probe, b"probe") {
                Ok(_) => {
                    let _ = fs::remove_file(&probe);
                }
                Err(err) => {
                    writable = false;
                    writable_message = format!("state dir write probe failed: {err}");
                }
            }
        }
        if !writable {
            warnings.push(writable_message.clone());
        }
        checks.push(SystemCheckRowOutput {
            id: "state_dir_writable".to_string(),
            label: "State directory writable".to_string(),
            severity: "critical".to_string(),
            passed: writable,
            message: writable_message,
            fixed: false,
        });

        let plugins_dir = state_dir.join("plugins");
        let mut plugins_dir_passed = plugins_dir.exists();
        let mut plugins_dir_fixed = false;
        let plugins_dir_message = if plugins_dir_passed {
            format!("plugins dir exists: {}", plugins_dir.display())
        } else if fix {
            match fs::create_dir_all(&plugins_dir) {
                Ok(_) => {
                    plugins_dir_passed = true;
                    plugins_dir_fixed = true;
                    fixes_applied += 1;
                    format!("plugins dir created: {}", plugins_dir.display())
                }
                Err(err) => {
                    warnings.push(format!("plugins dir create failed: {err}"));
                    format!("plugins dir create failed: {err}")
                }
            }
        } else {
            format!("plugins dir missing: {}", plugins_dir.display())
        };
        checks.push(SystemCheckRowOutput {
            id: "plugins_dir_exists".to_string(),
            label: "Plugin directory exists".to_string(),
            severity: "warning".to_string(),
            passed: plugins_dir_passed,
            message: plugins_dir_message,
            fixed: plugins_dir_fixed,
        });

        let registry_index =
            registry_index_path().unwrap_or_else(|_| state_dir.join("registry-index.toml"));
        let mut registry_age_days = None;
        checks.push(SystemCheckRowOutput {
            id: "registry_index_present".to_string(),
            label: "Registry index present".to_string(),
            severity: "warning".to_string(),
            passed: registry_index.exists(),
            message: if registry_index.exists() {
                format!("registry index found: {}", registry_index.display())
            } else {
                format!(
                    "registry index missing: {} (run `preen plugin registry-update`)",
                    registry_index.display()
                )
            },
            fixed: false,
        });
        if registry_index.exists() {
            match fs::read_to_string(&registry_index) {
                Ok(content) => match toml::from_str::<RegistryIndex>(&content) {
                    Ok(index) => {
                        if let Some(generated_at) = index.generated_at
                            && let Ok(parsed) = OffsetDateTime::parse(&generated_at, &Rfc3339)
                        {
                            let age = OffsetDateTime::now_utc() - parsed;
                            registry_age_days = Some(age.whole_days());
                        }
                    }
                    Err(err) => warnings.push(format!("registry index parse failed: {err}")),
                },
                Err(err) => warnings.push(format!("registry index read failed: {err}")),
            }
        }
        let registry_fresh = registry_age_days
            .map(|age| age <= DEFAULT_REGISTRY_MAX_AGE_DAYS)
            .unwrap_or(true);
        checks.push(SystemCheckRowOutput {
            id: "registry_index_fresh".to_string(),
            label: "Registry index fresh".to_string(),
            severity: "warning".to_string(),
            passed: registry_fresh,
            message: match registry_age_days {
                Some(age) => format!("registry index age: {age} days"),
                None => "registry index freshness unknown".to_string(),
            },
            fixed: false,
        });
    }

    let overall_passed = checks.iter().all(|check| {
        if check.severity == "critical" {
            check.passed
        } else {
            true
        }
    });
    let state_issue = has_failed_check_rows(&checks, &["state_dir_exists", "state_dir_writable"]);
    let registry_issue =
        has_failed_check_rows(&checks, &["registry_index_present", "registry_index_fresh"]);
    let mut suggested_actions = build_core_maintenance_actions(state_issue, registry_issue, !fix);
    if overall_passed {
        push_unique_action(&mut suggested_actions, "preen optimize --dry-run");
    }

    SystemCheckOutput {
        mode,
        overall_passed,
        checks,
        fixes_applied,
        suggested_actions,
        warnings,
    }
}

fn check_json(out: SystemCheckOutput) -> Result<String, String> {
    to_json_envelope("system.check", out)
}

fn print_check_output(out: &SystemCheckOutput) {
    println!(
        "summary: kind=system_check overall_passed={}",
        out.overall_passed
    );
    println!("mode: {}", out.mode);
    println!("checks: label=Checks");
    for check in &out.checks {
        println!(
            "check: id={} label={} severity={} passed={} fixed={} message={}",
            check.id, check.label, check.severity, check.passed, check.fixed, check.message
        );
    }
    println!("fixes_applied: {}", out.fixes_applied);
    if !out.suggested_actions.is_empty() {
        println!("suggested_actions: count={}", out.suggested_actions.len());
        for action in &out.suggested_actions {
            println!("suggested_action: {action}");
        }
    }
    if !out.warnings.is_empty() {
        println!("warnings: count={}", out.warnings.len());
        for warning in &out.warnings {
            println!("warning: {warning}");
        }
    }
}

fn run_analyze(path: Option<PathBuf>, max_depth: Option<usize>, json: bool) -> Result<(), String> {
    let output = run_analyze_output(path, max_depth)?;
    if json {
        println!("{}", analyze_json(output.clone())?);
        return Ok(());
    }
    print_analyze_output(&output);
    Ok(())
}

fn run_analyze_output(
    path: Option<PathBuf>,
    max_depth_override: Option<usize>,
) -> Result<AnalyzeOutput, String> {
    let mut warnings = Vec::new();
    let root = normalize_analyze_root(resolve_analyze_root(path)?)?;
    if !root.exists() {
        return Err(err_code(
            CliErrorKind::NotFound,
            "analyze_root_not_found",
            format!("analyze root not found: {}", root.display()),
        ));
    }
    if !root.is_dir() {
        return Err(err_code(
            CliErrorKind::Validation,
            "analyze_root_not_directory",
            format!("analyze root is not a directory: {}", root.display()),
        ));
    }

    let max_depth = analyze_max_depth(max_depth_override);
    let mut scanned_entries = 0_usize;
    let mut top_entries = Vec::new();
    let mut aggregate_stats = AnalyzeStats {
        files: 0,
        dirs: 1,
        size_bytes: 0,
        truncated_dirs: 0,
    };
    let read_dir = fs::read_dir(&root).map_err(|e| {
        err_code(
            CliErrorKind::Io,
            "analyze_target_not_readable",
            format!("analyze root read failed: {}: {e}", root.display()),
        )
    })?;
    for child in read_dir {
        let child = match child {
            Ok(value) => value,
            Err(error) => {
                warnings.push(format!("analyze read_dir entry failed: {error}"));
                continue;
            }
        };
        scanned_entries += 1;
        let child_path = child.path();
        let metadata = match fs::symlink_metadata(&child_path) {
            Ok(value) => value,
            Err(error) => {
                warnings.push(format!(
                    "analyze metadata failed: {}: {error}",
                    child_path.display()
                ));
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            let link_size = metadata.len();
            aggregate_stats.files += 1;
            aggregate_stats.size_bytes += link_size;
            top_entries.push(AnalyzeEntryOutput {
                name: child.file_name().to_string_lossy().to_string(),
                path: child_path.display().to_string(),
                item_type: "symlink".to_string(),
                size_bytes: link_size,
            });
            continue;
        }
        let stats = if metadata.is_dir() {
            analyze_path_stats(&child_path, max_depth, &mut warnings)
        } else if metadata.is_file() {
            AnalyzeStats {
                files: 1,
                dirs: 0,
                size_bytes: metadata.len(),
                truncated_dirs: 0,
            }
        } else {
            AnalyzeStats {
                files: 0,
                dirs: 0,
                size_bytes: 0,
                truncated_dirs: 0,
            }
        };
        aggregate_stats.files += stats.files;
        aggregate_stats.dirs += stats.dirs;
        aggregate_stats.size_bytes += stats.size_bytes;
        aggregate_stats.truncated_dirs += stats.truncated_dirs;
        let item_type = if metadata.is_dir() {
            "dir"
        } else if metadata.is_file() {
            "file"
        } else {
            "other"
        };
        top_entries.push(AnalyzeEntryOutput {
            name: child.file_name().to_string_lossy().to_string(),
            path: child_path.display().to_string(),
            item_type: item_type.to_string(),
            size_bytes: stats.size_bytes,
        });
    }

    top_entries.sort_by(|left, right| {
        right
            .size_bytes
            .cmp(&left.size_bytes)
            .then_with(|| left.path.cmp(&right.path))
    });
    top_entries.truncate(analyze_top_entries());
    let warnings = dedupe_warnings_with_limit(warnings, analyze_warning_limit());
    let root_display = root.display().to_string();
    Ok(AnalyzeOutput {
        root: root_display.clone(),
        path: root_display,
        max_depth,
        scanned_entries,
        total_files: aggregate_stats.files,
        total_dirs: aggregate_stats.dirs,
        total_size_bytes: aggregate_stats.size_bytes,
        total_size: aggregate_stats.size_bytes,
        truncated_dirs: aggregate_stats.truncated_dirs,
        entries: top_entries.clone(),
        top_entries,
        warnings,
    })
}

fn resolve_analyze_root(path: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(value) = path {
        return Ok(value);
    }
    if let Some(value) =
        std::env::var_os("PREEN_ANALYZE_PATH").or_else(|| std::env::var_os("MO_ANALYZE_PATH"))
    {
        return Ok(PathBuf::from(value));
    }
    dirs::home_dir().ok_or_else(|| {
        err_code(
            CliErrorKind::Io,
            "analyze_home_missing",
            "analyze default root requires a home directory",
        )
    })
}

fn normalize_analyze_root(root: PathBuf) -> Result<PathBuf, String> {
    if root.is_absolute() {
        return Ok(root);
    }
    let cwd = std::env::current_dir().map_err(|error| {
        err_code(
            CliErrorKind::Io,
            "analyze_cwd_unavailable",
            format!("analyze current directory resolve failed: {error}"),
        )
    })?;
    Ok(cwd.join(root))
}

fn analyze_path_stats(path: &Path, max_depth: usize, warnings: &mut Vec<String>) -> AnalyzeStats {
    fn walk(
        path: &Path,
        depth: usize,
        max_depth: usize,
        warnings: &mut Vec<String>,
    ) -> AnalyzeStats {
        let metadata = match fs::symlink_metadata(path) {
            Ok(value) => value,
            Err(error) => {
                warnings.push(format!(
                    "analyze metadata failed: {}: {error}",
                    path.display()
                ));
                return AnalyzeStats {
                    files: 0,
                    dirs: 0,
                    size_bytes: 0,
                    truncated_dirs: 0,
                };
            }
        };

        if metadata.file_type().is_symlink() {
            return AnalyzeStats {
                files: 1,
                dirs: 0,
                size_bytes: metadata.len(),
                truncated_dirs: 0,
            };
        }

        if metadata.is_file() {
            return AnalyzeStats {
                files: 1,
                dirs: 0,
                size_bytes: metadata.len(),
                truncated_dirs: 0,
            };
        }

        if !metadata.is_dir() {
            return AnalyzeStats {
                files: 0,
                dirs: 0,
                size_bytes: 0,
                truncated_dirs: 0,
            };
        }

        let mut stats = AnalyzeStats {
            files: 0,
            dirs: 1,
            size_bytes: 0,
            truncated_dirs: 0,
        };
        if depth >= max_depth {
            stats.truncated_dirs = 1;
            return stats;
        }

        let read_dir = match fs::read_dir(path) {
            Ok(value) => value,
            Err(error) => {
                warnings.push(format!(
                    "analyze read_dir failed: {}: {error}",
                    path.display()
                ));
                return stats;
            }
        };
        for child in read_dir {
            let child = match child {
                Ok(value) => value,
                Err(error) => {
                    warnings.push(format!("analyze read_dir entry failed: {error}"));
                    continue;
                }
            };
            let child_stats = walk(&child.path(), depth + 1, max_depth, warnings);
            stats.files += child_stats.files;
            stats.dirs += child_stats.dirs;
            stats.size_bytes += child_stats.size_bytes;
            stats.truncated_dirs += child_stats.truncated_dirs;
        }
        stats
    }

    walk(path, 0, max_depth, warnings)
}

fn analyze_max_depth(override_value: Option<usize>) -> usize {
    if let Some(value) = override_value.filter(|value| *value > 0) {
        return value;
    }
    std::env::var("PREEN_ANALYZE_MAX_DEPTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ANALYZE_MAX_DEPTH)
}

fn analyze_top_entries() -> usize {
    std::env::var("PREEN_ANALYZE_TOP_ENTRIES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ANALYZE_TOP_ENTRIES)
}

fn analyze_warning_limit() -> usize {
    std::env::var("PREEN_ANALYZE_WARNING_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100)
}

fn dedupe_warnings_with_limit(warnings: Vec<String>, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for warning in warnings {
        if seen.insert(warning.clone()) {
            out.push(warning);
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

fn analyze_json(out: AnalyzeOutput) -> Result<String, String> {
    to_json_envelope("system.analyze", out)
}

fn print_analyze_output(out: &AnalyzeOutput) {
    println!("summary: kind=system_analyze");
    println!("root: {}", out.root);
    println!("max_depth: {}", out.max_depth);
    println!("scanned_entries: {}", out.scanned_entries);
    println!("total_files: {}", out.total_files);
    println!("total_dirs: {}", out.total_dirs);
    println!("total_size: {}", format_bytes(out.total_size_bytes));
    println!("truncated_dirs: {}", out.truncated_dirs);
    println!("entries: label=Top entries");
    for entry in &out.top_entries {
        println!(
            "entry: name={} type={} size={} path={}",
            entry.name,
            entry.item_type,
            format_bytes(entry.size_bytes),
            entry.path
        );
    }
    if !out.warnings.is_empty() {
        println!("warnings: count={}", out.warnings.len());
        for warning in &out.warnings {
            println!("warning: {warning}");
        }
    }
}

fn run_status(json: bool) -> Result<(), String> {
    let output = run_status_output()?;
    if should_emit_status_json(json) {
        println!("{}", status_json(output.clone())?);
        return Ok(());
    }
    print_status_output(&output);
    Ok(())
}

fn should_emit_status_json(json_flag: bool) -> bool {
    if json_flag {
        return true;
    }
    if let Ok(value) = std::env::var("PREEN_STATUS_FORCE_JSON") {
        let normalized = value.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes" | "on") {
            return true;
        }
        if matches!(normalized.as_str(), "0" | "false" | "no" | "off") {
            return false;
        }
    }
    !std::io::stdout().is_terminal()
}

fn run_status_output() -> Result<StatusOutput, String> {
    let mut warnings = Vec::new();
    let state_dir = preen_state_dir().map_err(|error| {
        let decoded = CliError::from(error);
        err_code(
            decoded.kind,
            "status_state_dir_unavailable",
            decoded.message,
        )
    })?;

    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let mut checks = Vec::new();

    let state_exists = state_dir.exists();
    checks.push(SystemStatusCheckOutput {
        id: "state_dir_exists".to_string(),
        label: "State directory exists".to_string(),
        severity: "critical".to_string(),
        passed: state_exists,
        message: if state_exists {
            format!("state dir exists: {}", state_dir.display())
        } else {
            format!("state dir missing: {}", state_dir.display())
        },
    });

    let (state_writable, state_writable_message) = if state_exists {
        let probe = state_dir.join(".preen-status-write-probe");
        match fs::write(&probe, b"probe") {
            Ok(_) => {
                let _ = fs::remove_file(&probe);
                (true, "state dir is writable".to_string())
            }
            Err(error) => (false, format!("state dir write probe failed: {error}")),
        }
    } else {
        (false, "state dir is not present".to_string())
    };
    if !state_writable {
        warnings.push(state_writable_message.clone());
    }
    checks.push(SystemStatusCheckOutput {
        id: "state_dir_writable".to_string(),
        label: "State directory writable".to_string(),
        severity: "critical".to_string(),
        passed: state_writable,
        message: state_writable_message,
    });

    let lock_path = default_lockfile_path()?;
    let plugin_count = if lock_path.exists() {
        match load_lockfile_at(&lock_path) {
            Ok(lockfile) => Some(lockfile.plugins.len()),
            Err(error) => {
                warnings.push(format!("lockfile read failed: {error}"));
                None
            }
        }
    } else {
        Some(0)
    };
    checks.push(SystemStatusCheckOutput {
        id: "lockfile_readable".to_string(),
        label: "Lockfile readable".to_string(),
        severity: "warning".to_string(),
        passed: plugin_count.is_some(),
        message: if plugin_count.is_some() {
            format!("lockfile readable: {}", lock_path.display())
        } else {
            format!("lockfile read failed: {}", lock_path.display())
        },
    });

    let registry_path = registry_index_path()?;
    let mut registry_generated_at = None;
    let mut registry_age_days = None;
    let registry_index_present = registry_path.exists();
    if registry_index_present {
        match fs::read_to_string(&registry_path) {
            Ok(content) => match toml::from_str::<RegistryIndex>(&content) {
                Ok(index) => {
                    registry_generated_at = index.generated_at.clone();
                    if let Some(generated_at) = index.generated_at
                        && let Ok(parsed) = OffsetDateTime::parse(&generated_at, &Rfc3339)
                    {
                        let age = OffsetDateTime::now_utc() - parsed;
                        registry_age_days = Some(age.whole_days());
                    }
                }
                Err(error) => warnings.push(format!("registry index parse failed: {error}")),
            },
            Err(error) => warnings.push(format!("registry index read failed: {error}")),
        }
    }
    checks.push(SystemStatusCheckOutput {
        id: "registry_index_present".to_string(),
        label: "Registry index present".to_string(),
        severity: "warning".to_string(),
        passed: registry_index_present,
        message: if registry_index_present {
            format!("registry index found: {}", registry_path.display())
        } else {
            format!(
                "registry index missing: {} (run `preen plugin registry-update`)",
                registry_path.display()
            )
        },
    });

    let registry_fresh = registry_age_days
        .map(|age| age <= DEFAULT_REGISTRY_MAX_AGE_DAYS)
        .unwrap_or(true);
    checks.push(SystemStatusCheckOutput {
        id: "registry_index_fresh".to_string(),
        label: "Registry index fresh".to_string(),
        severity: "warning".to_string(),
        passed: registry_fresh,
        message: match registry_age_days {
            Some(age) => format!("registry index age: {age} days"),
            None => "registry index freshness unknown".to_string(),
        },
    });

    let metrics = collect_system_metrics(Path::new(&state_dir), &mut warnings);
    if let (Some(load), Some(cores)) = (metrics.load_avg_1m_milli, metrics.cpu_cores) {
        let threshold = (cores as u64).saturating_mul(2000);
        checks.push(SystemStatusCheckOutput {
            id: "system_load_normal".to_string(),
            label: "System load normal".to_string(),
            severity: "warning".to_string(),
            passed: load <= threshold,
            message: format!(
                "load_1m={} cores={} threshold_milli={threshold}",
                format_load_milli(load),
                cores
            ),
        });
    }
    if let (Some(total), Some(used)) = (metrics.memory_total_bytes, metrics.memory_used_bytes)
        && total > 0
    {
        let usage_pct = ((used as f64 / total as f64) * 100.0).round() as u64;
        checks.push(SystemStatusCheckOutput {
            id: "memory_pressure_ok".to_string(),
            label: "Memory pressure".to_string(),
            severity: "warning".to_string(),
            passed: usage_pct <= 90,
            message: format!("memory_used_pct={usage_pct}"),
        });
    }
    if let (Some(total), Some(available)) = (metrics.disk_total_bytes, metrics.disk_available_bytes)
        && total > 0
    {
        let free_pct = ((available as f64 / total as f64) * 100.0).round() as u64;
        checks.push(SystemStatusCheckOutput {
            id: "disk_space_ok".to_string(),
            label: "Disk free space".to_string(),
            severity: "warning".to_string(),
            passed: free_pct >= 10,
            message: format!("disk_free_pct={free_pct}"),
        });
    }

    let overall_passed = checks
        .iter()
        .all(|check| check.severity != "critical" || check.passed);
    let health_score = status_health_score(&checks);
    let suggested_actions = build_status_suggested_actions(&checks, &metrics);

    Ok(StatusOutput {
        mode: "status".to_string(),
        os,
        arch,
        health_score,
        state_dir: state_dir.display().to_string(),
        plugin_count,
        registry_index_present,
        registry_generated_at,
        registry_age_days,
        metrics,
        overall_passed,
        checks,
        suggested_actions,
        warnings,
    })
}

fn build_status_suggested_actions(
    checks: &[SystemStatusCheckOutput],
    metrics: &SystemMetricsOutput,
) -> Vec<String> {
    let state_issue = has_failed_check_status(checks, &["state_dir_exists", "state_dir_writable"]);
    let registry_issue =
        has_failed_check_status(checks, &["registry_index_present", "registry_index_fresh"]);
    let mut actions = build_core_maintenance_actions(state_issue, registry_issue, true);

    if let Some(free_pct) = metrics.disk_free_pct
        && free_pct < 15
    {
        push_unique_action(&mut actions, "preen analyze --json");
        push_unique_action(&mut actions, "preen clean --dry-run");
        push_unique_action(&mut actions, "preen purge --dry-run");
    }

    if let Some(memory_used_pct) = metrics.memory_used_pct
        && memory_used_pct > 90
    {
        push_unique_action(&mut actions, "preen optimize --dry-run");
    }

    if let (Some(load), Some(cores)) = (metrics.load_avg_1m_milli, metrics.cpu_cores) {
        let threshold = (cores as u64).saturating_mul(2000);
        if load > threshold {
            push_unique_action(&mut actions, "preen optimize --dry-run");
        }
    }

    actions
}

fn push_unique_action(actions: &mut Vec<String>, action: &str) {
    if !actions.iter().any(|existing| existing == action) {
        actions.push(action.to_string());
    }
}

fn build_core_maintenance_actions(
    state_issue: bool,
    registry_issue: bool,
    suggest_fix_command: bool,
) -> Vec<String> {
    let mut actions = Vec::new();
    if state_issue {
        if suggest_fix_command {
            push_unique_action(&mut actions, "preen check --fix");
        } else {
            push_unique_action(&mut actions, "preen check --json");
        }
    }
    if registry_issue {
        push_unique_action(&mut actions, "preen plugin registry-update");
    }
    actions
}

fn has_failed_check_rows(checks: &[SystemCheckRowOutput], ids: &[&str]) -> bool {
    checks
        .iter()
        .any(|check| ids.contains(&check.id.as_str()) && !check.passed)
}

fn has_failed_check_status(checks: &[SystemStatusCheckOutput], ids: &[&str]) -> bool {
    checks
        .iter()
        .any(|check| ids.contains(&check.id.as_str()) && !check.passed)
}

fn collect_system_metrics(state_dir: &Path, warnings: &mut Vec<String>) -> SystemMetricsOutput {
    let cpu_cores = std::thread::available_parallelism()
        .ok()
        .map(|value| value.get());
    let (load_avg_1m_milli, load_avg_5m_milli, load_avg_15m_milli) =
        collect_load_avg_milli(warnings);
    let uptime_seconds = collect_uptime_seconds(warnings);
    let (memory_total_bytes, memory_used_bytes) = collect_memory_bytes(warnings);
    let (disk_total_bytes, disk_available_bytes) = collect_disk_bytes(state_dir, warnings);
    let process_count = collect_process_count(warnings);
    let (network_rx_bytes, network_tx_bytes) = collect_network_bytes(warnings);
    let memory_used_pct = compute_percent(memory_used_bytes, memory_total_bytes);
    let disk_free_pct = compute_percent(disk_available_bytes, disk_total_bytes);
    SystemMetricsOutput {
        cpu_cores,
        load_avg_1m_milli,
        load_avg_5m_milli,
        load_avg_15m_milli,
        uptime_seconds,
        memory_total_bytes,
        memory_used_bytes,
        memory_used_pct,
        disk_total_bytes,
        disk_available_bytes,
        disk_free_pct,
        process_count,
        network_rx_bytes,
        network_tx_bytes,
    }
}

fn collect_load_avg_milli(warnings: &mut Vec<String>) -> (Option<u64>, Option<u64>, Option<u64>) {
    if let Ok(value) = std::env::var("PREEN_STATUS_LOAD_1M_MILLI")
        && let Ok(parsed) = value.trim().parse::<u64>()
    {
        let load_5m = std::env::var("PREEN_STATUS_LOAD_5M_MILLI")
            .ok()
            .and_then(|item| item.trim().parse::<u64>().ok());
        let load_15m = std::env::var("PREEN_STATUS_LOAD_15M_MILLI")
            .ok()
            .and_then(|item| item.trim().parse::<u64>().ok());
        return (Some(parsed), load_5m, load_15m);
    }

    if cfg!(target_os = "linux") {
        match fs::read_to_string("/proc/loadavg") {
            Ok(value) => {
                let mut parts = value.split_whitespace();
                let load_1m = parts.next().and_then(parse_float_to_milli);
                let load_5m = parts.next().and_then(parse_float_to_milli);
                let load_15m = parts.next().and_then(parse_float_to_milli);
                if load_1m.is_some() || load_5m.is_some() || load_15m.is_some() {
                    return (load_1m, load_5m, load_15m);
                }
            }
            Err(error) => warnings.push(format!("status loadavg read failed: {error}")),
        }
        return (None, None, None);
    }

    if cfg!(target_os = "macos") {
        let output = ProcessCommand::new("sysctl")
            .args(["-n", "vm.loadavg"])
            .output();
        match output {
            Ok(value) if value.status.success() => {
                let text = String::from_utf8_lossy(&value.stdout);
                let floats = parse_floats(&text, 3);
                if !floats.is_empty() {
                    let load_1m = floats.first().copied();
                    let load_5m = floats.get(1).copied();
                    let load_15m = floats.get(2).copied();
                    return (load_1m, load_5m, load_15m);
                }
            }
            Ok(value) => warnings.push(format!(
                "status loadavg command failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            )),
            Err(error) => warnings.push(format!("status loadavg command failed: {error}")),
        }
    }
    (None, None, None)
}

fn collect_uptime_seconds(warnings: &mut Vec<String>) -> Option<u64> {
    if let Ok(value) = std::env::var("PREEN_STATUS_UPTIME_SECONDS")
        && let Ok(parsed) = value.trim().parse::<u64>()
    {
        return Some(parsed);
    }

    if cfg!(target_os = "linux") {
        match fs::read_to_string("/proc/uptime") {
            Ok(value) => {
                if let Some(first) = value.split_whitespace().next()
                    && let Ok(parsed) = first.parse::<f64>()
                {
                    return Some(parsed as u64);
                }
            }
            Err(error) => warnings.push(format!("status uptime read failed: {error}")),
        }
        return None;
    }

    if cfg!(target_os = "macos") {
        let output = ProcessCommand::new("sysctl")
            .args(["-n", "kern.boottime"])
            .output();
        match output {
            Ok(value) if value.status.success() => {
                let text = String::from_utf8_lossy(&value.stdout);
                if let Some(boot_sec) = parse_boot_time_seconds(&text)
                    && let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH)
                {
                    return Some(now.as_secs().saturating_sub(boot_sec));
                }
            }
            Ok(value) => warnings.push(format!(
                "status uptime command failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            )),
            Err(error) => warnings.push(format!("status uptime command failed: {error}")),
        }
    }
    None
}

fn collect_memory_bytes(warnings: &mut Vec<String>) -> (Option<u64>, Option<u64>) {
    if let Ok(total) = std::env::var("PREEN_STATUS_MEMORY_TOTAL_BYTES")
        && let Ok(total_bytes) = total.trim().parse::<u64>()
    {
        let used = std::env::var("PREEN_STATUS_MEMORY_USED_BYTES")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok());
        return (Some(total_bytes), used);
    }

    if cfg!(target_os = "linux") {
        return collect_memory_linux(warnings);
    }
    if cfg!(target_os = "macos") {
        return collect_memory_macos(warnings);
    }
    (None, None)
}

fn collect_memory_linux(warnings: &mut Vec<String>) -> (Option<u64>, Option<u64>) {
    match fs::read_to_string("/proc/meminfo") {
        Ok(content) => {
            let total_kb = parse_meminfo_kb(&content, "MemTotal:");
            let available_kb = parse_meminfo_kb(&content, "MemAvailable:");
            if let (Some(total), Some(available)) = (total_kb, available_kb) {
                let total_bytes = total.saturating_mul(1024);
                let available_bytes = available.saturating_mul(1024);
                let used = total_bytes.saturating_sub(available_bytes);
                return (Some(total_bytes), Some(used));
            }
        }
        Err(error) => warnings.push(format!("status meminfo read failed: {error}")),
    }
    (None, None)
}

fn collect_memory_macos(warnings: &mut Vec<String>) -> (Option<u64>, Option<u64>) {
    let total_output = ProcessCommand::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output();
    let total_bytes = match total_output {
        Ok(value) if value.status.success() => String::from_utf8_lossy(&value.stdout)
            .trim()
            .parse::<u64>()
            .ok(),
        Ok(value) => {
            warnings.push(format!(
                "status hw.memsize command failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            ));
            None
        }
        Err(error) => {
            warnings.push(format!("status hw.memsize command failed: {error}"));
            None
        }
    };

    let page_size_output = ProcessCommand::new("sysctl")
        .args(["-n", "hw.pagesize"])
        .output();
    let page_size = match page_size_output {
        Ok(value) if value.status.success() => String::from_utf8_lossy(&value.stdout)
            .trim()
            .parse::<u64>()
            .ok(),
        _ => None,
    };

    let vm_output = ProcessCommand::new("vm_stat").output();
    let vm_text = match vm_output {
        Ok(value) if value.status.success() => {
            Some(String::from_utf8_lossy(&value.stdout).to_string())
        }
        _ => None,
    };

    if let (Some(total), Some(page_size), Some(vm)) = (total_bytes, page_size, vm_text) {
        let free_pages = parse_vm_stat_pages(&vm, "Pages free:")
            .unwrap_or(0)
            .saturating_add(parse_vm_stat_pages(&vm, "Pages speculative:").unwrap_or(0));
        let free_bytes = free_pages.saturating_mul(page_size);
        let used = total.saturating_sub(free_bytes);
        return (Some(total), Some(used));
    }

    (total_bytes, None)
}

fn collect_disk_bytes(state_dir: &Path, warnings: &mut Vec<String>) -> (Option<u64>, Option<u64>) {
    if let Ok(total) = std::env::var("PREEN_STATUS_DISK_TOTAL_BYTES")
        && let Ok(total_bytes) = total.trim().parse::<u64>()
    {
        let available = std::env::var("PREEN_STATUS_DISK_AVAILABLE_BYTES")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok());
        return (Some(total_bytes), available);
    }

    let probe = if state_dir.exists() {
        state_dir.to_path_buf()
    } else {
        state_dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let output = ProcessCommand::new("df")
        .args(["-kP", &probe.to_string_lossy()])
        .output();
    match output {
        Ok(value) if value.status.success() => {
            let text = String::from_utf8_lossy(&value.stdout);
            if let Some((total, available)) = parse_df_kbytes(&text) {
                return (
                    Some(total.saturating_mul(1024)),
                    Some(available.saturating_mul(1024)),
                );
            }
        }
        Ok(value) => warnings.push(format!(
            "status disk command failed: {}",
            String::from_utf8_lossy(&value.stderr).trim()
        )),
        Err(error) => warnings.push(format!("status disk command failed: {error}")),
    }
    (None, None)
}

fn collect_process_count(warnings: &mut Vec<String>) -> Option<u64> {
    if let Ok(value) = std::env::var("PREEN_STATUS_PROCESS_COUNT")
        && let Ok(parsed) = value.trim().parse::<u64>()
    {
        return Some(parsed);
    }

    if cfg!(target_os = "linux") {
        match fs::read_dir("/proc") {
            Ok(entries) => {
                let count = entries
                    .flatten()
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .filter(|name| name.chars().all(|ch| ch.is_ascii_digit()))
                    .count();
                return Some(count as u64);
            }
            Err(error) => warnings.push(format!("status process count read failed: {error}")),
        }
        return None;
    }

    if cfg!(target_os = "macos") {
        let output = ProcessCommand::new("ps")
            .args(["-A", "-o", "pid="])
            .output();
        match output {
            Ok(value) if value.status.success() => {
                let count = String::from_utf8_lossy(&value.stdout)
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count();
                return Some(count as u64);
            }
            Ok(value) => warnings.push(format!(
                "status process count command failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            )),
            Err(error) => warnings.push(format!("status process count command failed: {error}")),
        }
    }
    None
}

fn collect_network_bytes(warnings: &mut Vec<String>) -> (Option<u64>, Option<u64>) {
    if let Ok(rx) = std::env::var("PREEN_STATUS_NET_RX_BYTES")
        && let Ok(rx_bytes) = rx.trim().parse::<u64>()
    {
        let tx_bytes = std::env::var("PREEN_STATUS_NET_TX_BYTES")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok());
        return (Some(rx_bytes), tx_bytes);
    }

    if cfg!(target_os = "linux") {
        match fs::read_to_string("/proc/net/dev") {
            Ok(content) => {
                let mut rx_sum = 0_u64;
                let mut tx_sum = 0_u64;
                for line in content.lines().skip(2) {
                    let Some((iface, values)) = line.split_once(':') else {
                        continue;
                    };
                    if iface.trim() == "lo" {
                        continue;
                    }
                    let cols: Vec<&str> = values.split_whitespace().collect();
                    if cols.len() < 16 {
                        continue;
                    }
                    let rx = cols
                        .first()
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0);
                    let tx = cols
                        .get(8)
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0);
                    rx_sum = rx_sum.saturating_add(rx);
                    tx_sum = tx_sum.saturating_add(tx);
                }
                return (Some(rx_sum), Some(tx_sum));
            }
            Err(error) => warnings.push(format!("status network read failed: {error}")),
        }
        return (None, None);
    }

    if cfg!(target_os = "macos") {
        let output = ProcessCommand::new("netstat").args(["-ib"]).output();
        match output {
            Ok(value) if value.status.success() => {
                let text = String::from_utf8_lossy(&value.stdout);
                if let Some((rx, tx)) = parse_netstat_interface_bytes(&text) {
                    return (Some(rx), Some(tx));
                }
            }
            Ok(value) => warnings.push(format!(
                "status network command failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            )),
            Err(error) => warnings.push(format!("status network command failed: {error}")),
        }
    }

    (None, None)
}

fn parse_meminfo_kb(content: &str, key: &str) -> Option<u64> {
    content.lines().find_map(|line| {
        if !line.starts_with(key) {
            return None;
        }
        line.split_whitespace().nth(1)?.parse::<u64>().ok()
    })
}

fn parse_vm_stat_pages(content: &str, key: &str) -> Option<u64> {
    content.lines().find_map(|line| {
        if !line.trim_start().starts_with(key) {
            return None;
        }
        let value = line.split(':').nth(1)?.trim().trim_end_matches('.');
        value.parse::<u64>().ok()
    })
}

fn parse_df_kbytes(content: &str) -> Option<(u64, u64)> {
    let line = content.lines().nth(1)?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 4 {
        return None;
    }
    let total = cols.get(1)?.parse::<u64>().ok()?;
    let available = cols.get(3)?.parse::<u64>().ok()?;
    Some((total, available))
}

fn parse_floats(content: &str, max_items: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let mut token = String::new();
    for ch in content.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            token.push(ch);
        } else if !token.is_empty() {
            if let Some(value) = parse_float_to_milli(&token) {
                out.push(value);
                if out.len() >= max_items {
                    break;
                }
            }
            token.clear();
        }
    }
    if out.len() < max_items
        && !token.is_empty()
        && let Some(value) = parse_float_to_milli(&token)
    {
        out.push(value);
    }
    out
}

fn parse_float_to_milli(value: &str) -> Option<u64> {
    value
        .parse::<f64>()
        .ok()
        .map(|parsed| (parsed * 1000.0).round() as u64)
}

fn parse_netstat_interface_bytes(content: &str) -> Option<(u64, u64)> {
    let mut lines = content.lines();
    let header = lines.next()?;
    let columns: Vec<&str> = header.split_whitespace().collect();
    let ibytes_idx = columns.iter().position(|column| *column == "Ibytes")?;
    let obytes_idx = columns.iter().position(|column| *column == "Obytes")?;

    let mut rx_sum = 0_u64;
    let mut tx_sum = 0_u64;
    for line in lines {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() <= obytes_idx {
            continue;
        }
        let name = cols.first().copied().unwrap_or_default();
        if name.starts_with("lo") {
            continue;
        }
        let Some(rx) = cols
            .get(ibytes_idx)
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        let Some(tx) = cols
            .get(obytes_idx)
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        rx_sum = rx_sum.saturating_add(rx);
        tx_sum = tx_sum.saturating_add(tx);
    }
    Some((rx_sum, tx_sum))
}

fn compute_percent(numerator: Option<u64>, denominator: Option<u64>) -> Option<u64> {
    match (numerator, denominator) {
        (Some(a), Some(b)) if b > 0 => Some(((a as f64 / b as f64) * 100.0).round() as u64),
        _ => None,
    }
}

fn parse_boot_time_seconds(content: &str) -> Option<u64> {
    let marker = "sec =";
    let start = content.find(marker)?;
    let rest = &content[start + marker.len()..];
    let value = rest
        .chars()
        .skip_while(|ch| ch.is_whitespace())
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    value.parse::<u64>().ok()
}

fn format_load_milli(value: u64) -> String {
    let whole = value / 1000;
    let frac = value % 1000;
    format!("{whole}.{frac:03}")
}

fn status_health_score(checks: &[SystemStatusCheckOutput]) -> u8 {
    let mut score: i32 = 100;
    for check in checks {
        if check.passed {
            continue;
        }
        if check.severity == "critical" {
            score -= 30;
        } else {
            score -= 10;
        }
    }
    score.clamp(0, 100) as u8
}

fn status_json(out: StatusOutput) -> Result<String, String> {
    to_json_envelope("system.status", out)
}

fn print_status_output(out: &StatusOutput) {
    println!(
        "summary: kind=system_status overall_passed={} health_score={}",
        out.overall_passed, out.health_score
    );
    println!("mode: {}", out.mode);
    println!("os: {}", out.os);
    println!("arch: {}", out.arch);
    println!("state_dir: {}", out.state_dir);
    if let Some(plugin_count) = out.plugin_count {
        println!("plugins: count={plugin_count}");
    } else {
        println!("plugins: count=unknown");
    }
    println!("registry_index_present: {}", out.registry_index_present);
    if let Some(generated_at) = &out.registry_generated_at {
        println!("registry_generated_at: {generated_at}");
    }
    if let Some(age_days) = out.registry_age_days {
        println!("registry_age_days: {age_days}");
    }
    if let Some(value) = out.metrics.cpu_cores {
        println!("metrics_cpu_cores: {value}");
    }
    if let Some(value) = out.metrics.load_avg_1m_milli {
        println!("metrics_load_avg_1m: {}", format_load_milli(value));
    }
    if let Some(value) = out.metrics.load_avg_5m_milli {
        println!("metrics_load_avg_5m: {}", format_load_milli(value));
    }
    if let Some(value) = out.metrics.load_avg_15m_milli {
        println!("metrics_load_avg_15m: {}", format_load_milli(value));
    }
    if let Some(value) = out.metrics.uptime_seconds {
        println!("metrics_uptime_seconds: {value}");
    }
    if let Some(value) = out.metrics.memory_total_bytes {
        println!("metrics_memory_total: {}", format_bytes(value));
    }
    if let Some(value) = out.metrics.memory_used_bytes {
        println!("metrics_memory_used: {}", format_bytes(value));
    }
    if let Some(value) = out.metrics.memory_used_pct {
        println!("metrics_memory_used_pct: {value}");
    }
    if let Some(value) = out.metrics.disk_total_bytes {
        println!("metrics_disk_total: {}", format_bytes(value));
    }
    if let Some(value) = out.metrics.disk_available_bytes {
        println!("metrics_disk_available: {}", format_bytes(value));
    }
    if let Some(value) = out.metrics.disk_free_pct {
        println!("metrics_disk_free_pct: {value}");
    }
    if let Some(value) = out.metrics.process_count {
        println!("metrics_process_count: {value}");
    }
    if let Some(value) = out.metrics.network_rx_bytes {
        println!("metrics_network_rx_bytes: {value}");
    }
    if let Some(value) = out.metrics.network_tx_bytes {
        println!("metrics_network_tx_bytes: {value}");
    }
    println!("checks: label=Checks");
    for check in &out.checks {
        println!(
            "check: id={} label={} severity={} passed={} message={}",
            check.id, check.label, check.severity, check.passed, check.message
        );
    }
    if !out.suggested_actions.is_empty() {
        println!("suggested_actions: count={}", out.suggested_actions.len());
        for action in &out.suggested_actions {
            println!("suggested_action: {action}");
        }
    }
    if !out.warnings.is_empty() {
        println!("warnings: count={}", out.warnings.len());
        for warning in &out.warnings {
            println!("warning: {warning}");
        }
    }
}

fn run_touchid(action: Option<TouchIdActionArg>, dry_run: bool, json: bool) -> Result<(), String> {
    let output = run_touchid_output(action.unwrap_or(TouchIdActionArg::Status), dry_run)?;
    if json {
        println!("{}", touchid_json(output.clone())?);
        return Ok(());
    }
    print_touchid_output(&output);
    Ok(())
}

fn run_touchid_output(action: TouchIdActionArg, dry_run: bool) -> Result<TouchIdOutput, String> {
    let mut warnings = Vec::new();
    let supported_os = cfg!(target_os = "macos");
    let configured = if supported_os {
        touchid_is_configured(&mut warnings)?
    } else {
        warnings.push(format!(
            "touchid is supported only on macos (current os: {})",
            std::env::consts::OS
        ));
        false
    };

    let would_change = match action {
        TouchIdActionArg::Status => false,
        TouchIdActionArg::Enable => !configured,
        TouchIdActionArg::Disable => configured,
    };

    let mut applied = false;
    if !dry_run && !matches!(action, TouchIdActionArg::Status) {
        warnings.push(
            "touchid apply mode is not enabled in this build; run with --dry-run to preview"
                .to_string(),
        );
    } else if !dry_run {
        applied = true;
    }

    Ok(TouchIdOutput {
        mode: if dry_run {
            "dry_run".to_string()
        } else {
            "apply".to_string()
        },
        action: touchid_action_label(action).to_string(),
        supported_os,
        configured,
        would_change,
        applied,
        warnings,
    })
}

fn touchid_is_configured(warnings: &mut Vec<String>) -> Result<bool, String> {
    let sudo_file =
        std::env::var("PREEN_TOUCHID_SUDO_FILE").unwrap_or_else(|_| "/etc/pam.d/sudo".to_string());
    let sudo_local_file = std::env::var("PREEN_TOUCHID_SUDO_LOCAL_FILE")
        .unwrap_or_else(|_| "/etc/pam.d/sudo_local".to_string());
    let mut configured = false;

    for candidate in [sudo_local_file, sudo_file] {
        let path = PathBuf::from(candidate);
        if !path.exists() {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(content) => {
                if content.contains("pam_tid.so") {
                    configured = true;
                    break;
                }
            }
            Err(error) => warnings.push(format!(
                "touchid status read failed for {}: {error}",
                path.display()
            )),
        }
    }

    Ok(configured)
}

fn touchid_action_label(action: TouchIdActionArg) -> &'static str {
    match action {
        TouchIdActionArg::Enable => "enable",
        TouchIdActionArg::Disable => "disable",
        TouchIdActionArg::Status => "status",
    }
}

fn touchid_json(out: TouchIdOutput) -> Result<String, String> {
    to_json_envelope("system.touchid", out)
}

fn print_touchid_output(out: &TouchIdOutput) {
    println!(
        "summary: kind=system_touchid action={} mode={} supported_os={} configured={} would_change={} applied={}",
        out.action, out.mode, out.supported_os, out.configured, out.would_change, out.applied
    );
    if !out.warnings.is_empty() {
        println!("warnings: count={}", out.warnings.len());
        for warning in &out.warnings {
            println!("warning: {warning}");
        }
    }
}

fn run_completion(
    shell: Option<CompletionShellArg>,
    dry_run: bool,
    json: bool,
) -> Result<(), String> {
    let output = run_completion_output(shell, dry_run)?;
    if json {
        println!("{}", completion_json(output.clone())?);
        return Ok(());
    }

    if output.mode == "generate" {
        if let Some(script) = &output.script {
            print!("{script}");
        }
        return Ok(());
    }

    println!(
        "summary: kind=system_completion mode={} shell={} installed={} changed={}",
        output.mode, output.shell, output.installed, output.changed
    );
    if let Some(path) = &output.config_path {
        println!("config_path: {path}");
    }
    if let Some(snippet) = &output.snippet {
        println!("snippet: {snippet}");
    }
    if !output.warnings.is_empty() {
        println!("warnings: count={}", output.warnings.len());
        for warning in &output.warnings {
            println!("warning: {warning}");
        }
    }
    Ok(())
}

fn run_completion_output(
    shell: Option<CompletionShellArg>,
    dry_run: bool,
) -> Result<CompletionOutput, String> {
    let explicit_shell = shell.is_some();
    let shell = match shell {
        Some(value) => value,
        None => detect_completion_shell().ok_or_else(|| {
            err_code(
                CliErrorKind::Validation,
                "completion_shell_unknown",
                "unable to detect shell, pass bash|zsh|fish explicitly",
            )
        })?,
    };

    let script = generate_completion_script(shell);
    if explicit_shell {
        return Ok(CompletionOutput {
            mode: "generate".to_string(),
            shell: completion_shell_name(shell).to_string(),
            generated: true,
            installed: false,
            changed: false,
            config_path: None,
            snippet: None,
            script: Some(script),
            warnings: Vec::new(),
        });
    }

    let path = shell_config_path(shell)?;
    install_completion_snippet(shell, &path, dry_run)
}

fn install_completion_snippet(
    shell: CompletionShellArg,
    path: &Path,
    dry_run: bool,
) -> Result<CompletionOutput, String> {
    let snippet = completion_install_snippet(shell)?;
    let mut warnings = Vec::new();
    let mut changed = false;
    let mut installed = false;
    let mode = if dry_run { "dry_run" } else { "apply" };

    let content = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(err_code(
                CliErrorKind::Io,
                "completion_read_failed",
                format!("completion config read failed: {error}"),
            ));
        }
    };

    if content.contains(&snippet) {
        installed = true;
    } else if dry_run {
        warnings.push("completion snippet is missing and would be appended".to_string());
    } else {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|error| {
                err_code(
                    CliErrorKind::Io,
                    "completion_write_failed",
                    format!("completion config dir create failed: {error}"),
                )
            })?;
        }

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| {
                err_code(
                    CliErrorKind::Io,
                    "completion_write_failed",
                    format!("completion config open failed: {error}"),
                )
            })?;
        if !content.is_empty() && !content.ends_with('\n') {
            file.write_all(b"\n").map_err(|error| {
                err_code(
                    CliErrorKind::Io,
                    "completion_write_failed",
                    format!("completion config newline write failed: {error}"),
                )
            })?;
        }
        file.write_all(b"# Preen shell completion\n")
            .and_then(|_| file.write_all(snippet.as_bytes()))
            .and_then(|_| file.write_all(b"\n"))
            .map_err(|error| {
                err_code(
                    CliErrorKind::Io,
                    "completion_write_failed",
                    format!("completion config write failed: {error}"),
                )
            })?;
        changed = true;
        installed = true;
    }

    Ok(CompletionOutput {
        mode: mode.to_string(),
        shell: completion_shell_name(shell).to_string(),
        generated: false,
        installed,
        changed,
        config_path: Some(path.display().to_string()),
        snippet: Some(snippet),
        script: None,
        warnings,
    })
}

fn completion_install_snippet(shell: CompletionShellArg) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|error| {
        err_code(
            CliErrorKind::Internal,
            "completion_executable_unknown",
            format!("resolve executable path failed: {error}"),
        )
    })?;
    let exe = exe.display().to_string();
    let snippet = match shell {
        CompletionShellArg::Bash | CompletionShellArg::Zsh => {
            format!(
                "eval \"$({exe} completion {})\"",
                completion_shell_name(shell)
            )
        }
        CompletionShellArg::Fish => format!("{exe} completion fish | source"),
    };
    Ok(snippet)
}

fn detect_completion_shell() -> Option<CompletionShellArg> {
    let shell = std::env::var("SHELL").ok()?;
    let name = Path::new(&shell)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match name.as_str() {
        "bash" => Some(CompletionShellArg::Bash),
        "zsh" => Some(CompletionShellArg::Zsh),
        "fish" => Some(CompletionShellArg::Fish),
        _ => None,
    }
}

fn shell_config_path(shell: CompletionShellArg) -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        err_code(
            CliErrorKind::Io,
            "completion_home_missing",
            "missing HOME environment variable",
        )
    })?;
    let path = match shell {
        CompletionShellArg::Bash => home.join(".bashrc"),
        CompletionShellArg::Zsh => home.join(".zshrc"),
        CompletionShellArg::Fish => home.join(".config").join("fish").join("config.fish"),
    };
    Ok(path)
}

fn completion_shell_name(shell: CompletionShellArg) -> &'static str {
    match shell {
        CompletionShellArg::Bash => "bash",
        CompletionShellArg::Zsh => "zsh",
        CompletionShellArg::Fish => "fish",
    }
}

fn generate_completion_script(shell: CompletionShellArg) -> String {
    let commands = [
        "plugin",
        "clean",
        "uninstall",
        "optimize",
        "analyze",
        "status",
        "purge",
        "installer",
        "check",
        "touchid",
        "completion",
        "update",
        "remove",
    ];
    match shell {
        CompletionShellArg::Bash => format!(
            "_preen_completions()\n{{\n    local cur prev\n    cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n    prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\n    if [ \"$COMP_CWORD\" -eq 1 ]; then\n        COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") )\n        return\n    fi\n\n    case \"$prev\" in\n        completion)\n            COMPREPLY=( $(compgen -W \"bash zsh fish\" -- \"$cur\") )\n            ;;\n        touchid)\n            COMPREPLY=( $(compgen -W \"enable disable status\" -- \"$cur\") )\n            ;;\n        *)\n            COMPREPLY=()\n            ;;\n    esac\n}}\n\ncomplete -F _preen_completions preen\n",
            commands.join(" ")
        ),
        CompletionShellArg::Zsh => {
            let mut script =
                String::from("#compdef preen\n\n_preen() {\n  local -a commands\n  commands=(\n");
            for command in commands {
                let _ = writeln!(script, "    '{command}:{command} command'");
            }
            script.push_str(
                "    'completion:bash|zsh|fish'\n    'touchid:enable|disable|status'\n  )\n  _describe 'command' commands\n}\n\ncompdef _preen preen\n",
            );
            script
        }
        CompletionShellArg::Fish => format!(
            "set -l preen_commands {}\nfor cmd in $preen_commands\n    complete -c preen -f -a $cmd\nend\ncomplete -c preen -n \"__fish_seen_subcommand_from completion\" -a \"bash zsh fish\"\ncomplete -c preen -n \"__fish_seen_subcommand_from touchid\" -a \"enable disable status\"\n",
            commands.join(" ")
        ),
    }
}

fn completion_json(out: CompletionOutput) -> Result<String, String> {
    to_json_envelope("system.completion", out)
}

fn run_update(force: bool, nightly: bool, json: bool) -> Result<(), String> {
    let output = run_update_output(force, nightly);
    if json {
        println!("{}", update_json(output.clone())?);
        return Ok(());
    }
    print_update_output(&output);
    Ok(())
}

fn run_update_output(force: bool, nightly: bool) -> UpdateOutput {
    let mut warnings = Vec::new();
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let install_source = detect_install_source();
    let suggested_command = suggested_update_command(&install_source, nightly);
    let latest_version = if nightly {
        None
    } else {
        match fetch_latest_release_version() {
            Ok(value) => value,
            Err(error) => {
                warnings.push(error);
                None
            }
        }
    };

    let update_available = latest_version
        .as_deref()
        .and_then(|latest| compare_semver_like(&current_version, latest));

    let mut checks = Vec::new();
    checks.push(SystemStatusCheckOutput {
        id: "update_source_detected".to_string(),
        label: "Install source detected".to_string(),
        severity: "warning".to_string(),
        passed: install_source != "unknown",
        message: format!("install source: {install_source}"),
    });
    checks.push(SystemStatusCheckOutput {
        id: "update_command_available".to_string(),
        label: "Suggested update command".to_string(),
        severity: "warning".to_string(),
        passed: !suggested_command.is_empty(),
        message: suggested_command.clone(),
    });
    checks.push(SystemStatusCheckOutput {
        id: "update_version_check".to_string(),
        label: "Version check".to_string(),
        severity: "critical".to_string(),
        passed: update_available.map(|available| !available).unwrap_or(true),
        message: match (&latest_version, update_available) {
            (Some(latest), Some(true)) => {
                format!("update available: current={current_version} latest={latest}")
            }
            (Some(latest), Some(false)) => {
                format!("already latest: current={current_version} latest={latest}")
            }
            (Some(latest), None) => {
                format!("version comparison skipped: current={current_version} latest={latest}")
            }
            (None, _) => "latest version unavailable".to_string(),
        },
    });

    if force {
        warnings.push(
            "force mode is advisory only in this build; run suggested command manually".to_string(),
        );
    }

    UpdateOutput {
        mode: if force {
            "force_plan".to_string()
        } else {
            "plan".to_string()
        },
        channel: if nightly {
            "nightly".to_string()
        } else {
            "stable".to_string()
        },
        force,
        current_version,
        latest_version,
        update_available,
        install_source,
        suggested_command,
        executed: false,
        checks,
        warnings,
    }
}

fn fetch_latest_release_version() -> Result<Option<String>, String> {
    if let Ok(value) = std::env::var("PREEN_UPDATE_LATEST_VERSION") {
        let trimmed = value.trim().trim_start_matches('v').to_string();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed));
        }
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .map_err(|error| format!("build update client failed: {error}"))?;

    let response = client
        .get("https://api.github.com/repos/Preen-rs/preen/releases/latest")
        .header("User-Agent", "preen-cli")
        .send()
        .map_err(|error| format!("latest release fetch failed: {error}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "latest release fetch failed with status {}",
            response.status()
        ));
    }

    let body = response
        .text()
        .map_err(|error| format!("latest release body read failed: {error}"))?;
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| format!("latest release parse failed: {error}"))?;
    let tag = value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .map(|v| v.trim().trim_start_matches('v').to_string())
        .filter(|v| !v.is_empty());
    Ok(tag)
}

fn detect_install_source() -> String {
    if let Ok(value) = std::env::var("PREEN_UPDATE_INSTALL_SOURCE") {
        let lowered = value.trim().to_ascii_lowercase();
        if !lowered.is_empty() {
            return lowered;
        }
    }

    match std::env::current_exe() {
        Ok(path) => {
            let text = path.display().to_string().to_ascii_lowercase();
            if text.contains("homebrew") || text.contains("/cellar/") {
                "homebrew".to_string()
            } else if text.contains("/.cargo/bin/") {
                "cargo".to_string()
            } else {
                "unknown".to_string()
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

fn suggested_update_command(install_source: &str, nightly: bool) -> String {
    match (install_source, nightly) {
        ("homebrew", false) => "brew upgrade preen".to_string(),
        ("homebrew", true) => "brew upgrade --fetch-HEAD preen".to_string(),
        ("cargo", false) => "cargo install preen-cli --locked --force".to_string(),
        ("cargo", true) => {
            "cargo install --git https://github.com/Preen-rs/preen preen-cli --locked --force"
                .to_string()
        }
        ("script", false) => "curl -fsSL https://preen.rs/install.sh | bash".to_string(),
        ("script", true) => {
            "curl -fsSL https://preen.rs/install.sh | bash -s -- --nightly".to_string()
        }
        (_, false) => "preen update --force".to_string(),
        (_, true) => "preen update --nightly --force".to_string(),
    }
}

fn compare_semver_like(current: &str, latest: &str) -> Option<bool> {
    let cur = parse_semver_like(current)?;
    let lat = parse_semver_like(latest)?;
    Some(lat > cur)
}

fn parse_semver_like(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.trim().trim_start_matches('v').split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .split('-')
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .ok()?;
    Some((major, minor, patch))
}

fn update_json(out: UpdateOutput) -> Result<String, String> {
    to_json_envelope("system.update", out)
}

fn print_update_output(out: &UpdateOutput) {
    println!(
        "summary: kind=system_update mode={} channel={} force={} executed={}",
        out.mode, out.channel, out.force, out.executed
    );
    println!("current_version: {}", out.current_version);
    if let Some(version) = &out.latest_version {
        println!("latest_version: {version}");
    }
    if let Some(available) = out.update_available {
        println!("update_available: {available}");
    }
    println!("install_source: {}", out.install_source);
    println!("suggested_command: {}", out.suggested_command);
    println!("checks: label=Checks");
    for check in &out.checks {
        println!(
            "check: id={} label={} severity={} passed={} message={}",
            check.id, check.label, check.severity, check.passed, check.message
        );
    }
    if !out.warnings.is_empty() {
        println!("warnings: count={}", out.warnings.len());
        for warning in &out.warnings {
            println!("warning: {warning}");
        }
    }
}

fn run_remove(dry_run: bool, json: bool) -> Result<(), String> {
    let output = run_remove_output(dry_run)?;
    if json {
        println!("{}", remove_json(output.clone())?);
        return Ok(());
    }
    print_remove_output(&output);
    Ok(())
}

fn collect_remove_candidate(
    path: PathBuf,
    dry_run: bool,
    detected_paths: &mut Vec<String>,
    removed_paths: &mut Vec<String>,
    skipped_paths: &mut Vec<String>,
) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    let display = path.display().to_string();
    detected_paths.push(display.clone());
    if dry_run {
        skipped_paths.push(display);
    } else {
        remove_path_recursively(&path)?;
        removed_paths.push(display);
    }
    Ok(())
}

fn run_remove_output(dry_run: bool) -> Result<RemoveOutput, String> {
    let executable = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let mut detected_paths = Vec::new();
    let mut removed_paths = Vec::new();
    let mut skipped_paths = Vec::new();
    let mut warnings = Vec::new();

    collect_remove_candidate(
        resolve_remove_state_dir()?,
        dry_run,
        &mut detected_paths,
        &mut removed_paths,
        &mut skipped_paths,
    )?;
    collect_remove_candidate(
        resolve_remove_cache_dir()?,
        dry_run,
        &mut detected_paths,
        &mut removed_paths,
        &mut skipped_paths,
    )?;

    if detected_paths.is_empty() {
        warnings.push("no managed Preen paths detected".to_string());
    }

    let install_source = detect_install_source();
    let manual_steps = remove_manual_steps(&install_source);
    if manual_steps.is_empty() {
        warnings.push("install source unknown; remove executable manually if needed".to_string());
    }

    Ok(RemoveOutput {
        mode: if dry_run {
            "dry_run".to_string()
        } else {
            "apply".to_string()
        },
        executable,
        detected_paths,
        removed_paths,
        skipped_paths,
        manual_steps,
        warnings,
    })
}

fn resolve_remove_state_dir() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("PREEN_REMOVE_STATE_DIR") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    preen_state_dir()
}

fn resolve_remove_cache_dir() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("PREEN_REMOVE_CACHE_DIR") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    match std::env::consts::OS {
        "macos" => {
            let home = dirs::home_dir().ok_or_else(|| err(CliErrorKind::Io, "missing home dir"))?;
            Ok(home.join("Library").join("Caches").join("Preen"))
        }
        "linux" => {
            let base =
                dirs::cache_dir().ok_or_else(|| err(CliErrorKind::Io, "missing cache dir"))?;
            Ok(base.join("preen"))
        }
        other => Err(err(
            CliErrorKind::Unsupported,
            format!("unsupported OS: {other}"),
        )),
    }
}

fn remove_path_recursively(path: &Path) -> Result<(), String> {
    let target = path
        .canonicalize()
        .or_else(|_| Ok::<PathBuf, std::io::Error>(path.to_path_buf()))
        .map_err(|error| {
            err_code(
                CliErrorKind::Io,
                "remove_path_resolve_failed",
                format!("remove path resolve failed: {error}"),
            )
        })?;

    if !is_safe_remove_target(&target) {
        return Err(err_code(
            CliErrorKind::Validation,
            "remove_path_scope_violation",
            format!("refusing to remove unsafe path: {}", target.display()),
        ));
    }

    if target.is_dir() {
        fs::remove_dir_all(&target).map_err(|error| {
            err_code(
                CliErrorKind::Io,
                "remove_execution_failed",
                format!("remove dir failed: {error}"),
            )
        })?;
    } else if target.exists() {
        fs::remove_file(&target).map_err(|error| {
            err_code(
                CliErrorKind::Io,
                "remove_execution_failed",
                format!("remove file failed: {error}"),
            )
        })?;
    }
    Ok(())
}

fn is_safe_remove_target(path: &Path) -> bool {
    let value = path.to_string_lossy();
    if value.is_empty() || value == "/" {
        return false;
    }
    if path == Path::new("/usr") || path == Path::new("/var") || path == Path::new("/etc") {
        return false;
    }
    true
}

fn remove_manual_steps(install_source: &str) -> Vec<String> {
    match install_source {
        "homebrew" => vec!["brew uninstall --force preen".to_string()],
        "cargo" => vec!["cargo uninstall preen-cli".to_string()],
        "script" => vec!["rm -f $(command -v preen)".to_string()],
        _ => Vec::new(),
    }
}

fn remove_json(out: RemoveOutput) -> Result<String, String> {
    to_json_envelope("system.remove", out)
}

fn print_remove_output(out: &RemoveOutput) {
    println!(
        "summary: kind=system_remove mode={} detected={} removed={} skipped={}",
        out.mode,
        out.detected_paths.len(),
        out.removed_paths.len(),
        out.skipped_paths.len()
    );
    println!("executable: {}", out.executable);
    for path in &out.detected_paths {
        println!("detected_path: {path}");
    }
    for path in &out.removed_paths {
        println!("removed_path: {path}");
    }
    for path in &out.skipped_paths {
        println!("skipped_path: {path}");
    }
    for step in &out.manual_steps {
        println!("manual_step: {step}");
    }
    if !out.warnings.is_empty() {
        println!("warnings: count={}", out.warnings.len());
        for warning in &out.warnings {
            println!("warning: {warning}");
        }
    }
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

    let runtime = new_cli_runtime()?;
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

    let (affected_items, freed_bytes, runtime_warnings, audit_events) =
        execute_action_with_default_policy(
            &runtime,
            &manifest,
            &rule,
            dry_run,
            confirm,
            clean_executor,
            map_clean_runtime_error,
        )?;

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
        affected_items,
        freed_bytes,
        risk_summary,
        warnings: runtime_warnings,
        audit_events,
    })
}

fn run_purge_output_with_executor(
    dry_run: bool,
    confirm: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<PurgeCommandOutput, String> {
    if !dry_run && !confirm {
        return Err(err_code(
            CliErrorKind::Validation,
            "purge_confirmation_required",
            "purge apply mode requires --confirm",
        ));
    }

    let roots = normalize_purge_roots(resolve_purge_roots());
    if roots.is_empty() {
        return Err(err_code(
            CliErrorKind::Unsupported,
            "purge_no_roots",
            "purge has no configured scan roots",
        ));
    }

    let (selection, scanned_dirs, mut warnings) = scan_purge_candidates(&roots, purge_scan_depth());
    let selected_paths = selection
        .iter()
        .map(|item| item.path.clone())
        .collect::<Vec<_>>();
    let estimated_freed_bytes: u64 = selection.iter().map(|item| item.size).sum();
    enforce_purge_scope(&selected_paths, &roots)?;
    let preview_paths = clean_preview_paths(&selected_paths, purge_preview_limit());

    if selected_paths.is_empty() {
        warnings.push("no purge targets selected".to_string());
        return Ok(PurgeCommandOutput {
            mode: if dry_run {
                "dry_run".to_string()
            } else {
                "apply".to_string()
            },
            scanned_roots: roots.len(),
            scanned_dirs,
            target_count: 0,
            estimated_freed_bytes: 0,
            preview_paths: Vec::new(),
            affected_items: 0,
            freed_bytes: 0,
            warnings,
            audit_events: 0,
        });
    }

    let manifest = Manifest {
        schema_version: 1,
        pack_id: "preen.builtin.purge".to_string(),
        name: "Built-in Purge".to_string(),
        version: "0.1.0".to_string(),
        description: "Built-in purge plan".to_string(),
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
        capabilities: vec![Capability::FsRead, Capability::FsDelete],
        signing: None,
        rules: vec![RuleRef {
            id: "builtin-purge".to_string(),
            name: "Built-in Purge".to_string(),
            rule_file: "builtin".to_string(),
        }],
    };
    let rule = RuleFile {
        schema_version: 1,
        id: "builtin-purge".to_string(),
        name: "Built-in Purge".to_string(),
        category: ItemCategory::Other("build_artifact".to_string()),
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
            action_type: ActionType::DeletePaths,
            paths: selected_paths.clone(),
            command: Vec::new(),
            mode: None,
            timeout_sec: Some(600),
            allow_globs: false,
            max_items: Some(50_000),
            package_manager: None,
            project_types: Vec::new(),
            params: std::collections::HashMap::new(),
        },
    };

    let runtime = new_cli_runtime()?;
    let (affected_items, freed_bytes, runtime_warnings, audit_events) =
        execute_action_with_default_policy(
            &runtime,
            &manifest,
            &rule,
            dry_run,
            confirm,
            clean_executor,
            map_purge_runtime_error,
        )?;

    Ok(PurgeCommandOutput {
        mode: if dry_run {
            "dry_run".to_string()
        } else {
            "apply".to_string()
        },
        scanned_roots: roots.len(),
        scanned_dirs,
        target_count: selected_paths.len(),
        estimated_freed_bytes,
        preview_paths,
        affected_items,
        freed_bytes,
        warnings: runtime_warnings,
        audit_events,
    })
}

fn map_runtime_error_with_prefix(error: RuntimeExecutionError, prefix: &str) -> String {
    match error {
        RuntimeExecutionError::Plan(plan_error) => err_code(
            CliErrorKind::Validation,
            &format!("{prefix}_{}", plan_error_detail_code(&plan_error)),
            plan_error.to_string(),
        ),
        RuntimeExecutionError::Execute(execution_error) => err_code(
            CliErrorKind::Internal,
            &format!("{prefix}_{}", execution_error_detail_code(&execution_error)),
            execution_error.to_string(),
        ),
    }
}

fn map_clean_runtime_error(error: RuntimeExecutionError) -> String {
    map_runtime_error_with_prefix(error, "clean")
}

fn map_purge_runtime_error(error: RuntimeExecutionError) -> String {
    map_runtime_error_with_prefix(error, "purge")
}

fn map_installer_runtime_error(error: RuntimeExecutionError) -> String {
    map_runtime_error_with_prefix(error, "installer")
}

fn map_uninstall_runtime_error(error: RuntimeExecutionError) -> String {
    map_runtime_error_with_prefix(error, "uninstall")
}

fn map_optimize_runtime_error(error: RuntimeExecutionError) -> String {
    map_runtime_error_with_prefix(error, "optimize")
}

fn clean_json(out: CleanCommandOutput) -> Result<String, String> {
    to_json_envelope("system.clean", out)
}

fn purge_json(out: PurgeCommandOutput) -> Result<String, String> {
    to_json_envelope("system.purge", out)
}

fn installer_json(out: InstallerCommandOutput) -> Result<String, String> {
    to_json_envelope("system.installer", out)
}

fn uninstall_json(out: UninstallCommandOutput) -> Result<String, String> {
    to_json_envelope("system.uninstall", out)
}

fn optimize_json(out: OptimizeCommandOutput) -> Result<String, String> {
    to_json_envelope("system.optimize", out)
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

fn resolve_purge_roots() -> Vec<String> {
    if let Some(from_env) = std::env::var_os("PREEN_PURGE_PATHS") {
        let out: Vec<String> = from_env
            .to_string_lossy()
            .split([',', '\n'])
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
    vec![
        home.join("Projects").to_string_lossy().to_string(),
        home.join("GitHub").to_string_lossy().to_string(),
        home.join("dev").to_string_lossy().to_string(),
    ]
}

fn resolve_installer_roots() -> Vec<String> {
    if let Some(from_env) = std::env::var_os("PREEN_INSTALLER_PATHS") {
        let out: Vec<String> = from_env
            .to_string_lossy()
            .split([',', '\n'])
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
    vec![
        home.join("Downloads").to_string_lossy().to_string(),
        home.join("Desktop").to_string_lossy().to_string(),
    ]
}

fn resolve_uninstall_roots() -> Vec<String> {
    if let Some(from_env) = std::env::var_os("PREEN_UNINSTALL_PATHS") {
        let out: Vec<String> = from_env
            .to_string_lossy()
            .split([',', '\n'])
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

    #[cfg(target_os = "macos")]
    {
        vec![
            home.join("Applications").to_string_lossy().to_string(),
            home.join("Library")
                .join("Application Support")
                .to_string_lossy()
                .to_string(),
            home.join("Library")
                .join("Caches")
                .to_string_lossy()
                .to_string(),
            home.join("Library")
                .join("Preferences")
                .to_string_lossy()
                .to_string(),
        ]
    }

    #[cfg(not(target_os = "macos"))]
    {
        vec![
            home.join(".local")
                .join("share")
                .join("applications")
                .to_string_lossy()
                .to_string(),
            home.join(".local")
                .join("share")
                .to_string_lossy()
                .to_string(),
            home.join(".config").to_string_lossy().to_string(),
            home.join(".cache").to_string_lossy().to_string(),
        ]
    }
}

fn clean_max_items() -> usize {
    std::env::var("PREEN_CLEAN_MAX_ITEMS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(10_000)
}

fn purge_scan_depth() -> usize {
    std::env::var("PREEN_PURGE_MAX_DEPTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_PURGE_SCAN_DEPTH)
}

fn purge_preview_limit() -> usize {
    std::env::var("PREEN_PURGE_PREVIEW_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_PURGE_PREVIEW_LIMIT)
}

fn installer_scan_depth() -> usize {
    std::env::var("PREEN_INSTALLER_MAX_DEPTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_INSTALLER_SCAN_DEPTH)
}

fn installer_preview_limit() -> usize {
    std::env::var("PREEN_INSTALLER_PREVIEW_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_INSTALLER_PREVIEW_LIMIT)
}

fn installer_min_size_bytes() -> u64 {
    const DEFAULT_MIN_BYTES: u64 = 10 * 1024 * 1024;
    std::env::var("PREEN_INSTALLER_MIN_SIZE_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MIN_BYTES)
}

fn uninstall_scan_depth() -> usize {
    std::env::var("PREEN_UNINSTALL_MAX_DEPTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_UNINSTALL_SCAN_DEPTH)
}

fn uninstall_preview_limit() -> usize {
    std::env::var("PREEN_UNINSTALL_PREVIEW_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_UNINSTALL_PREVIEW_LIMIT)
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

fn normalize_purge_roots(roots: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        let trimmed = root.trim();
        if trimmed.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(trimmed);
        if !candidate.is_dir() {
            continue;
        }
        let normalized = fs::canonicalize(&candidate)
            .unwrap_or(candidate)
            .to_string_lossy()
            .to_string();
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn normalize_installer_roots(roots: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        let trimmed = root.trim();
        if trimmed.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(trimmed);
        if !candidate.is_dir() {
            continue;
        }
        let normalized = fs::canonicalize(&candidate)
            .unwrap_or(candidate)
            .to_string_lossy()
            .to_string();
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn normalize_uninstall_roots(roots: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        let trimmed = root.trim();
        if trimmed.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(trimmed);
        if !candidate.exists() {
            continue;
        }
        let normalized = fs::canonicalize(&candidate)
            .unwrap_or(candidate)
            .to_string_lossy()
            .to_string();
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn scan_purge_candidates(
    roots: &[String],
    max_depth: usize,
) -> (Vec<CleanSelectedItem>, usize, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut scanned_dirs = 0usize;

    for root in roots {
        let root_path = PathBuf::from(root);
        if !root_path.exists() {
            continue;
        }
        discover_purge_targets_under(
            &root_path,
            1,
            max_depth,
            &mut seen,
            &mut out,
            &mut scanned_dirs,
            &mut warnings,
        );
    }

    out.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    (out, scanned_dirs, warnings)
}

fn scan_installer_candidates(
    roots: &[String],
    max_depth: usize,
    min_size_bytes: u64,
) -> (Vec<CleanSelectedItem>, usize, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut scanned_files = 0usize;

    for root in roots {
        let root_path = PathBuf::from(root);
        if !root_path.exists() {
            continue;
        }
        let mut state = InstallerScanState {
            max_depth,
            min_size_bytes,
            seen: &mut seen,
            out: &mut out,
            scanned_files: &mut scanned_files,
            warnings: &mut warnings,
        };
        discover_installer_targets_under(&root_path, 0, &mut state);
    }

    out.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    (out, scanned_files, warnings)
}

struct InstallerScanState<'a> {
    max_depth: usize,
    min_size_bytes: u64,
    seen: &'a mut std::collections::HashSet<PathBuf>,
    out: &'a mut Vec<CleanSelectedItem>,
    scanned_files: &'a mut usize,
    warnings: &'a mut Vec<String>,
}

fn discover_installer_targets_under(root: &Path, depth: usize, state: &mut InstallerScanState<'_>) {
    if depth > state.max_depth {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) => {
            state.warnings.push(format!(
                "installer scan skipped unreadable directory: {} ({e})",
                root.display()
            ));
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };

        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            discover_installer_targets_under(&path, depth + 1, state);
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        *state.scanned_files += 1;
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() < state.min_size_bytes {
            continue;
        }
        if !is_installer_file(&path) {
            continue;
        }

        let canonical = fs::canonicalize(&path).unwrap_or(path.clone());
        if state.seen.insert(canonical.clone()) {
            state.out.push(CleanSelectedItem {
                path: canonical.to_string_lossy().to_string(),
                size: metadata.len(),
            });
        }
    }
}

fn is_installer_file(path: &Path) -> bool {
    let lower_path = path.to_string_lossy().to_ascii_lowercase();
    if lower_path.ends_with(".tar.gz") || lower_path.ends_with(".tar.bz2") {
        return true;
    }
    if let Some(ext) = path.extension().and_then(|ext| ext.to_str()) {
        return DEFAULT_INSTALLER_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str());
    }
    false
}

fn scan_uninstall_candidates(
    roots: &[String],
    target: &str,
    max_depth: usize,
) -> (Vec<CleanSelectedItem>, usize, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut scanned_entries = 0usize;
    let target_key = uninstall_target_key(target);

    if Path::new(target).is_absolute() {
        let candidate = PathBuf::from(target);
        scanned_entries = 1;
        let canonical = fs::canonicalize(&candidate).unwrap_or(candidate.clone());
        if seen.insert(canonical.clone()) {
            out.push(CleanSelectedItem {
                path: canonical.to_string_lossy().to_string(),
                size: calculate_path_size(&canonical),
            });
        }
        return (out, scanned_entries, warnings);
    }

    for root in roots {
        let root_path = PathBuf::from(root);
        if !root_path.exists() {
            continue;
        }
        let mut state = UninstallScanState {
            max_depth,
            target_key: &target_key,
            seen: &mut seen,
            out: &mut out,
            scanned_entries: &mut scanned_entries,
            warnings: &mut warnings,
        };
        discover_uninstall_targets_under(&root_path, 0, &mut state);
    }
    out.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    (out, scanned_entries, warnings)
}

struct UninstallScanState<'a> {
    max_depth: usize,
    target_key: &'a str,
    seen: &'a mut std::collections::HashSet<PathBuf>,
    out: &'a mut Vec<CleanSelectedItem>,
    scanned_entries: &'a mut usize,
    warnings: &'a mut Vec<String>,
}

fn discover_uninstall_targets_under(root: &Path, depth: usize, state: &mut UninstallScanState<'_>) {
    if depth > state.max_depth {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) => {
            state.warnings.push(format!(
                "uninstall scan skipped unreadable directory: {} ({e})",
                root.display()
            ));
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue;
        }
        *state.scanned_entries += 1;

        if uninstall_target_matches(&path, state.target_key) {
            let canonical = fs::canonicalize(&path).unwrap_or(path.clone());
            if state.seen.insert(canonical.clone()) {
                state.out.push(CleanSelectedItem {
                    path: canonical.to_string_lossy().to_string(),
                    size: calculate_path_size(&canonical),
                });
            }
        }

        if file_type.is_dir() {
            discover_uninstall_targets_under(&path, depth + 1, state);
        }
    }
}

fn uninstall_target_key(value: &str) -> String {
    let raw = Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(value);
    normalize_uninstall_name(raw)
}

fn uninstall_target_matches(path: &Path, target_key: &str) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    normalize_uninstall_name(name) == target_key
}

fn normalize_uninstall_name(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let trimmed = lower
        .strip_suffix(".app")
        .or_else(|| lower.strip_suffix(".desktop"))
        .or_else(|| lower.strip_suffix(".plist"))
        .unwrap_or(&lower);
    trimmed
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn discover_purge_targets_under(
    root: &Path,
    depth: usize,
    max_depth: usize,
    seen: &mut std::collections::HashSet<PathBuf>,
    out: &mut Vec<CleanSelectedItem>,
    scanned_dirs: &mut usize,
    warnings: &mut Vec<String>,
) {
    if depth > max_depth {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) => {
            warnings.push(format!(
                "purge scan skipped unreadable directory: {} ({e})",
                root.display()
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }
        *scanned_dirs += 1;
        if file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if DEFAULT_PURGE_ARTIFACT_NAMES.contains(&name.as_ref()) {
            let canonical = fs::canonicalize(&path).unwrap_or(path.clone());
            if seen.insert(canonical.clone()) {
                out.push(CleanSelectedItem {
                    path: canonical.to_string_lossy().to_string(),
                    size: calculate_path_size(&canonical),
                });
            }
            continue;
        }
        discover_purge_targets_under(
            &path,
            depth + 1,
            max_depth,
            seen,
            out,
            scanned_dirs,
            warnings,
        );
    }
}

fn calculate_path_size(path: &Path) -> u64 {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return 0,
    };
    if metadata.is_file() {
        return metadata.len();
    }
    if !metadata.is_dir() {
        return 0;
    }
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let child_path = entry.path();
            let Ok(child_meta) = fs::symlink_metadata(&child_path) else {
                continue;
            };
            if child_meta.file_type().is_symlink() {
                continue;
            }
            if child_meta.is_file() {
                total = total.saturating_add(child_meta.len());
            } else if child_meta.is_dir() {
                stack.push(child_path);
            }
        }
    }
    total
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
    enforce_scope_with_prefix(selected_paths, roots, "clean")
}

fn enforce_purge_scope(selected_paths: &[String], roots: &[String]) -> Result<(), String> {
    enforce_scope_with_prefix(selected_paths, roots, "purge")
}

fn enforce_installer_scope(selected_paths: &[String], roots: &[String]) -> Result<(), String> {
    enforce_scope_with_prefix(selected_paths, roots, "installer")
}

fn enforce_uninstall_scope(selected_paths: &[String], roots: &[String]) -> Result<(), String> {
    enforce_scope_with_prefix(selected_paths, roots, "uninstall")
}

fn enforce_scope_with_prefix(
    selected_paths: &[String],
    roots: &[String],
    prefix: &str,
) -> Result<(), String> {
    let canonical_roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| fs::canonicalize(root).ok())
        .collect();
    for path in selected_paths {
        let candidate = PathBuf::from(path);
        if !candidate.is_absolute() {
            return Err(err_code(
                CliErrorKind::Validation,
                &format!("{prefix}_relative_path"),
                format!("selected {prefix} path must be absolute: {path}"),
            ));
        }
        if candidate == Path::new("/") {
            return Err(err_code(
                CliErrorKind::Validation,
                &format!("{prefix}_path_scope_violation"),
                format!("selected {prefix} path cannot be root"),
            ));
        }
        if let Ok(meta) = fs::symlink_metadata(&candidate)
            && meta.file_type().is_symlink()
        {
            return Err(err_code(
                CliErrorKind::Validation,
                &format!("{prefix}_symlink_not_allowed"),
                format!("selected {prefix} path cannot be symlink: {path}"),
            ));
        }
        let canonical = fs::canonicalize(&candidate).map_err(|_| {
            err_code(
                CliErrorKind::Validation,
                &format!("{prefix}_path_scope_violation"),
                format!("selected {prefix} path cannot be resolved: {path}"),
            )
        })?;
        let in_scope = canonical_roots
            .iter()
            .any(|root| canonical.starts_with(root));
        if !in_scope {
            return Err(err_code(
                CliErrorKind::Validation,
                &format!("{prefix}_path_scope_violation"),
                format!("selected {prefix} path is outside configured roots: {path}"),
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

fn progress_line(command: &str, stage: &str, subject: &str) -> String {
    format!("progress: command={command} stage={stage} subject={subject}")
}

fn emit_progress(verbose: bool, command: &str, stage: &str, subject: &str) {
    if !verbose {
        return;
    }
    eprintln!("{}", progress_line(command, stage, subject));
}

fn install_plugin(
    spec: &str,
    lockfile: Option<PathBuf>,
    json: bool,
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let lockfile_path = resolve_lockfile_write_path(lockfile.as_deref())?;
    let locked =
        install_plugin_internal_with_verifier(spec, lockfile, "plugin.install", verbose, verifier)?;
    let installed_path = ensure_install_base_dir()?.join(&locked.pack_id);
    let resolved_rev = locked
        .resolved_rev
        .clone()
        .unwrap_or_else(|| locked.rev.clone());
    let output = PluginInstallOutput {
        pack_id: locked.pack_id,
        version: locked.version,
        source: locked.source,
        rev: locked.rev,
        resolved_rev,
        installed_path: installed_path.display().to_string(),
        lockfile_path: lockfile_path.display().to_string(),
    };
    if json {
        println!("{}", plugin_install_json(output)?);
    } else {
        let language = cli_language();
        print!(
            "{}",
            format_plugin_change_output("install", &output, &language)
        );
    }
    Ok(())
}

fn preflight_plugin(
    spec: Option<&str>,
    all: bool,
    lockfile: Option<PathBuf>,
    json: bool,
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    if all {
        return preflight_all_plugins(lockfile, json, verbose, verifier);
    }
    let spec = spec.ok_or_else(|| {
        err(
            CliErrorKind::Validation,
            "spec is required unless --all is set",
        )
    })?;
    let out = preflight_single(spec, verbose, verifier)?;
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
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let out = build_preflight_all_output(lockfile.as_deref(), verifier)?;
    if json {
        println!("{}", plugin_preflight_all_json(out.clone())?);
    } else {
        let language = cli_language();
        print!("{}", format_preflight_all_output(&out, &language, verbose));
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
        match preflight_single(&spec, false, verifier) {
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
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<PluginPreflightOutput, String> {
    let started = Instant::now();
    emit_progress(verbose, "plugin.preflight", "parse_spec", spec);
    let parsed = parse_plugin_spec(spec)
        .map_err(|e| err_code(CliErrorKind::Validation, "preflight_spec_invalid", e))?;
    emit_progress(verbose, "plugin.preflight", "resolve_source", spec);
    let (source, url, rev) = resolve_install_source(parsed)?;
    let temp_dir = TempDir::new()
        .map_err(|e| err_with(CliErrorKind::Io, "preflight temp dir create failed", e))?;
    let pack_dir = temp_dir.path().join("repo");
    emit_progress(verbose, "plugin.preflight", "clone", &url);
    let resolved_rev = clone_rule_pack_at(&url, &rev, &pack_dir, "preflight_clone_failed")?;
    emit_progress(verbose, "plugin.preflight", "load_pack", &url);
    let loaded = load_rule_pack_from_dir(&pack_dir).map_err(|e| {
        err_code(
            CliErrorKind::Validation,
            "preflight_pack_load_failed",
            format!("load failed: {e:?}"),
        )
    })?;
    emit_progress(
        verbose,
        "plugin.preflight",
        "validate_manifest",
        &loaded.manifest.pack_id,
    );
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
    emit_progress(
        verbose,
        "plugin.preflight",
        "verify_signature",
        &loaded.manifest.pack_id,
    );
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
        suggested_actions: plugin_preflight_success_actions(spec),
        duration_ms: started.elapsed().as_millis() as u64,
        detail_code: None,
    })
}

fn plugin_preflight_success_actions(spec: &str) -> Vec<String> {
    vec![
        format!("preen plugin test {spec}"),
        format!("preen plugin install {spec}"),
    ]
}

fn print_preflight_output(out: &PluginPreflightOutput) {
    let language = cli_language();
    print!("{}", format_preflight_output(out, &language));
}

fn format_preflight_output(out: &PluginPreflightOutput, language: &str) -> String {
    let mut text = String::new();
    writeln!(&mut text, "summary: kind=preflight overall_passed=true")
        .expect("writing to String should be infallible");
    writeln!(&mut text, "spec: {}", out.spec).expect("writing to String should be infallible");
    writeln!(&mut text, "source: {}", out.source).expect("writing to String should be infallible");
    writeln!(&mut text, "url: {}", out.url).expect("writing to String should be infallible");
    writeln!(&mut text, "requested_rev: {}", out.requested_rev)
        .expect("writing to String should be infallible");
    writeln!(&mut text, "resolved_rev: {}", out.resolved_rev)
        .expect("writing to String should be infallible");
    writeln!(&mut text, "pack_id: {}", out.pack_id)
        .expect("writing to String should be infallible");
    writeln!(&mut text, "version: {}", out.version)
        .expect("writing to String should be infallible");
    writeln!(&mut text, "duration_ms: {}", out.duration_ms)
        .expect("writing to String should be infallible");
    writeln!(&mut text, "checks: label={}", cli_label(language, "checks"))
        .expect("writing to String should be infallible");
    for check in &out.checks {
        writeln!(
            &mut text,
            "check: id={} label={} severity={} passed={}",
            check_id_key(check.check),
            plugin_check_label(check.check, language),
            plugin_check_severity(check.check).as_str(),
            check.passed
        )
        .expect("writing to String should be infallible");
    }
    if out.suggested_actions.is_empty() {
        writeln!(&mut text, "suggested_actions: []")
            .expect("writing to String should be infallible");
    } else {
        writeln!(
            &mut text,
            "suggested_actions: count={}",
            out.suggested_actions.len()
        )
        .expect("writing to String should be infallible");
        for action in &out.suggested_actions {
            writeln!(&mut text, "suggested_action: {action}")
                .expect("writing to String should be infallible");
        }
    }
    text
}

fn format_preflight_all_output(
    out: &PluginPreflightAllOutput,
    language: &str,
    verbose: bool,
) -> String {
    let mut text = String::new();
    writeln!(
        &mut text,
        "summary: kind=preflight_all overall_passed={} total={} passed={} failed={} summary_label={}",
        out.overall_passed,
        out.total,
        out.passed,
        out.failed,
        cli_label(language, "summary")
    )
    .expect("writing to String should be infallible");
    if out.failures.is_empty() {
        writeln!(
            &mut text,
            "failures: [] failures_label={}",
            cli_label(language, "failures")
        )
        .expect("writing to String should be infallible");
    } else {
        for failure in &out.failures {
            writeln!(
                &mut text,
                "{}",
                format_preflight_failure_row(failure, language)
            )
            .expect("writing to String should be infallible");
        }
    }
    if !verbose {
        let hidden = out.results.len();
        if hidden > 0 {
            writeln!(
                &mut text,
                "passed_results_hidden: {} rerun_with=preen plugin preflight --all --verbose",
                hidden
            )
            .expect("writing to String should be infallible");
        }
        return text;
    }

    for result in &out.results {
        write!(&mut text, "{}", format_preflight_output(result, language))
            .expect("writing to String should be infallible");
    }
    text
}

fn install_plugin_internal_with_verifier(
    spec: &str,
    lockfile: Option<PathBuf>,
    command: &'static str,
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<LockedPlugin, String> {
    let install_dir = ensure_install_base_dir()?;
    install_plugin_internal_in_dir(spec, lockfile, &install_dir, command, verbose, verifier)
}

fn install_plugin_internal_in_dir(
    spec: &str,
    lockfile: Option<PathBuf>,
    install_dir: &Path,
    command: &'static str,
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<LockedPlugin, String> {
    emit_progress(verbose, command, "parse_spec", spec);
    let parsed = parse_plugin_spec(spec)
        .map_err(|e| err_code(CliErrorKind::Validation, "install_spec_invalid", e))?;
    emit_progress(verbose, command, "resolve_source", spec);
    let (source, url, rev) = resolve_install_source(parsed).map_err(|e| {
        map_install_error_with_detail_code(
            e,
            CliErrorKind::Validation,
            "install_source_resolve_failed",
        )
    })?;
    let mut lock = load_lockfile(lockfile.as_deref()).map_err(|e| {
        map_install_error_with_detail_code(e, CliErrorKind::Io, "install_lockfile_load_failed")
    })?;
    fs::create_dir_all(install_dir)
        .map_err(|e| err_with(CliErrorKind::Io, "plugin base dir create failed", e))?;
    let temp_dir = TempDir::new_in(install_dir)
        .map_err(|e| err_with(CliErrorKind::Io, "temp dir create failed", e))?;
    let pack_dir = temp_dir.path().join("repo");
    emit_progress(verbose, command, "clone", &url);
    let resolved_rev = clone_rule_pack_at(&url, &rev, &pack_dir, "install_clone_failed")?;
    emit_progress(verbose, command, "load_pack", &url);
    let loaded = load_rule_pack_from_dir(&pack_dir).map_err(|e| {
        err_code(
            CliErrorKind::Validation,
            "install_pack_load_failed",
            format!("load failed: {e:?}"),
        )
    })?;
    emit_progress(
        verbose,
        command,
        "validate_manifest",
        &loaded.manifest.pack_id,
    );
    validate_os_targets(&loaded)
        .map_err(|e| err_code(CliErrorKind::Validation, "install_os_target_failed", e))?;
    loaded
        .manifest
        .validate_with_core_version("0.1.0")
        .map_err(|e| {
            err_code(
                CliErrorKind::Validation,
                "install_core_compat_failed",
                format!("core compatibility check failed: {e:?}"),
            )
        })?;
    if loaded.manifest.action_api != 1 {
        return Err(err_code(
            CliErrorKind::Validation,
            "install_action_api_unsupported",
            "unsupported action_api",
        ));
    }
    let trust = load_trust_policy().map_err(|e| {
        map_install_error_with_detail_code(
            e,
            CliErrorKind::Validation,
            "install_trust_policy_invalid",
        )
    })?;
    emit_progress(
        verbose,
        command,
        "verify_signature",
        &loaded.manifest.pack_id,
    );
    verify_rule_pack_with_verifier(&loaded, &trust, verifier).map_err(|e| {
        map_install_error_with_detail_code(
            e,
            CliErrorKind::Verification,
            "install_signature_or_trust_failed",
        )
    })?;
    emit_progress(verbose, command, "hash_artifacts", &loaded.manifest.pack_id);
    let manifest_hash = hash_file(&pack_dir.join("manifest.toml")).map_err(|e| {
        map_install_error_with_detail_code(e, CliErrorKind::Io, "install_manifest_hash_failed")
    })?;
    let signature_hash = hash_file(&pack_dir.join("manifest.sig")).map_err(|e| {
        map_install_error_with_detail_code(e, CliErrorKind::Io, "install_signature_hash_failed")
    })?;

    let final_dir = install_dir.join(&loaded.manifest.pack_id);
    if final_dir.exists() {
        fs::remove_dir_all(&final_dir)
            .map_err(|e| err_with(CliErrorKind::Io, "existing plugin remove failed", e))?;
    }
    emit_progress(verbose, command, "write_files", &loaded.manifest.pack_id);
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
    emit_progress(verbose, command, "write_lockfile", &locked.pack_id);
    save_lockfile(lockfile.as_deref(), &lock).map_err(|e| {
        map_install_error_with_detail_code(e, CliErrorKind::Io, "install_lockfile_save_failed")
    })?;
    Ok(locked)
}

fn map_install_error_with_detail_code(
    message: String,
    fallback_kind: CliErrorKind,
    detail_code: &str,
) -> String {
    let (kind_raw, _, plain_message) = parse_error_metadata(&message);
    let kind = CliErrorKind::from_str(&kind_raw).unwrap_or(fallback_kind);
    err_code(kind, detail_code, plain_message)
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
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    if all {
        return test_all_plugins(lockfile, json, verbose, verifier);
    }
    let target = pack_id.ok_or_else(|| {
        err(
            CliErrorKind::Validation,
            "target is required unless --all is set",
        )
    })?;
    if parse_plugin_spec(target).is_ok() {
        return test_plugin_spec(target, json, verbose, verifier);
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
        Some(value) if value.starts_with("purge_") => true,
        Some(value) if value.starts_with("installer_") => true,
        Some(value) if value.starts_with("uninstall_") => true,
        Some(value) if value.starts_with("optimize_") => true,
        Some(value) if value.starts_with("check_") => true,
        Some(value) if value.starts_with("analyze_") => true,
        Some(value) if value.starts_with("status_") => true,
        Some(value) if value.starts_with("touchid_") => true,
        Some(value) if value.starts_with("completion_") => true,
        Some(value) if value.starts_with("update_") => true,
        Some(value) if value.starts_with("remove_") => true,
        _ => false,
    }
}

fn test_plugin_spec(
    spec: &str,
    json: bool,
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let out = preflight_single(spec, verbose, verifier)?;
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
        suggested_actions: out.suggested_actions,
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
    if !test.suggested_actions.is_empty() {
        println!("suggested_actions: count={}", test.suggested_actions.len());
        for action in &test.suggested_actions {
            println!("suggested_action: {action}");
        }
    }
    Ok(())
}

fn test_all_plugins(
    lockfile: Option<PathBuf>,
    json: bool,
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let out = build_test_all_output(lockfile.as_deref(), None, verifier)?;
    if json {
        println!("{}", plugin_test_all_json(out.clone())?);
    } else {
        let language = cli_language();
        print!("{}", format_test_all_output(&out, &language, verbose));
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

fn format_plugin_change_output(
    kind: &'static str,
    out: &PluginInstallOutput,
    language: &str,
) -> String {
    let mut output = String::new();
    writeln!(
        &mut output,
        "summary: kind={} pack_id={} version={} source={} rev={} summary_label={}",
        kind,
        out.pack_id,
        out.version,
        out.source,
        out.rev,
        cli_label(language, "summary")
    )
    .expect("writing to String should be infallible");
    writeln!(&mut output, "resolved_rev: {}", out.resolved_rev)
        .expect("writing to String should be infallible");
    writeln!(&mut output, "installed_path: {}", out.installed_path)
        .expect("writing to String should be infallible");
    writeln!(&mut output, "lockfile_path: {}", out.lockfile_path)
        .expect("writing to String should be infallible");
    let next_steps = [
        format!("preen plugin verify {}", out.pack_id),
        format!("preen plugin test {}", out.pack_id),
        format!("preen plugin info {}", out.pack_id),
    ];
    writeln!(&mut output, "next_steps: count={}", next_steps.len())
        .expect("writing to String should be infallible");
    for step in next_steps {
        writeln!(&mut output, "next_step: {step}").expect("writing to String should be infallible");
    }
    output
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
    if report.suggested_actions.is_empty() {
        writeln!(&mut out, "suggested_actions: []")
            .expect("writing to String should be infallible");
    } else {
        writeln!(
            &mut out,
            "suggested_actions: count={}",
            report.suggested_actions.len()
        )
        .expect("writing to String should be infallible");
        for action in &report.suggested_actions {
            writeln!(&mut out, "suggested_action: {action}")
                .expect("writing to String should be infallible");
        }
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

fn format_test_all_output(out: &PluginTestAllOutput, language: &str, verbose: bool) -> String {
    let mut text = String::new();
    writeln!(
        &mut text,
        "summary: kind=test_all overall_passed={} total={} passed={} failed={} summary_label={}",
        out.overall_passed,
        out.total,
        out.passed,
        out.failed,
        cli_label(language, "summary")
    )
    .expect("writing to String should be infallible");
    if out.failures.is_empty() {
        writeln!(
            &mut text,
            "failures: [] failures_label={}",
            cli_label(language, "failures")
        )
        .expect("writing to String should be infallible");
    } else {
        for failure in &out.failures {
            writeln!(&mut text, "{}", format_test_failure_row(failure, language))
                .expect("writing to String should be infallible");
        }
    }
    if verbose {
        for result in &out.results {
            write!(&mut text, "{}", format_plugin_test_output(result, language))
                .expect("writing to String should be infallible");
        }
        return text;
    }

    let mut shown_failed_reports = 0usize;
    for result in &out.results {
        if !result.overall_passed {
            shown_failed_reports += 1;
            write!(&mut text, "{}", format_plugin_test_output(result, language))
                .expect("writing to String should be infallible");
        }
    }
    let hidden = out.results.len().saturating_sub(shown_failed_reports);
    if hidden > 0 {
        writeln!(
            &mut text,
            "passed_results_hidden: {} rerun_with=preen plugin test --all --verbose",
            hidden
        )
        .expect("writing to String should be infallible");
    }
    text
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

fn plugin_test_suggested_actions(
    pack_id: &str,
    overall_passed: bool,
    detail_code: Option<&str>,
) -> Vec<String> {
    let mut actions = Vec::new();
    if overall_passed {
        push_unique_action(&mut actions, &format!("preen plugin verify {pack_id}"));
        push_unique_action(&mut actions, &format!("preen plugin info {pack_id}"));
        push_unique_action(&mut actions, &format!("preen plugin update {pack_id}"));
        return actions;
    }

    push_unique_action(&mut actions, &format!("preen plugin test {pack_id}"));
    push_unique_action(&mut actions, &format!("preen plugin verify {pack_id}"));
    push_unique_action(&mut actions, &format!("preen plugin info {pack_id}"));
    if let Some(code) = detail_code {
        match code {
            "test_signature_or_trust_failed" | "verify_signature_or_trust_failed" => {
                push_unique_action(&mut actions, "preen plugin registry-update");
                push_unique_action(&mut actions, "preen plugin preflight --all");
            }
            "test_resolved_rev_drift"
            | "test_manifest_hash_drift"
            | "test_signature_hash_drift"
            | "test_version_drift" => {
                push_unique_action(&mut actions, &format!("preen plugin update {pack_id}"));
            }
            "test_core_compat_failed" | "test_action_api_unsupported" => {
                push_unique_action(&mut actions, "preen update");
            }
            _ => {}
        }
    }
    actions
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
        suggested_actions: plugin_test_suggested_actions(pack_id, true, None),
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
    let suggested_actions =
        plugin_test_suggested_actions(&plugin.pack_id, overall_passed, detail_code.as_deref());

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
        suggested_actions,
        duration_ms: started.elapsed().as_millis() as u64,
        drifts,
        detail_code,
    })
}

fn update_plugin(
    pack_id: &str,
    lockfile: Option<PathBuf>,
    json: bool,
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    let lockfile_path = resolve_lockfile_write_path(lockfile.as_deref())?;
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
        "plugin.update",
        verbose,
        verifier,
    )?;
    let installed_path = ensure_install_base_dir()?.join(&locked.pack_id);
    let resolved_rev = locked
        .resolved_rev
        .clone()
        .unwrap_or_else(|| locked.rev.clone());
    let output = PluginInstallOutput {
        pack_id: locked.pack_id,
        version: locked.version,
        source: locked.source,
        rev: locked.rev,
        resolved_rev,
        installed_path: installed_path.display().to_string(),
        lockfile_path: lockfile_path.display().to_string(),
    };
    if json {
        println!("{}", plugin_update_json(output)?);
    } else {
        let language = cli_language();
        print!(
            "{}",
            format_plugin_change_output("update", &output, &language)
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

pub fn progress_line_for_test(command: &str, stage: &str, subject: &str) -> String {
    progress_line(command, stage, subject)
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
            suggested_actions: plugin_test_suggested_actions(pack_id, true, None),
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
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<String, String> {
    let out = build_test_all_output(lockfile, Some(install_dir), verifier)?;
    if json {
        return plugin_test_all_json(out);
    }
    Ok(format_test_all_output(&out, "en-US", verbose))
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
        suggested_actions: plugin_test_suggested_actions(pack_id, true, None),
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
        suggested_actions: plugin_preflight_success_actions(spec),
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
        suggested_actions: plugin_preflight_success_actions(spec),
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
    json: bool,
    verbose: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<String, String> {
    let out = build_preflight_all_output(lockfile, verifier)?;
    if json {
        return plugin_preflight_all_json(out);
    }
    Ok(format_preflight_all_output(&out, "en-US", verbose))
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
    let state_dir = preen_state_dir()?;
    let installed_path = state_dir.join("plugins").join(pack_id);
    let lockfile_path = default_lockfile_path()?;
    plugin_install_json(PluginInstallOutput {
        pack_id: pack_id.to_string(),
        version: version.to_string(),
        source: source.to_string(),
        rev: rev.to_string(),
        resolved_rev: rev.to_string(),
        installed_path: installed_path.display().to_string(),
        lockfile_path: lockfile_path.display().to_string(),
    })
}

pub fn plugin_install_text_for_test(
    pack_id: &str,
    version: &str,
    source: &str,
    rev: &str,
) -> String {
    let state_dir = preen_state_dir().unwrap_or_else(|_| PathBuf::from("."));
    let installed_path = state_dir.join("plugins").join(pack_id);
    let lockfile_path = default_lockfile_path().unwrap_or_else(|_| PathBuf::from("plugins.lock"));
    format_plugin_change_output(
        "install",
        &PluginInstallOutput {
            pack_id: pack_id.to_string(),
            version: version.to_string(),
            source: source.to_string(),
            rev: rev.to_string(),
            resolved_rev: rev.to_string(),
            installed_path: installed_path.display().to_string(),
            lockfile_path: lockfile_path.display().to_string(),
        },
        "en-US",
    )
}

pub fn plugin_update_json_for_test(
    pack_id: &str,
    version: &str,
    source: &str,
    rev: &str,
) -> Result<String, String> {
    let state_dir = preen_state_dir()?;
    let installed_path = state_dir.join("plugins").join(pack_id);
    let lockfile_path = default_lockfile_path()?;
    plugin_update_json(PluginInstallOutput {
        pack_id: pack_id.to_string(),
        version: version.to_string(),
        source: source.to_string(),
        rev: rev.to_string(),
        resolved_rev: rev.to_string(),
        installed_path: installed_path.display().to_string(),
        lockfile_path: lockfile_path.display().to_string(),
    })
}

pub fn plugin_update_text_for_test(
    pack_id: &str,
    version: &str,
    source: &str,
    rev: &str,
) -> String {
    let state_dir = preen_state_dir().unwrap_or_else(|_| PathBuf::from("."));
    let installed_path = state_dir.join("plugins").join(pack_id);
    let lockfile_path = default_lockfile_path().unwrap_or_else(|_| PathBuf::from("plugins.lock"));
    format_plugin_change_output(
        "update",
        &PluginInstallOutput {
            pack_id: pack_id.to_string(),
            version: version.to_string(),
            source: source.to_string(),
            rev: rev.to_string(),
            resolved_rev: rev.to_string(),
            installed_path: installed_path.display().to_string(),
            lockfile_path: lockfile_path.display().to_string(),
        },
        "en-US",
    )
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
        suggested_actions: plugin_test_suggested_actions("test.pack", drifts.is_empty(), None),
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
    let path = resolve_lockfile_write_path(path)?;
    save_lockfile_at(&path, lock)
}

fn resolve_lockfile_write_path(path: Option<&Path>) -> Result<PathBuf, String> {
    match path {
        Some(path) => Ok(path.to_path_buf()),
        None => default_lockfile_path(),
    }
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

pub fn enforce_purge_scope_for_test(
    selected_paths: &[String],
    roots: &[String],
) -> Result<(), String> {
    enforce_purge_scope(selected_paths, roots)
}

pub fn enforce_installer_scope_for_test(
    selected_paths: &[String],
    roots: &[String],
) -> Result<(), String> {
    enforce_installer_scope(selected_paths, roots)
}

pub fn enforce_uninstall_scope_for_test(
    selected_paths: &[String],
    roots: &[String],
) -> Result<(), String> {
    enforce_uninstall_scope(selected_paths, roots)
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

pub fn purge_output_for_test(dry_run: bool, confirm: bool) -> Result<serde_json::Value, String> {
    let output = run_purge_output_with_executor(dry_run, confirm, &OsActionExecutor)?;
    let json = purge_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "purge output parse failed", e))
}

pub fn installer_output_for_test(
    dry_run: bool,
    confirm: bool,
) -> Result<serde_json::Value, String> {
    let output = run_installer_output_with_executor(dry_run, confirm, &OsActionExecutor)?;
    let json = installer_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "installer output parse failed", e))
}

pub fn uninstall_output_for_test(
    target: Option<&str>,
    dry_run: bool,
    confirm: bool,
) -> Result<serde_json::Value, String> {
    let output = run_uninstall_output_with_executor(target, dry_run, confirm, &OsActionExecutor)?;
    let json = uninstall_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "uninstall output parse failed", e))
}

pub fn optimize_output_for_test(dry_run: bool, confirm: bool) -> Result<serde_json::Value, String> {
    let output = run_optimize_output_with_executor(dry_run, confirm, &OsActionExecutor)?;
    let json = optimize_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "optimize output parse failed", e))
}

pub fn optimize_output_with_executor_for_test(
    dry_run: bool,
    confirm: bool,
    clean_executor: &dyn ActionExecutorPort,
) -> Result<serde_json::Value, String> {
    let output = run_optimize_output_with_executor(dry_run, confirm, clean_executor)?;
    let json = optimize_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "optimize output parse failed", e))
}

pub fn check_output_for_test(fix: bool) -> Result<serde_json::Value, String> {
    let output = run_check_output(fix);
    let json = check_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "check output parse failed", e))
}

pub fn analyze_output_for_test(path: Option<&Path>) -> Result<serde_json::Value, String> {
    let output = run_analyze_output(path.map(|value| value.to_path_buf()), None)?;
    let json = analyze_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "analyze output parse failed", e))
}

pub fn analyze_output_with_depth_for_test(
    path: Option<&Path>,
    max_depth: Option<usize>,
) -> Result<serde_json::Value, String> {
    let output = run_analyze_output(path.map(|value| value.to_path_buf()), max_depth)?;
    let json = analyze_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "analyze output parse failed", e))
}

pub fn status_output_for_test() -> Result<serde_json::Value, String> {
    let output = run_status_output()?;
    let json = status_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "status output parse failed", e))
}

pub fn status_should_emit_json_for_test(json_flag: bool) -> bool {
    should_emit_status_json(json_flag)
}

pub fn touchid_output_for_test(
    action: Option<&str>,
    dry_run: bool,
) -> Result<serde_json::Value, String> {
    let action = match action.map(|value| value.trim().to_ascii_lowercase()) {
        Some(value) if value == "enable" => Some(TouchIdActionArg::Enable),
        Some(value) if value == "disable" => Some(TouchIdActionArg::Disable),
        Some(value) if value == "status" => Some(TouchIdActionArg::Status),
        Some(other) => {
            return Err(err(
                CliErrorKind::Validation,
                format!("unsupported touchid action for test: {other}"),
            ));
        }
        None => None,
    };
    let output = run_touchid_output(action.unwrap_or(TouchIdActionArg::Status), dry_run)?;
    let json = touchid_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "touchid output parse failed", e))
}

pub fn completion_output_for_test(
    shell: Option<&str>,
    dry_run: bool,
) -> Result<serde_json::Value, String> {
    let shell = match shell.map(|value| value.trim().to_ascii_lowercase()) {
        Some(value) if value == "bash" => Some(CompletionShellArg::Bash),
        Some(value) if value == "zsh" => Some(CompletionShellArg::Zsh),
        Some(value) if value == "fish" => Some(CompletionShellArg::Fish),
        Some(other) => {
            return Err(err(
                CliErrorKind::Validation,
                format!("unsupported completion shell for test: {other}"),
            ));
        }
        None => None,
    };
    let output = run_completion_output(shell, dry_run)?;
    let json = completion_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "completion output parse failed", e))
}

pub fn update_output_for_test(force: bool, nightly: bool) -> Result<serde_json::Value, String> {
    let output = run_update_output(force, nightly);
    let json = update_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "update output parse failed", e))
}

pub fn remove_output_for_test(dry_run: bool) -> Result<serde_json::Value, String> {
    let output = run_remove_output(dry_run)?;
    let json = remove_json(output)?;
    serde_json::from_str(&json)
        .map_err(|e| err_with(CliErrorKind::Internal, "remove output parse failed", e))
}

pub fn clean_runtime_error_detail_code_for_test(error: RuntimeExecutionError) -> Option<String> {
    let encoded = map_clean_runtime_error(error);
    decode_tagged_error(&encoded).and_then(|(_, detail_code, _)| detail_code)
}

pub fn installer_runtime_error_detail_code_for_test(
    error: RuntimeExecutionError,
) -> Option<String> {
    let encoded = map_installer_runtime_error(error);
    decode_tagged_error(&encoded).and_then(|(_, detail_code, _)| detail_code)
}

pub fn uninstall_runtime_error_detail_code_for_test(
    error: RuntimeExecutionError,
) -> Option<String> {
    let encoded = map_uninstall_runtime_error(error);
    decode_tagged_error(&encoded).and_then(|(_, detail_code, _)| detail_code)
}

pub fn optimize_runtime_error_detail_code_for_test(error: RuntimeExecutionError) -> Option<String> {
    let encoded = map_optimize_runtime_error(error);
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
        "plugin.install",
        false,
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
        target: Option<String>,
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: bool,
        #[arg(long, conflicts_with_all = ["target", "dry_run", "confirm"])]
        paths: bool,
        #[arg(long)]
        json: bool,
    },
    Optimize {
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: bool,
        #[arg(long)]
        json: bool,
    },
    Analyze {
        path: Option<PathBuf>,
        #[arg(long)]
        max_depth: Option<usize>,
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
        #[arg(long, conflicts_with = "dry_run")]
        confirm: bool,
        #[arg(long, conflicts_with_all = ["dry_run", "confirm"])]
        paths: bool,
        #[arg(long)]
        json: bool,
    },
    Installer {
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: bool,
        #[arg(long, conflicts_with_all = ["dry_run", "confirm"])]
        paths: bool,
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
        verbose: bool,
        #[arg(long)]
        json: bool,
    },
    Preflight {
        spec: Option<String>,
        #[arg(long, conflicts_with = "spec")]
        all: bool,
        #[arg(long)]
        verbose: bool,
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
        verbose: bool,
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
        verbose: bool,
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
