use crate::action_executor::OsActionExecutor;
use crate::smart_care::read_plugin_lockfile_from_state_dir;
use preen_core::action_runtime::{
    ActionExecutorPort, DefaultSafetyPolicy, ExecutionMode, build_execution_plan,
};
use preen_core::plugin::ActionType;
use preen_core::plugin_loader::load_rule_pack_from_dir;
use preen_core::plugin_lock::PluginLockfile;
use preen_core::smart_care::{
    SmartCareCapability, SmartCarePluginDescriptor, SmartCarePreview, SmartCareProfile,
    build_preview_from_descriptors, infer_capability_from_rule,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::Path;

const SMART_CARE_RUN_JOURNAL_FILE: &str = "smart-care-last-run.toml";
const SMART_CARE_RUN_JOURNAL_SCHEMA_VERSION: u32 = 1;
const SMART_CARE_APPLY_CONFIRMATION_TOKEN: &str = "smart-care-apply";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartCareAnalyzeOutput {
    pub preview: SmartCarePreview,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartCareExecuteOutput {
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SmartCareRunJournal {
    schema_version: u32,
    run_id: u64,
    mode: String,
    review_entries: usize,
    success_rules: u64,
    failed_rules: u64,
    total_affected_items: u64,
    total_freed_bytes: u64,
    #[serde(default)]
    undo_items: Vec<SmartCareUndoItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SmartCareUndoItem {
    pack_id: String,
    rule_id: String,
    action_type: String,
    original_path: String,
    undo_info: String,
}

#[derive(Debug)]
enum SmartCareJournalError {
    NotFound,
    Io(io::Error),
    Parse(toml::de::Error),
}

pub fn analyze(
    profile: &SmartCareProfile,
    descriptors: &[SmartCarePluginDescriptor],
    state_dir: Option<&Path>,
) -> SmartCareAnalyzeOutput {
    let mut preview = build_preview_from_descriptors(profile, descriptors);
    if let Some(state_dir) = state_dir {
        enrich_review_entries_from_installed_rules(state_dir, descriptors, &mut preview);
    }
    let enabled = profile.enabled_capabilities();

    if enabled.is_empty() {
        return SmartCareAnalyzeOutput {
            preview,
            lines: vec![
                "overall: blocked".to_string(),
                "reason: no capability selected".to_string(),
                "hint: toggle capability with 1/2/3/4".to_string(),
            ],
        };
    }

    let mut lines = Vec::new();
    let mut selected_packs = BTreeSet::new();
    lines.push(format!("enabled_capabilities: {}", enabled.len()));

    for capability in enabled {
        let candidates = descriptors
            .iter()
            .filter(|descriptor| descriptor.enabled && descriptor.capability == capability)
            .collect::<Vec<_>>();
        let trusted_count = candidates
            .iter()
            .filter(|descriptor| descriptor.trusted_identity.is_some())
            .count();
        let status = if candidates.is_empty() {
            "missing_plugin"
        } else if trusted_count == 0 {
            "untrusted_only"
        } else {
            for descriptor in &candidates {
                selected_packs.insert(format!(
                    "{}@{}",
                    descriptor.pack_id,
                    descriptor.version.as_deref().unwrap_or("n/a")
                ));
            }
            "ready"
        };
        lines.push(format!(
            "capability={} plugins={} trusted={} status={}",
            capability.as_str(),
            candidates.len(),
            trusted_count,
            status
        ));
    }

    if selected_packs.is_empty() {
        lines.push("overall: blocked".to_string());
        lines.push("reason: no trusted plugin available for selected capability".to_string());
        lines
            .push("hint: install trusted capability packs or relax trust policy later".to_string());
    } else {
        lines.push("overall: ready".to_string());
        lines.push(format!("selected_plugins: {}", selected_packs.len()));
        for pack in selected_packs {
            lines.push(format!("plan: {pack}"));
        }
    }

    SmartCareAnalyzeOutput { preview, lines }
}

fn enrich_review_entries_from_installed_rules(
    state_dir: &Path,
    descriptors: &[SmartCarePluginDescriptor],
    preview: &mut SmartCarePreview,
) {
    let lockfile = match read_plugin_lockfile_from_state_dir(state_dir) {
        Ok(lockfile) => lockfile,
        Err(_) => return,
    };
    let plugins_dir = state_dir.join("plugins");
    if !plugins_dir.is_dir() {
        return;
    }

    let mut enriched = Vec::new();
    for entry in &preview.review_entries {
        let descriptor = descriptors.iter().find(|descriptor| {
            descriptor.enabled
                && descriptor.trusted_identity.is_some()
                && descriptor.capability == entry.capability
                && descriptor.pack_id == entry.pack_id
        });
        let Some(descriptor) = descriptor else {
            enriched.push(entry.clone());
            continue;
        };

        let locked_plugin = lockfile
            .plugins
            .iter()
            .find(|plugin| plugin.pack_id == descriptor.pack_id);
        let Some(locked_plugin) = locked_plugin else {
            enriched.push(entry.clone());
            continue;
        };

        let pack_dir = plugins_dir.join(&locked_plugin.pack_id);
        let loaded_pack = match load_rule_pack_from_dir(&pack_dir) {
            Ok(pack) => pack,
            Err(_) => {
                enriched.push(entry.clone());
                continue;
            }
        };

        let matching_rules = loaded_pack
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .filter(|rule| infer_capability_from_rule(rule) == Some(entry.capability))
            .collect::<Vec<_>>();
        if matching_rules.is_empty() {
            enriched.push(entry.clone());
            continue;
        }

        for rule in matching_rules {
            enriched.push(preen_core::smart_care::SmartCareReviewEntry {
                id: format!(
                    "{}:{}:{}",
                    descriptor.pack_id,
                    descriptor.capability.as_str(),
                    rule.id
                ),
                capability: descriptor.capability,
                pack_id: descriptor.pack_id.clone(),
                version: descriptor.version.clone(),
                trusted_identity: descriptor.trusted_identity.clone(),
                rule_id: Some(rule.id.clone()),
                rule_label: Some(rule.name.clone()),
            });
        }
    }

    if !enriched.is_empty() {
        preview.review_entries = enriched;
    }
}

pub fn execute_local_dry_run(
    preview: &SmartCarePreview,
    disabled_entry_ids: &HashSet<String>,
    review_confirmed: bool,
) -> SmartCareExecuteOutput {
    let selected_entries = preview
        .review_entries
        .iter()
        .filter(|entry| !disabled_entry_ids.contains(&entry.id))
        .collect::<Vec<_>>();

    let mut lines = Vec::new();
    if !review_confirmed {
        lines.push("run: blocked".to_string());
        lines.push("reason: review is required before run".to_string());
        lines.push("hint: open review with 'v' and confirm selected entries".to_string());
        return SmartCareExecuteOutput { lines };
    }
    if !preview.overall_ready {
        lines.push("run: blocked".to_string());
        lines.push("reason: preview is not ready".to_string());
        for blocker in preview.blockers.iter().take(4) {
            lines.push(format!("blocker: {blocker}"));
        }
        return SmartCareExecuteOutput { lines };
    }
    if selected_entries.is_empty() {
        lines.push("run: blocked".to_string());
        lines.push("reason: no review entry selected".to_string());
        lines.push("hint: select at least one entry with <space>".to_string());
        return SmartCareExecuteOutput { lines };
    }

    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    let selected_plugins = selected_entries
        .iter()
        .map(|entry| {
            format!(
                "{}@{}",
                entry.pack_id,
                entry.version.as_deref().unwrap_or("n/a")
            )
        })
        .collect::<BTreeSet<_>>();

    lines.push(format!("run: local-dry-run-{run_id}"));
    lines.push(format!("selected_plugins: {}", selected_plugins.len()));
    lines.push(format!("review_entries: {}", selected_entries.len()));
    for capability in [
        SmartCareCapability::Cleanup,
        SmartCareCapability::Performance,
        SmartCareCapability::Applications,
        SmartCareCapability::Protection,
    ] {
        let count = selected_entries
            .iter()
            .filter(|entry| entry.capability == capability)
            .count();
        lines.push(format!(
            "capability={} entries={count}",
            capability.as_str()
        ));
    }
    lines.push("result: dry-run completed (execution wiring pending)".to_string());
    SmartCareExecuteOutput { lines }
}

fn calculate_size(path: &std::path::Path) -> u64 {
    if path.is_file() {
        return fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    }
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len())
        .sum()
}

fn expand_path(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(shellexpand::tilde(path).to_string())
}

fn move_path_to_trash_with_undo_info(path: &std::path::Path) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().ok_or_else(|| "missing home dir".to_string())?;
        let trash_dir = home.join(".Trash");
        fs::create_dir_all(&trash_dir).map_err(|error| error.to_string())?;
        let file_name = path
            .file_name()
            .ok_or_else(|| "missing file name".to_string())?
            .to_string_lossy()
            .to_string();
        let mut target = trash_dir.join(&file_name);
        if target.exists() {
            let suffix = uuid::Uuid::new_v4().to_string();
            target = trash_dir.join(format!("{file_name}.{suffix}"));
        }
        fs::rename(path, &target).map_err(|error| error.to_string())?;
        Ok(target.to_string_lossy().to_string())
    }

    #[cfg(not(target_os = "macos"))]
    {
        trash::delete(path).map_err(|error| error.to_string())?;
        Ok(path.to_string_lossy().to_string())
    }
}

fn execute_trash_paths_with_undo_journal(
    plan: &preen_core::action_runtime::ExecutionPlan,
    pack_id: &str,
    rule_id: &str,
    undo_items: &mut Vec<SmartCareUndoItem>,
) -> Result<
    preen_core::action_runtime::ActionExecutionResult,
    preen_core::action_runtime::ActionExecutionError,
> {
    let mut affected_items: u64 = 0;
    let mut freed_bytes: u64 = 0;
    let mut warnings = Vec::new();

    for raw in &plan.request.action.paths {
        let path = expand_path(raw);
        if !path.exists() {
            warnings.push(format!("path not found: {}", path.display()));
            continue;
        }

        affected_items = affected_items.saturating_add(1);
        freed_bytes = freed_bytes.saturating_add(calculate_size(&path));

        if plan.request.mode == ExecutionMode::DryRun {
            continue;
        }

        let undo_info = move_path_to_trash_with_undo_info(&path).map_err(|message| {
            preen_core::action_runtime::ActionExecutionError::Failed {
                message: format!("trash failed: {}: {message}", path.display()),
            }
        })?;
        undo_items.push(SmartCareUndoItem {
            pack_id: pack_id.to_string(),
            rule_id: rule_id.to_string(),
            action_type: "TrashPaths".to_string(),
            original_path: path.to_string_lossy().to_string(),
            undo_info,
        });
    }

    Ok(preen_core::action_runtime::ActionExecutionResult {
        affected_items,
        freed_bytes,
        warnings,
    })
}

pub fn execute_from_state_dir(
    state_dir: &Path,
    preview: &SmartCarePreview,
    disabled_entry_ids: &HashSet<String>,
    review_confirmed: bool,
    apply_confirmed: bool,
) -> SmartCareExecuteOutput {
    if !review_confirmed {
        return SmartCareExecuteOutput {
            lines: vec![
                "run: blocked".to_string(),
                "reason: review is required before run".to_string(),
                "hint: open review with 'v' and confirm selected entries".to_string(),
            ],
        };
    }
    if !apply_confirmed {
        return SmartCareExecuteOutput {
            lines: vec![
                "run: blocked".to_string(),
                "reason: apply confirmation gate is not armed".to_string(),
                "hint: arm apply in UI with Shift+X and retry".to_string(),
            ],
        };
    }
    if !preview.overall_ready {
        let mut lines = vec![
            "run: blocked".to_string(),
            "reason: preview is not ready".to_string(),
        ];
        lines.extend(
            preview
                .blockers
                .iter()
                .take(4)
                .map(|blocker| format!("blocker: {blocker}")),
        );
        return SmartCareExecuteOutput { lines };
    }

    let selected_entries = preview
        .review_entries
        .iter()
        .filter(|entry| !disabled_entry_ids.contains(&entry.id))
        .collect::<Vec<_>>();
    let selected_entry_count = selected_entries.len();
    if selected_entries.is_empty() {
        return SmartCareExecuteOutput {
            lines: vec![
                "run: blocked".to_string(),
                "reason: no review entry selected".to_string(),
                "hint: select at least one entry with <space>".to_string(),
            ],
        };
    }

    let lockfile = match read_lockfile(state_dir) {
        Ok(lockfile) => lockfile,
        Err(error) => {
            return SmartCareExecuteOutput {
                lines: vec!["run: failed".to_string(), format!("reason: {error}")],
            };
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return SmartCareExecuteOutput {
                lines: vec![
                    "run: failed".to_string(),
                    format!("reason: failed to initialize async runtime: {error}"),
                ],
            };
        }
    };

    let action_executor = OsActionExecutor;
    let safety_policy = DefaultSafetyPolicy::default();
    let execution_mode = ExecutionMode::Apply;
    let confirmation_token = Some(SMART_CARE_APPLY_CONFIRMATION_TOKEN);
    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    let mut lines = Vec::new();
    lines.push(format!("run: core-os-apply-{run_id}"));
    lines.push(format!("state_dir: {}", state_dir.display()));
    lines.push(format!("selected_entries: {selected_entry_count}"));

    let mut success_count: u64 = 0;
    let mut failure_count: u64 = 0;
    let mut total_affected_items: u64 = 0;
    let mut total_freed_bytes: u64 = 0;
    let mut undo_items = Vec::new();
    let mut executed_rule_keys = HashSet::new();

    for entry in &selected_entries {
        let Some(locked_plugin) = lockfile
            .plugins
            .iter()
            .find(|item| item.pack_id == entry.pack_id)
        else {
            failure_count = failure_count.saturating_add(1);
            lines.push(format!(
                "entry: {} capability={} failed=missing_lockfile_entry",
                entry.pack_id,
                entry.capability.as_str()
            ));
            continue;
        };

        let pack_dir = state_dir.join("plugins").join(&locked_plugin.pack_id);
        let loaded_pack = match load_rule_pack_from_dir(&pack_dir) {
            Ok(loaded_pack) => loaded_pack,
            Err(error) => {
                failure_count = failure_count.saturating_add(1);
                lines.push(format!(
                    "entry: {} capability={} failed=load_rule_pack error={error:?}",
                    locked_plugin.pack_id,
                    entry.capability.as_str()
                ));
                continue;
            }
        };

        let matching_rules = loaded_pack
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .filter(|rule| infer_capability_from_rule(rule) == Some(entry.capability))
            .filter(|rule| match entry.rule_id.as_deref() {
                Some(rule_id) => rule.id == rule_id,
                None => true,
            })
            .collect::<Vec<_>>();

        if matching_rules.is_empty() {
            lines.push(format!(
                "entry: {} capability={} skipped=no_matching_rule",
                locked_plugin.pack_id,
                entry.capability.as_str()
            ));
            continue;
        }

        for rule in matching_rules {
            let rule_key = format!("{}:{}", locked_plugin.pack_id, rule.id);
            if !executed_rule_keys.insert(rule_key.clone()) {
                continue;
            }
            let plan = match build_execution_plan(
                &loaded_pack.manifest,
                rule,
                execution_mode,
                confirmation_token,
                &safety_policy,
            ) {
                Ok(plan) => plan,
                Err(error) => {
                    failure_count = failure_count.saturating_add(1);
                    lines.push(format!(
                        "rule: {}:{} failed=plan error={error}",
                        locked_plugin.pack_id, rule.id
                    ));
                    continue;
                }
            };

            let execution_result = if execution_mode == ExecutionMode::Apply
                && matches!(rule.action.action_type, ActionType::TrashPaths)
            {
                execute_trash_paths_with_undo_journal(
                    &plan,
                    &locked_plugin.pack_id,
                    &rule.id,
                    &mut undo_items,
                )
            } else {
                runtime.block_on(action_executor.execute(&plan))
            };

            match execution_result {
                Ok(result) => {
                    success_count = success_count.saturating_add(1);
                    total_affected_items =
                        total_affected_items.saturating_add(result.affected_items);
                    total_freed_bytes = total_freed_bytes.saturating_add(result.freed_bytes);
                    lines.push(format!(
                        "rule: {}:{} ok affected={} freed_bytes={}",
                        locked_plugin.pack_id, rule.id, result.affected_items, result.freed_bytes
                    ));
                    for warning in result.warnings.iter().take(2) {
                        lines.push(format!(
                            "warning: {}:{} {warning}",
                            locked_plugin.pack_id, rule.id
                        ));
                    }
                }
                Err(error) => {
                    failure_count = failure_count.saturating_add(1);
                    lines.push(format!(
                        "rule: {}:{} failed=execute error={error}",
                        locked_plugin.pack_id, rule.id
                    ));
                }
            }
        }
    }

    lines.push(format!(
        "result: success_rules={success_count} failed_rules={failure_count}"
    ));
    lines.push(format!(
        "totals: affected_items={total_affected_items} freed_bytes={total_freed_bytes}"
    ));
    if failure_count > 0 {
        lines.push("run_status: partial_failure".to_string());
    } else {
        lines.push("run_status: success".to_string());
    }
    let journal = SmartCareRunJournal {
        schema_version: SMART_CARE_RUN_JOURNAL_SCHEMA_VERSION,
        run_id,
        mode: "apply".to_string(),
        review_entries: selected_entry_count,
        success_rules: success_count,
        failed_rules: failure_count,
        total_affected_items,
        total_freed_bytes,
        undo_items,
    };
    match write_run_journal(state_dir, &journal) {
        Ok(()) => lines.push(format!(
            "journal: {}",
            state_dir.join(SMART_CARE_RUN_JOURNAL_FILE).display()
        )),
        Err(error) => lines.push(format!("warning: failed_to_write_journal error={error}")),
    }

    SmartCareExecuteOutput { lines }
}

pub fn undo_from_state_dir(state_dir: &Path) -> SmartCareExecuteOutput {
    let journal = match read_run_journal(state_dir) {
        Ok(journal) => journal,
        Err(SmartCareJournalError::NotFound) => {
            return SmartCareExecuteOutput {
                lines: vec![
                    "undo: skipped".to_string(),
                    "reason: no previous smart care run journal".to_string(),
                ],
            };
        }
        Err(SmartCareJournalError::Io(error)) => {
            return SmartCareExecuteOutput {
                lines: vec![
                    "undo: failed".to_string(),
                    format!("reason: failed to read run journal: {error}"),
                ],
            };
        }
        Err(SmartCareJournalError::Parse(error)) => {
            return SmartCareExecuteOutput {
                lines: vec![
                    "undo: failed".to_string(),
                    format!("reason: failed to parse run journal: {error}"),
                ],
            };
        }
    };

    if journal.mode != "apply" || journal.success_rules == 0 {
        let mut lines = vec![
            "undo: no-op".to_string(),
            format!(
                "reason: last run mode={} success_rules={}",
                journal.mode, journal.success_rules
            ),
            "result: no reversible apply action found".to_string(),
        ];
        if let Err(error) = remove_run_journal(state_dir) {
            lines.push(format!("warning: failed_to_remove_journal error={error}"));
        }
        return SmartCareExecuteOutput { lines };
    }
    if journal.undo_items.is_empty() {
        return SmartCareExecuteOutput {
            lines: vec![
                "undo: no-op".to_string(),
                "reason: no reversible undo items were recorded in last run".to_string(),
                format!(
                    "last_run: id={} success_rules={} failed_rules={}",
                    journal.run_id, journal.success_rules, journal.failed_rules
                ),
            ],
        };
    }

    let mut lines = Vec::new();
    lines.push(format!("undo: run_id={}", journal.run_id));
    lines.push(format!("undo_items: {}", journal.undo_items.len()));

    let mut restored_count = 0u64;
    let mut failed_count = 0u64;

    for item in journal.undo_items.iter().rev() {
        match restore_undo_item(item) {
            Ok(()) => {
                restored_count = restored_count.saturating_add(1);
                lines.push(format!(
                    "restored: {}:{} path={}",
                    item.pack_id, item.rule_id, item.original_path
                ));
            }
            Err(error) => {
                failed_count = failed_count.saturating_add(1);
                lines.push(format!(
                    "restore_failed: {}:{} path={} error={error}",
                    item.pack_id, item.rule_id, item.original_path
                ));
            }
        }
    }

    lines.push(format!(
        "result: restored_items={restored_count} failed_items={failed_count}"
    ));
    if failed_count == 0 {
        lines.push("undo_status: success".to_string());
        if let Err(error) = remove_run_journal(state_dir) {
            lines.push(format!("warning: failed_to_remove_journal error={error}"));
        }
    } else if restored_count > 0 {
        lines.push("undo_status: partial_failure".to_string());
    } else {
        lines.push("undo_status: failed".to_string());
    }
    SmartCareExecuteOutput { lines }
}

pub fn undo_local_dry_run(has_last_run_report: bool) -> SmartCareExecuteOutput {
    let lines = if has_last_run_report {
        vec![
            "undo: local-dry-run rollback".to_string(),
            "result: smart care run uses dry-run mode; no filesystem changes were applied"
                .to_string(),
        ]
    } else {
        vec![
            "undo: skipped".to_string(),
            "reason: no previous smart care dry-run record".to_string(),
        ]
    };
    SmartCareExecuteOutput { lines }
}

fn run_journal_path(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join(SMART_CARE_RUN_JOURNAL_FILE)
}

fn write_run_journal(state_dir: &Path, journal: &SmartCareRunJournal) -> Result<(), String> {
    let path = run_journal_path(state_dir);
    let encoded = toml::to_string_pretty(journal).map_err(|error| error.to_string())?;
    fs::write(path, encoded).map_err(|error| error.to_string())
}

fn read_run_journal(state_dir: &Path) -> Result<SmartCareRunJournal, SmartCareJournalError> {
    let path = run_journal_path(state_dir);
    let content = fs::read_to_string(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            SmartCareJournalError::NotFound
        } else {
            SmartCareJournalError::Io(error)
        }
    })?;
    toml::from_str(&content).map_err(SmartCareJournalError::Parse)
}

fn remove_run_journal(state_dir: &Path) -> Result<(), String> {
    let path = run_journal_path(state_dir);
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn restore_undo_item(item: &SmartCareUndoItem) -> Result<(), String> {
    if item.action_type != "TrashPaths" {
        return Err(format!(
            "unsupported action_type for undo: {}",
            item.action_type
        ));
    }

    #[cfg(target_os = "macos")]
    {
        let trash_path = std::path::PathBuf::from(&item.undo_info);
        let original_path = std::path::PathBuf::from(&item.original_path);
        let home = dirs::home_dir().ok_or_else(|| "missing home dir".to_string())?;
        let expected_trash_dir = home.join(".Trash");
        if !trash_path.starts_with(&expected_trash_dir) {
            return Err(format!(
                "invalid trash path for restore: {}",
                trash_path.display()
            ));
        }
        if !trash_path.exists() {
            return Err(format!("trash item not found: {}", trash_path.display()));
        }
        if original_path.exists() {
            return Err(format!(
                "target path exists and cannot restore: {}",
                original_path.display()
            ));
        }
        fs::rename(&trash_path, &original_path).map_err(|error| {
            format!(
                "restore rename failed {} -> {}: {error}",
                trash_path.display(),
                original_path.display()
            )
        })?;
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let original_path = std::path::PathBuf::from(&item.undo_info);
        let mut candidates = trash::os_limited::list()
            .map_err(|error| format!("trash list failed: {error}"))?
            .into_iter()
            .filter(|candidate| candidate.original_path == original_path)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(format!(
                "trash item not found for {}",
                original_path.display()
            ));
        }
        if candidates.len() > 1 {
            return Err(format!(
                "ambiguous trash candidates for {} (count={})",
                original_path.display(),
                candidates.len()
            ));
        }
        let candidate = candidates.remove(0);
        trash::os_limited::restore_all(vec![candidate])
            .map_err(|error| format!("trash restore failed: {error}"))?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "macos", all(unix, not(target_os = "macos")))))]
    {
        let _ = item;
        Err("undo not supported on this OS".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SMART_CARE_RUN_JOURNAL_FILE, analyze, execute_from_state_dir, execute_local_dry_run,
        undo_from_state_dir, undo_local_dry_run,
    };
    use preen_core::plugin_lock::{LockedPlugin, PluginLockfile};
    use preen_core::smart_care::{
        SmartCareCapability, SmartCareCapabilitySelection, SmartCarePluginDescriptor,
        SmartCareProfile,
    };
    use std::collections::HashSet;
    use std::fs;

    #[test]
    fn analyze_returns_ready_when_trusted_plugin_exists() {
        let profile = SmartCareProfile {
            id: "test".to_string(),
            name: "Test".to_string(),
            capabilities: vec![SmartCareCapabilitySelection::enabled(
                SmartCareCapability::Cleanup,
            )],
        };
        let descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        }];

        let output = analyze(&profile, &descriptors, None);
        assert!(output.lines.iter().any(|line| line == "overall: ready"));
        assert!(output.preview.overall_ready);
    }

    #[test]
    fn execute_blocks_when_review_is_missing() {
        let profile = SmartCareProfile::default_profile();
        let output = analyze(&profile, &[], None);
        let exec = execute_local_dry_run(&output.preview, &HashSet::new(), false);
        assert!(
            exec.lines
                .iter()
                .any(|line| line == "reason: review is required before run")
        );
    }

    #[test]
    fn undo_uses_expected_output() {
        let skipped = undo_local_dry_run(false);
        assert!(skipped.lines.iter().any(|line| line == "undo: skipped"));

        let done = undo_local_dry_run(true);
        assert!(
            done.lines
                .iter()
                .any(|line| line == "undo: local-dry-run rollback")
        );
    }

    fn build_cleanup_pack(base: &std::path::Path, pack_id: &str) {
        let pack_dir = base.join("plugins").join(pack_id);
        fs::create_dir_all(pack_dir.join("rules")).unwrap();
        fs::write(
            pack_dir.join("manifest.toml"),
            format!(
                r#"
schema_version = 1
pack_id = "{pack_id}"
name = "Test Cleanup"
version = "1.0.0"
description = "Test cleanup plugin"
author = "Preen"
license = "MIT"
homepage = ""
core_compat = ">=0.1.0,<2.0.0"
action_api = 1
os_targets = ["Macos", "Linux"]
capabilities = ["FsRead"]

[[rules]]
id = "{pack_id}.disk_snapshot"
name = "Disk Snapshot"
rule_file = "rules/disk-snapshot.toml"
"#
            ),
        )
        .unwrap();
        fs::write(
            pack_dir.join("rules/disk-snapshot.toml"),
            format!(
                r#"
schema_version = 1
id = "{pack_id}.disk_snapshot"
name = "Disk Snapshot"
category = "Cache"
risk = "Low"
enabled = true

[match]
mode = "Paths"
paths = ["/private/tmp/preen-smart-care-runtime"]
strategy = "Shallow"
command = []
parser = ""

[action]
action_type = "DiskUsageSnapshot"
paths = ["/private/tmp/preen-smart-care-runtime"]
command = []
mode = "Auto"
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
    fn execute_from_state_dir_runs_real_core_os_apply_path() {
        let temp = tempfile::tempdir().unwrap();
        let scanned_root = std::path::PathBuf::from("/private/tmp/preen-smart-care-runtime");
        let _ = fs::create_dir_all(&scanned_root);
        build_cleanup_pack(temp.path(), "preen-rs.cleanup.base");
        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![LockedPlugin {
                pack_id: "preen-rs.cleanup.base".to_string(),
                source: "registry".to_string(),
                url: "https://example.com/cleanup".to_string(),
                rev: "0123456789abcdef0123456789abcdef01234567".to_string(),
                resolved_rev: None,
                version: "1.0.0".to_string(),
                manifest_hash: "sha256:a".to_string(),
                signature: "sha256:b".to_string(),
                trusted_identity: "https://example.com/workflow".to_string(),
            }],
        };
        fs::write(
            temp.path().join("plugins.lock"),
            lockfile.to_string().unwrap(),
        )
        .unwrap();

        let profile = SmartCareProfile {
            id: "test".to_string(),
            name: "Test".to_string(),
            capabilities: vec![SmartCareCapabilitySelection::enabled(
                SmartCareCapability::Cleanup,
            )],
        };
        let descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://example.com/workflow".to_string()),
            version: Some("1.0.0".to_string()),
        }];
        let analyzed = analyze(&profile, &descriptors, None);
        let output =
            execute_from_state_dir(temp.path(), &analyzed.preview, &HashSet::new(), true, true);
        assert!(
            output
                .lines
                .iter()
                .any(|line| line.starts_with("run: core-os-apply-"))
        );
        assert!(
            output
                .lines
                .iter()
                .any(|line| line.starts_with("result: success_rules="))
        );
        assert!(temp.path().join(SMART_CARE_RUN_JOURNAL_FILE).exists());
    }

    #[test]
    fn undo_from_state_dir_reports_no_op_when_journal_has_no_undo_items() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join(SMART_CARE_RUN_JOURNAL_FILE);
        fs::write(
            journal_path,
            r#"
schema_version = 1
run_id = 42
mode = "apply"
review_entries = 3
success_rules = 2
failed_rules = 0
total_affected_items = 12
total_freed_bytes = 1200
"#,
        )
        .unwrap();

        let output = undo_from_state_dir(temp.path());
        assert!(output.lines.iter().any(|line| line == "undo: no-op"));
        assert!(
            output
                .lines
                .iter()
                .any(|line| line.contains("no reversible undo items"))
        );
    }

    #[test]
    fn undo_from_state_dir_reports_failed_when_restore_fails() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join(SMART_CARE_RUN_JOURNAL_FILE);
        fs::write(
            &journal_path,
            r#"
schema_version = 1
run_id = 43
mode = "apply"
review_entries = 1
success_rules = 1
failed_rules = 0
total_affected_items = 1
total_freed_bytes = 512

[[undo_items]]
pack_id = "preen-rs.cleanup.base"
rule_id = "preen-rs.cleanup.base.trash"
action_type = "TrashPaths"
original_path = "/tmp/preen-smart-care-missing-original"
undo_info = "/tmp/preen-smart-care-missing-trash"
"#,
        )
        .unwrap();

        let output = undo_from_state_dir(temp.path());
        assert!(
            output
                .lines
                .iter()
                .any(|line| line == "undo_status: failed")
        );
        assert!(
            output
                .lines
                .iter()
                .any(|line| line.starts_with("restore_failed:"))
        );
        assert!(journal_path.exists());
    }

    #[test]
    fn undo_from_state_dir_no_op_removes_non_apply_journal() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join(SMART_CARE_RUN_JOURNAL_FILE);
        fs::write(
            &journal_path,
            r#"
schema_version = 1
run_id = 44
mode = "dry-run"
review_entries = 2
success_rules = 2
failed_rules = 0
total_affected_items = 0
total_freed_bytes = 0
"#,
        )
        .unwrap();

        let output = undo_from_state_dir(temp.path());
        assert!(output.lines.iter().any(|line| line == "undo: no-op"));
        assert!(
            output
                .lines
                .iter()
                .any(|line| line.contains("mode=dry-run"))
        );
        assert!(!journal_path.exists());
    }
}

fn read_lockfile(state_dir: &Path) -> Result<PluginLockfile, String> {
    read_plugin_lockfile_from_state_dir(state_dir)
}
