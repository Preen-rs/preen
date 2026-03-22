use async_trait::async_trait;
use preen_core::action_runtime::{
    ActionExecutionError, ActionExecutionResult, ActionExecutorPort, ExecutionMode, ExecutionPlan,
};
use preen_core::plugin::ActionType;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime};
use tokio::process::Command as TokioCommand;
use walkdir::WalkDir;

#[derive(Debug, Default, Clone)]
pub struct OsActionExecutor;

impl OsActionExecutor {
    fn expand_path(path: &str) -> PathBuf {
        PathBuf::from(shellexpand::tilde(path).to_string())
    }

    fn calculate_size(path: &Path) -> u64 {
        if path.is_file() {
            return fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        }
        WalkDir::new(path)
            .into_iter()
            .filter_map(Result::ok)
            .filter_map(|entry| entry.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum()
    }

    fn delete_path(path: &Path) -> Result<(), ActionExecutionError> {
        if path.is_dir() {
            fs::remove_dir_all(path).map_err(|e| ActionExecutionError::Failed {
                message: format!("delete dir failed: {}: {e}", path.display()),
            })?;
        } else {
            fs::remove_file(path).map_err(|e| ActionExecutionError::Failed {
                message: format!("delete file failed: {}: {e}", path.display()),
            })?;
        }
        Ok(())
    }

    fn trash_path(path: &Path) -> Result<(), ActionExecutionError> {
        trash::delete(path).map_err(|e| ActionExecutionError::Failed {
            message: format!("trash failed: {}: {e}", path.display()),
        })
    }

    fn count_matching_files<F>(
        path: &Path,
        remaining: usize,
        mut matcher: F,
    ) -> Result<(u64, bool), ActionExecutionError>
    where
        F: FnMut(&Path) -> Result<bool, ActionExecutionError>,
    {
        if remaining == 0 {
            return Ok((0, true));
        }
        if path.is_file() {
            return Ok((u64::from(matcher(path)?), false));
        }
        if !path.is_dir() {
            return Ok((0, false));
        }

        let mut count: usize = 0;
        let mut truncated = false;
        for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
            if entry.path() == path {
                continue;
            }
            if entry.file_type().is_file() && matcher(entry.path())? {
                count += 1;
                if count >= remaining {
                    truncated = true;
                    break;
                }
            }
        }
        Ok((count as u64, truncated))
    }

    fn parse_max_items(plan: &ExecutionPlan) -> usize {
        plan.request
            .action
            .max_items
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(usize::MAX)
    }

    fn parse_required_param<'a>(
        plan: &'a ExecutionPlan,
        keys: &[&str],
        missing_message: &'static str,
    ) -> Result<&'a str, ActionExecutionError> {
        for key in keys {
            if let Some(value) = plan.request.action.params.get(*key) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Ok(trimmed);
                }
            }
        }
        Err(ActionExecutionError::Failed {
            message: missing_message.to_string(),
        })
    }

    fn parse_regex(plan: &ExecutionPlan) -> Result<Regex, ActionExecutionError> {
        let pattern = Self::parse_required_param(
            plan,
            &["pattern", "regex"],
            "match_regex requires params.pattern",
        )?;
        Regex::new(pattern).map_err(|e| ActionExecutionError::Failed {
            message: format!("match_regex invalid pattern: {e}"),
        })
    }

    fn parse_days(plan: &ExecutionPlan) -> Result<u64, ActionExecutionError> {
        let raw = Self::parse_required_param(
            plan,
            &["days", "older_than_days", "age_days"],
            "older_than_days requires params.days",
        )?;
        raw.parse::<u64>()
            .map_err(|_| ActionExecutionError::Failed {
                message: format!("older_than_days invalid days value: {raw}"),
            })
    }

    fn collect_empty_dirs(
        root: &Path,
        limit: usize,
    ) -> Result<(Vec<PathBuf>, bool), ActionExecutionError> {
        fn visit(
            dir: &Path,
            selected: &mut Vec<PathBuf>,
            limit: usize,
            truncated: &mut bool,
        ) -> Result<bool, ActionExecutionError> {
            let entries = fs::read_dir(dir).map_err(|e| ActionExecutionError::Failed {
                message: format!("prune_empty_dirs read_dir failed: {}: {e}", dir.display()),
            })?;
            let mut children: Vec<PathBuf> = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|e| ActionExecutionError::Failed {
                    message: format!(
                        "prune_empty_dirs read_dir entry failed: {}: {e}",
                        dir.display()
                    ),
                })?;
                children.push(entry.path());
            }
            children.sort();

            let mut empty_after_prune = true;
            for child in children {
                let meta =
                    fs::symlink_metadata(&child).map_err(|e| ActionExecutionError::Failed {
                        message: format!(
                            "prune_empty_dirs metadata failed: {}: {e}",
                            child.display()
                        ),
                    })?;
                if meta.file_type().is_dir() {
                    let child_empty = visit(&child, selected, limit, truncated)?;
                    if !child_empty {
                        empty_after_prune = false;
                    }
                } else {
                    empty_after_prune = false;
                }
            }

            if empty_after_prune {
                if selected.len() < limit {
                    selected.push(dir.to_path_buf());
                    return Ok(true);
                }
                *truncated = true;
            }
            Ok(false)
        }

        let mut selected: Vec<PathBuf> = Vec::new();
        let mut truncated = false;
        visit(root, &mut selected, limit, &mut truncated)?;
        Ok((selected, truncated))
    }

    fn parse_command_allowlist(plan: &ExecutionPlan) -> Vec<String> {
        let mut values = Vec::new();
        let mut has_param_allowlist = false;
        for key in ["command_allowlist", "allowlist"] {
            if let Some(raw) = plan.request.action.params.get(key) {
                has_param_allowlist = true;
                values.extend(
                    raw.split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(ToOwned::to_owned),
                );
            }
        }

        if has_param_allowlist {
            return values;
        }

        if let Ok(raw) = std::env::var("PREEN_RUN_COMMAND_ALLOWLIST") {
            values.extend(
                raw.split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(ToOwned::to_owned),
            );
        }
        values
    }

    fn normalize_command_name(value: &str) -> String {
        Path::new(value)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(value)
            .to_string()
    }

    fn is_command_allowed(command: &str, allowlist: &[String]) -> bool {
        let command_name = Self::normalize_command_name(command);
        allowlist.iter().any(|entry| {
            let normalized = entry.trim();
            !normalized.is_empty()
                && (normalized == command
                    || normalized == command_name
                    || Self::normalize_command_name(normalized) == command_name)
        })
    }

    async fn execute_run_command(
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        if plan.request.action.command.is_empty() {
            return Err(ActionExecutionError::Failed {
                message: "run command is empty".to_string(),
            });
        }
        let allowlist = Self::parse_command_allowlist(plan);
        if allowlist.is_empty() {
            return Err(ActionExecutionError::Failed {
                message: "run command allowlist is empty".to_string(),
            });
        }
        let program = &plan.request.action.command[0];
        if !Self::is_command_allowed(program, &allowlist) {
            return Err(ActionExecutionError::CommandDenied {
                command: program.clone(),
            });
        }

        if plan.request.mode == ExecutionMode::DryRun {
            return Ok(ActionExecutionResult {
                affected_items: 1,
                freed_bytes: 0,
                warnings: vec![format!(
                    "dry-run skipped command: {}",
                    plan.request.action.command.join(" ")
                )],
            });
        }

        let timeout_sec = plan.request.action.timeout_sec.unwrap_or(60).max(1);
        let mut command = TokioCommand::new(program);
        if plan.request.action.command.len() > 1 {
            command.args(&plan.request.action.command[1..]);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|e| ActionExecutionError::Failed {
            message: format!("run command spawn failed: {program}: {e}"),
        })?;

        let status =
            match tokio::time::timeout(Duration::from_secs(timeout_sec), child.wait()).await {
                Ok(wait_result) => wait_result.map_err(|e| ActionExecutionError::Failed {
                    message: format!("run command wait failed: {program}: {e}"),
                })?,
                Err(_) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Err(ActionExecutionError::CommandTimeout {
                        command: plan.request.action.command.join(" "),
                        timeout_sec,
                    });
                }
            };

        if !status.success() {
            return Err(ActionExecutionError::CommandNonZero {
                command: plan.request.action.command.join(" "),
                code: status.code(),
            });
        }

        Ok(ActionExecutionResult {
            affected_items: 1,
            freed_bytes: 0,
            warnings: Vec::new(),
        })
    }

    fn execute_match_regex(
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        let regex = Self::parse_regex(plan)?;
        let max_items = Self::parse_max_items(plan);
        let mut affected_items: u64 = 0;
        let mut warnings: Vec<String> = Vec::new();

        for raw in &plan.request.action.paths {
            let path = Self::expand_path(raw);
            if !path.exists() {
                warnings.push(format!("path not found: {}", path.display()));
                continue;
            }
            let remaining = max_items.saturating_sub(affected_items as usize);
            let (count, truncated) = Self::count_matching_files(&path, remaining, |candidate| {
                Ok(regex.is_match(&candidate.to_string_lossy()))
            })?;
            affected_items = affected_items.saturating_add(count);
            if truncated {
                warnings.push(format!(
                    "scan result truncated at max_items={max_items} for {}",
                    path.display()
                ));
                break;
            }
        }

        Ok(ActionExecutionResult {
            affected_items,
            freed_bytes: 0,
            warnings,
        })
    }

    fn execute_older_than_days(
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        let days = Self::parse_days(plan)?;
        let max_items = Self::parse_max_items(plan);
        let mut affected_items: u64 = 0;
        let mut warnings: Vec<String> = Vec::new();
        let seconds = days.saturating_mul(24_u64 * 60 * 60);
        let threshold = Duration::from_secs(seconds);

        for raw in &plan.request.action.paths {
            let path = Self::expand_path(raw);
            if !path.exists() {
                warnings.push(format!("path not found: {}", path.display()));
                continue;
            }
            let remaining = max_items.saturating_sub(affected_items as usize);
            let (count, truncated) = Self::count_matching_files(&path, remaining, |candidate| {
                let modified = fs::metadata(candidate)
                    .and_then(|metadata| metadata.modified())
                    .map_err(|e| ActionExecutionError::Failed {
                        message: format!("older_than_days metadata failed: {candidate:?}: {e}"),
                    })?;
                let age = SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_else(|_| Duration::from_secs(0));
                Ok(age > threshold)
            })?;
            affected_items = affected_items.saturating_add(count);
            if truncated {
                warnings.push(format!(
                    "scan result truncated at max_items={max_items} for {}",
                    path.display()
                ));
                break;
            }
        }

        Ok(ActionExecutionResult {
            affected_items,
            freed_bytes: 0,
            warnings,
        })
    }
}

#[async_trait]
impl ActionExecutorPort for OsActionExecutor {
    async fn execute(
        &self,
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        let action_type = &plan.request.action.action_type;
        if !matches!(
            action_type,
            ActionType::TrashPaths
                | ActionType::DeletePaths
                | ActionType::PruneEmptyDirs
                | ActionType::RunCommand
                | ActionType::ScanPaths
                | ActionType::MatchRegex
                | ActionType::OlderThanDays
        ) {
            return Err(ActionExecutionError::UnsupportedAction {
                action: format!("{action_type:?}"),
            });
        }

        if matches!(action_type, ActionType::RunCommand) {
            return Self::execute_run_command(plan).await;
        }

        if matches!(action_type, ActionType::ScanPaths) {
            let mut affected_items: u64 = 0;
            let mut warnings: Vec<String> = Vec::new();
            let max_items = Self::parse_max_items(plan);
            for raw in &plan.request.action.paths {
                let path = Self::expand_path(raw);
                if !path.exists() {
                    warnings.push(format!("path not found: {}", path.display()));
                    continue;
                }
                let remaining = max_items.saturating_sub(affected_items as usize);
                let (count, truncated) = Self::count_matching_files(&path, remaining, |_| {
                    Ok::<bool, ActionExecutionError>(true)
                })?;
                affected_items = affected_items.saturating_add(count);
                if truncated {
                    warnings.push(format!(
                        "scan result truncated at max_items={max_items} for {}",
                        path.display()
                    ));
                    break;
                }
            }
            return Ok(ActionExecutionResult {
                affected_items,
                freed_bytes: 0,
                warnings,
            });
        }

        if matches!(action_type, ActionType::MatchRegex) {
            return Self::execute_match_regex(plan);
        }

        if matches!(action_type, ActionType::OlderThanDays) {
            return Self::execute_older_than_days(plan);
        }

        if matches!(action_type, ActionType::PruneEmptyDirs) {
            let mut affected_items: u64 = 0;
            let mut warnings: Vec<String> = Vec::new();
            let max_items = Self::parse_max_items(plan);

            for raw in &plan.request.action.paths {
                let path = Self::expand_path(raw);
                if !path.exists() {
                    warnings.push(format!("path not found: {}", path.display()));
                    continue;
                }
                if !path.is_dir() {
                    warnings.push(format!("path is not directory: {}", path.display()));
                    continue;
                }
                let remaining = max_items.saturating_sub(affected_items as usize);
                let (dirs, truncated) = Self::collect_empty_dirs(&path, remaining)?;
                affected_items = affected_items.saturating_add(dirs.len() as u64);
                if plan.request.mode == ExecutionMode::Apply {
                    for dir in dirs {
                        fs::remove_dir(&dir).map_err(|e| ActionExecutionError::Failed {
                            message: format!(
                                "prune_empty_dirs remove_dir failed: {}: {e}",
                                dir.display()
                            ),
                        })?;
                    }
                }
                if truncated {
                    warnings.push(format!(
                        "scan result truncated at max_items={max_items} for {}",
                        path.display()
                    ));
                    break;
                }
            }

            return Ok(ActionExecutionResult {
                affected_items,
                freed_bytes: 0,
                warnings,
            });
        }

        let mut affected_items: u64 = 0;
        let mut freed_bytes: u64 = 0;
        let mut warnings: Vec<String> = Vec::new();

        for raw in &plan.request.action.paths {
            let path = Self::expand_path(raw);
            if !path.exists() {
                warnings.push(format!("path not found: {}", path.display()));
                continue;
            }

            affected_items += 1;
            freed_bytes += Self::calculate_size(&path);

            if plan.request.mode == ExecutionMode::DryRun {
                continue;
            }

            match action_type {
                ActionType::TrashPaths => Self::trash_path(&path)?,
                ActionType::DeletePaths => Self::delete_path(&path)?,
                _ => {}
            }
        }

        Ok(ActionExecutionResult {
            affected_items,
            freed_bytes,
            warnings,
        })
    }
}
