use async_trait::async_trait;
use preen_core::action_runtime::{
    ActionExecutionError, ActionExecutionResult, ActionExecutorPort, ExecutionMode, ExecutionPlan,
};
use preen_core::plugin::ActionType;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
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

    fn count_scan_matches(
        path: &Path,
        remaining: usize,
    ) -> Result<(u64, bool), ActionExecutionError> {
        if remaining == 0 {
            return Ok((0, true));
        }
        if path.is_file() {
            return Ok((1, false));
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
            if entry.file_type().is_file() {
                count += 1;
                if count >= remaining {
                    truncated = true;
                    break;
                }
            }
        }
        Ok((count as u64, truncated))
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
                | ActionType::RunCommand
                | ActionType::ScanPaths
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
            let max_items = plan
                .request
                .action
                .max_items
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(usize::MAX);
            for raw in &plan.request.action.paths {
                let path = Self::expand_path(raw);
                if !path.exists() {
                    warnings.push(format!("path not found: {}", path.display()));
                    continue;
                }
                let remaining = max_items.saturating_sub(affected_items as usize);
                let (count, truncated) = Self::count_scan_matches(&path, remaining)?;
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
