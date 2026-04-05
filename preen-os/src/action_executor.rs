use async_trait::async_trait;
use preen_core::action_runtime::{
    ActionExecutionError, ActionExecutionResult, ActionExecutorPort, ExecutionMode, ExecutionPlan,
};
use preen_core::plugin::ActionType;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime};
use tokio::process::Command as TokioCommand;
use walkdir::WalkDir;

#[derive(Debug, Default, Clone)]
pub struct OsActionExecutor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionRoute {
    TrashPaths,
    DeletePaths,
    PruneEmptyDirs,
    RemoveOrphansOrAppUninstall,
    DiskUsageSnapshot,
    ProjectCleanup,
    FindInstallers,
    OptimizeSystem,
    RunCommand,
    ScanPaths,
    MatchRegex,
    OlderThanDays,
}

impl OsActionExecutor {
    const MAX_RUN_COMMAND_TIMEOUT_SEC: u64 = 600;

    const SAFE_COMMAND_PATH_PREFIXES: [&'static str; 7] = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/nix/store",
    ];

    const DEFAULT_PROJECT_ARTIFACT_NAMES: [&'static str; 10] = [
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

    const DEFAULT_INSTALLER_EXTENSIONS: [&'static str; 12] = [
        "dmg", "pkg", "zip", "tar", "tgz", "gz", "bz2", "xz", "deb", "rpm", "appimage", "iso",
    ];

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

    fn parse_csv_set(plan: &ExecutionPlan, key: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        if let Some(raw) = plan.request.action.params.get(key) {
            out.extend(
                raw.split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| item.to_ascii_lowercase()),
            );
        }
        out
    }

    fn project_artifact_names(plan: &ExecutionPlan) -> HashSet<String> {
        let mut names = Self::parse_csv_set(plan, "artifact_names");
        if names.is_empty() {
            names.extend(
                Self::DEFAULT_PROJECT_ARTIFACT_NAMES
                    .iter()
                    .map(|item| item.to_string()),
            );
        }
        names
    }

    fn installer_extensions(plan: &ExecutionPlan) -> HashSet<String> {
        let mut exts = Self::parse_csv_set(plan, "extensions");
        if exts.is_empty() {
            exts.extend(
                Self::DEFAULT_INSTALLER_EXTENSIONS
                    .iter()
                    .map(|item| item.to_string()),
            );
        }
        exts
    }

    fn basename_lower(path: &Path) -> Option<String> {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|value| value.to_ascii_lowercase())
    }

    fn extension_lower(path: &Path) -> Option<String> {
        path.extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
    }

    fn count_files_and_size(path: &Path) -> (u64, u64) {
        if path.is_file() {
            return (1, fs::metadata(path).map(|m| m.len()).unwrap_or(0));
        }
        if !path.is_dir() {
            return (0, 0);
        }
        let mut files: u64 = 0;
        let mut size: u64 = 0;
        for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
            if let Ok(meta) = entry.metadata()
                && meta.is_file()
            {
                files += 1;
                size = size.saturating_add(meta.len());
            }
        }
        (files, size)
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

    fn is_safe_command_path(path: &Path) -> bool {
        let Some(normalized) = Self::normalize_absolute_path(path) else {
            return false;
        };

        Self::SAFE_COMMAND_PATH_PREFIXES
            .iter()
            .map(Path::new)
            .any(|prefix| normalized == prefix || normalized.starts_with(prefix))
    }

    fn is_path_like(value: &str) -> bool {
        value.contains('/')
    }

    fn normalize_absolute_path(path: &Path) -> Option<PathBuf> {
        if !path.is_absolute() {
            return None;
        }
        let mut parts = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::CurDir => {}
                Component::Normal(part) => parts.push(part.to_owned()),
                Component::ParentDir => {
                    parts.pop()?;
                }
                Component::Prefix(_) => return None,
            }
        }

        let mut normalized = PathBuf::from("/");
        for part in parts {
            normalized.push(part);
        }
        Some(normalized)
    }

    fn is_executable_file(path: &Path) -> bool {
        let Ok(metadata) = fs::metadata(path) else {
            return false;
        };
        if !metadata.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    fn resolve_safe_program(program: &str) -> Option<PathBuf> {
        Self::SAFE_COMMAND_PATH_PREFIXES
            .iter()
            .map(|prefix| Path::new(prefix).join(program))
            .find(|candidate| Self::is_executable_file(candidate))
    }

    fn format_command_for_log(command: &[String]) -> String {
        command
            .iter()
            .map(|part| {
                part.chars()
                    .flat_map(|c| c.escape_default())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn is_command_allowed(command: &str, allowlist: &[String]) -> bool {
        let command_name = Self::normalize_command_name(command);
        let command_path_like = Self::is_path_like(command);
        let command_path = Path::new(command);

        if command_path_like {
            if allowlist.iter().any(|entry| entry.trim() == command) {
                return true;
            }
            let basename_allowed = allowlist.iter().any(|entry| {
                let normalized = entry.trim();
                !normalized.is_empty() && Self::normalize_command_name(normalized) == command_name
            });
            if basename_allowed {
                return Self::is_safe_command_path(command_path);
            }
            return false;
        }

        allowlist.iter().any(|entry| {
            let normalized = entry.trim();
            !normalized.is_empty()
                && (normalized == command_name
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
                    Self::format_command_for_log(&plan.request.action.command)
                )],
            });
        }

        let timeout_sec = plan.request.action.timeout_sec.unwrap_or(60).max(1);
        if timeout_sec > Self::MAX_RUN_COMMAND_TIMEOUT_SEC {
            return Err(ActionExecutionError::Failed {
                message: format!(
                    "run command timeout exceeds max {} seconds: {timeout_sec}",
                    Self::MAX_RUN_COMMAND_TIMEOUT_SEC
                ),
            });
        }

        let executable = if Self::is_path_like(program) {
            program.clone()
        } else {
            Self::resolve_safe_program(program)
                .ok_or_else(|| ActionExecutionError::CommandDenied {
                    command: program.clone(),
                })?
                .to_string_lossy()
                .to_string()
        };
        let mut command = TokioCommand::new(&executable);
        if plan.request.action.command.len() > 1 {
            command.args(&plan.request.action.command[1..]);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut command_for_log_parts = plan.request.action.command.clone();
        command_for_log_parts[0] = executable.clone();
        let command_for_log = Self::format_command_for_log(&command_for_log_parts);
        let mut child = command.spawn().map_err(|e| ActionExecutionError::Failed {
            message: format!("run command spawn failed: {executable}: {e}"),
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
                        command: command_for_log,
                        timeout_sec,
                    });
                }
            };

        if !status.success() {
            return Err(ActionExecutionError::CommandNonZero {
                command: command_for_log,
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

    fn collect_project_cleanup_targets(
        root: &Path,
        remaining: usize,
        artifact_names: &HashSet<String>,
    ) -> Result<(Vec<PathBuf>, bool), ActionExecutionError> {
        if remaining == 0 {
            return Ok((Vec::new(), true));
        }
        if !root.exists() {
            return Ok((Vec::new(), false));
        }
        if !root.is_dir() {
            return Err(ActionExecutionError::Failed {
                message: format!(
                    "project_cleanup target is not directory: {}",
                    root.display()
                ),
            });
        }

        let mut selected = Vec::new();
        let mut truncated = false;
        let walker = WalkDir::new(root).sort_by_file_name();
        for entry in walker.into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_dir() {
                continue;
            }
            let candidate = entry.path();
            if let Some(name) = Self::basename_lower(candidate)
                && artifact_names.contains(&name)
            {
                selected.push(candidate.to_path_buf());
                if selected.len() >= remaining {
                    truncated = true;
                    break;
                }
            }
        }
        Ok((selected, truncated))
    }

    fn collect_installer_targets(
        root: &Path,
        remaining: usize,
        extensions: &HashSet<String>,
    ) -> Result<(Vec<PathBuf>, bool), ActionExecutionError> {
        if remaining == 0 {
            return Ok((Vec::new(), true));
        }
        if !root.exists() {
            return Ok((Vec::new(), false));
        }
        if root.is_file() {
            let matched = Self::extension_lower(root)
                .map(|ext| extensions.contains(&ext))
                .unwrap_or(false);
            return Ok((
                if matched {
                    vec![root.to_path_buf()]
                } else {
                    Vec::new()
                },
                false,
            ));
        }
        if !root.is_dir() {
            return Err(ActionExecutionError::Failed {
                message: format!(
                    "find_installers target is not directory: {}",
                    root.display()
                ),
            });
        }

        let mut selected = Vec::new();
        let mut truncated = false;
        let walker = WalkDir::new(root).sort_by_file_name();
        for entry in walker.into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let candidate = entry.path();
            if let Some(ext) = Self::extension_lower(candidate)
                && extensions.contains(&ext)
            {
                selected.push(candidate.to_path_buf());
                if selected.len() >= remaining {
                    truncated = true;
                    break;
                }
            }
        }
        Ok((selected, truncated))
    }

    fn execute_delete_like_paths(
        plan: &ExecutionPlan,
        use_trash: bool,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        let mut affected_items: u64 = 0;
        let mut freed_bytes: u64 = 0;
        let mut warnings: Vec<String> = Vec::new();

        for raw in &plan.request.action.paths {
            let path = Self::expand_path(raw);
            if !path.exists() {
                warnings.push(format!("path not found: {}", path.display()));
                continue;
            }

            affected_items = affected_items.saturating_add(1);
            freed_bytes = freed_bytes.saturating_add(Self::calculate_size(&path));

            if plan.request.mode == ExecutionMode::DryRun {
                continue;
            }

            if use_trash {
                Self::trash_path(&path)?;
            } else {
                Self::delete_path(&path)?;
            }
        }

        Ok(ActionExecutionResult {
            affected_items,
            freed_bytes,
            warnings,
        })
    }

    async fn execute_project_cleanup(
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        let max_items = Self::parse_max_items(plan);
        let artifact_names = Self::project_artifact_names(plan);
        let mut selected = Vec::new();
        let mut warnings = Vec::new();

        for raw in &plan.request.action.paths {
            let root = Self::expand_path(raw);
            if !root.exists() {
                warnings.push(format!("path not found: {}", root.display()));
                continue;
            }
            let remaining = max_items.saturating_sub(selected.len());
            let (targets, truncated) =
                Self::collect_project_cleanup_targets(&root, remaining, &artifact_names)?;
            selected.extend(targets);
            if truncated {
                warnings.push(format!(
                    "project cleanup result truncated at max_items={max_items} for {}",
                    root.display()
                ));
                break;
            }
        }

        let freed_bytes: u64 = selected.iter().map(|path| Self::calculate_size(path)).sum();
        if plan.request.mode == ExecutionMode::Apply {
            for path in &selected {
                Self::delete_path(path)?;
            }
        }

        Ok(ActionExecutionResult {
            affected_items: selected.len() as u64,
            freed_bytes,
            warnings,
        })
    }

    async fn execute_find_installers(
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        let max_items = Self::parse_max_items(plan);
        let extensions = Self::installer_extensions(plan);
        let mut selected = Vec::new();
        let mut warnings = Vec::new();

        for raw in &plan.request.action.paths {
            let root = Self::expand_path(raw);
            if !root.exists() {
                warnings.push(format!("path not found: {}", root.display()));
                continue;
            }
            let remaining = max_items.saturating_sub(selected.len());
            let (targets, truncated) =
                Self::collect_installer_targets(&root, remaining, &extensions)?;
            selected.extend(targets);
            if truncated {
                warnings.push(format!(
                    "installer scan result truncated at max_items={max_items} for {}",
                    root.display()
                ));
                break;
            }
        }

        let freed_bytes: u64 = selected.iter().map(|path| Self::calculate_size(path)).sum();
        if plan.request.mode == ExecutionMode::Apply {
            for path in &selected {
                Self::delete_path(path)?;
            }
        }

        Ok(ActionExecutionResult {
            affected_items: selected.len() as u64,
            freed_bytes,
            warnings,
        })
    }

    async fn execute_disk_usage_snapshot(
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        let mut affected_items: u64 = 0;
        let mut freed_bytes: u64 = 0;
        let mut warnings: Vec<String> = Vec::new();
        let max_items = Self::parse_max_items(plan);

        for raw in &plan.request.action.paths {
            let path = Self::expand_path(raw);
            if !path.exists() {
                warnings.push(format!("path not found: {}", path.display()));
                continue;
            }
            let (files, size) = Self::count_files_and_size(&path);
            affected_items = affected_items.saturating_add(files);
            freed_bytes = freed_bytes.saturating_add(size);
            if (affected_items as usize) >= max_items {
                warnings.push(format!(
                    "disk usage snapshot truncated at max_items={max_items} for {}",
                    path.display()
                ));
                affected_items = max_items as u64;
                break;
            }
        }

        Ok(ActionExecutionResult {
            affected_items,
            freed_bytes,
            warnings,
        })
    }

    fn execute_scan_paths(
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
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
        Ok(ActionExecutionResult {
            affected_items,
            freed_bytes: 0,
            warnings,
        })
    }

    fn execute_prune_empty_dirs(
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
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

        Ok(ActionExecutionResult {
            affected_items,
            freed_bytes: 0,
            warnings,
        })
    }

    async fn execute_remove_orphans_or_app_uninstall(
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        let action_type = &plan.request.action.action_type;
        if !plan.request.action.paths.is_empty() {
            return Self::execute_delete_like_paths(plan, false);
        }
        if !plan.request.action.command.is_empty() {
            return Self::execute_run_command(plan).await;
        }
        Err(ActionExecutionError::Failed {
            message: format!(
                "{} requires paths or command",
                match action_type {
                    ActionType::RemoveOrphans => "remove_orphans",
                    ActionType::AppUninstall => "app_uninstall",
                    _ => "action",
                }
            ),
        })
    }

    fn route_action(action_type: &ActionType) -> Result<ActionRoute, ActionExecutionError> {
        match action_type {
            ActionType::TrashPaths => Ok(ActionRoute::TrashPaths),
            ActionType::DeletePaths => Ok(ActionRoute::DeletePaths),
            ActionType::PruneEmptyDirs => Ok(ActionRoute::PruneEmptyDirs),
            ActionType::RemoveOrphans | ActionType::AppUninstall => {
                Ok(ActionRoute::RemoveOrphansOrAppUninstall)
            }
            ActionType::DiskUsageSnapshot | ActionType::SystemStatus => {
                Ok(ActionRoute::DiskUsageSnapshot)
            }
            ActionType::ProjectCleanup => Ok(ActionRoute::ProjectCleanup),
            ActionType::FindInstallers => Ok(ActionRoute::FindInstallers),
            ActionType::OptimizeSystem => Ok(ActionRoute::OptimizeSystem),
            ActionType::RunCommand => Ok(ActionRoute::RunCommand),
            ActionType::ScanPaths => Ok(ActionRoute::ScanPaths),
            ActionType::MatchRegex => Ok(ActionRoute::MatchRegex),
            ActionType::OlderThanDays => Ok(ActionRoute::OlderThanDays),
            ActionType::Other(_) => Err(ActionExecutionError::UnsupportedAction {
                action: format!("{action_type:?}"),
            }),
        }
    }
}

#[async_trait]
impl ActionExecutorPort for OsActionExecutor {
    async fn execute(
        &self,
        plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        let route = Self::route_action(&plan.request.action.action_type)?;
        match route {
            ActionRoute::TrashPaths => Self::execute_delete_like_paths(plan, true),
            ActionRoute::DeletePaths => Self::execute_delete_like_paths(plan, false),
            ActionRoute::PruneEmptyDirs => Self::execute_prune_empty_dirs(plan),
            ActionRoute::RemoveOrphansOrAppUninstall => {
                Self::execute_remove_orphans_or_app_uninstall(plan).await
            }
            ActionRoute::DiskUsageSnapshot => Self::execute_disk_usage_snapshot(plan).await,
            ActionRoute::ProjectCleanup => Self::execute_project_cleanup(plan).await,
            ActionRoute::FindInstallers => Self::execute_find_installers(plan).await,
            ActionRoute::OptimizeSystem => {
                if plan.request.action.command.is_empty() {
                    return Err(ActionExecutionError::Failed {
                        message: "optimize_system requires command".to_string(),
                    });
                }
                Self::execute_run_command(plan).await
            }
            ActionRoute::RunCommand => Self::execute_run_command(plan).await,
            ActionRoute::ScanPaths => Self::execute_scan_paths(plan),
            ActionRoute::MatchRegex => Self::execute_match_regex(plan),
            ActionRoute::OlderThanDays => Self::execute_older_than_days(plan),
        }
    }
}
