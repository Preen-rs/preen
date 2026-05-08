use crate::{app_inventory, trash_ops};
use preen_core::app_uninstall::{
    AppIdentity, AppPlatform, InstalledApplication, RelatedPath, RelatedPathKind, UninstallPlan,
    path_name_matches_app,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const APP_UNINSTALL_JOURNAL_SCHEMA_VERSION: u32 = 1;
const APP_UNINSTALL_JOURNAL_FILE: &str = "app-uninstall-last.toml";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUninstallJournal {
    pub schema_version: u32,
    pub records: Vec<AppUninstallJournalRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUninstallJournalRecord {
    pub plan: UninstallPlan,
    pub moves: Vec<AppUninstallJournalMove>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUninstallJournalMove {
    pub original_path: PathBuf,
    pub trashed_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppUninstallExecutionOutput {
    pub lines: Vec<String>,
    pub removed_apps: Vec<String>,
    pub records: Vec<AppUninstallJournalRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppUninstallUndoOutput {
    pub lines: Vec<String>,
    pub restored_apps: Vec<String>,
    pub retry_records: Vec<AppUninstallJournalRecord>,
}

impl AppUninstallJournal {
    pub fn new(records: Vec<AppUninstallJournalRecord>) -> Self {
        Self {
            schema_version: APP_UNINSTALL_JOURNAL_SCHEMA_VERSION,
            records,
        }
    }
}

pub fn app_uninstall_journal_path(state_dir: &Path) -> PathBuf {
    state_dir.join(APP_UNINSTALL_JOURNAL_FILE)
}

pub fn write_last_app_uninstall_journal(
    state_dir: &Path,
    journal: &AppUninstallJournal,
) -> Result<PathBuf, String> {
    fs::create_dir_all(state_dir).map_err(|error| {
        format!(
            "failed to create state dir {}: {error}",
            state_dir.display()
        )
    })?;
    let path = app_uninstall_journal_path(state_dir);
    let content = toml::to_string_pretty(journal)
        .map_err(|error| format!("failed to encode app uninstall journal: {error}"))?;
    fs::write(&path, content)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    Ok(path)
}

pub fn read_last_app_uninstall_journal(
    state_dir: &Path,
) -> Result<Option<AppUninstallJournal>, String> {
    let path = app_uninstall_journal_path(state_dir);
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let journal: AppUninstallJournal = toml::from_str(&content)
        .map_err(|error| format!("failed to decode {}: {error}", path.display()))?;
    if journal.schema_version != APP_UNINSTALL_JOURNAL_SCHEMA_VERSION {
        return Err(format!(
            "unsupported app uninstall journal schema version: {}",
            journal.schema_version
        ));
    }
    Ok(Some(journal))
}

pub fn clear_last_app_uninstall_journal(state_dir: &Path) -> Result<(), String> {
    let path = app_uninstall_journal_path(state_dir);
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(&path).map_err(|error| format!("failed to remove {}: {error}", path.display()))
}

pub fn build_uninstall_plan_for_name(app_name: &str) -> UninstallPlan {
    if let Some(app) = app_inventory::collect_installed_applications()
        .into_iter()
        .find(|app| app.identity.display_name == app_name)
    {
        return build_uninstall_plan_for_application(app);
    }

    let platform = if cfg!(target_os = "linux") {
        AppPlatform::Linux
    } else {
        AppPlatform::Macos
    };
    let identity = AppIdentity {
        display_name: app_name.to_string(),
        platform,
        bundle_identifier: None,
        desktop_id: None,
    };
    let paths = discover_related_path_items(&identity, &home_dir());
    UninstallPlan::trash(identity, paths)
}

pub fn build_uninstall_plan_for_application(app: InstalledApplication) -> UninstallPlan {
    let mut paths = Vec::new();
    let app_path = PathBuf::from(&app.path);
    if app_path.exists() {
        paths.push(RelatedPath {
            path: app.path.clone(),
            kind: match app.identity.platform {
                AppPlatform::Macos => RelatedPathKind::ApplicationBundle,
                AppPlatform::Linux => RelatedPathKind::DesktopEntry,
            },
            estimated_size: calculate_path_size(&app_path),
        });
    }
    paths.extend(discover_related_path_items(&app.identity, &home_dir()));
    UninstallPlan::trash_with_protection(app.identity, dedup_related_paths(paths), app.protected)
}

pub fn execute_app_uninstall(
    applications: Vec<InstalledApplication>,
    state_dir: Option<&Path>,
) -> Result<AppUninstallExecutionOutput, String> {
    if applications.is_empty() {
        return Err("no application selected for uninstall".to_string());
    }

    let mut lines = Vec::new();
    let mut removed_apps = Vec::new();
    let mut records = Vec::new();

    for application in applications {
        let app_name = application.identity.display_name.clone();
        let plan = build_uninstall_plan_for_application(application);
        if plan.protected {
            lines.push(format!("{app_name}: protected system application skipped"));
            continue;
        }
        if plan.paths.is_empty() {
            lines.push(format!("{app_name}: no related path found"));
            continue;
        }

        let mut moves = Vec::new();
        for related_path in &plan.paths {
            let path = PathBuf::from(&related_path.path);
            if !path.exists() {
                continue;
            }
            match trash_ops::move_path_to_home_trash(&path) {
                Ok(moved) => {
                    lines.push(format!(
                        "moved: {} -> {}",
                        path.display(),
                        moved.trashed_path.display()
                    ));
                    moves.push(AppUninstallJournalMove {
                        original_path: moved.original_path,
                        trashed_path: moved.trashed_path,
                    });
                }
                Err(error) => lines.push(format!("failed: {} ({error})", path.display())),
            }
        }

        if !moves.is_empty() {
            removed_apps.push(app_name);
            records.push(AppUninstallJournalRecord { plan, moves });
        }
    }

    if !records.is_empty()
        && let Some(state_dir) = state_dir
    {
        let journal = AppUninstallJournal::new(records.clone());
        match write_last_app_uninstall_journal(state_dir, &journal) {
            Ok(path) => lines.push(format!("journal: {}", path.display())),
            Err(error) => lines.push(format!("journal failed: {error}")),
        }
    }

    if lines.is_empty() {
        return Err("no file was moved; permissions may be missing".to_string());
    }

    Ok(AppUninstallExecutionOutput {
        lines,
        removed_apps,
        records,
    })
}

pub fn undo_last_app_uninstall(state_dir: &Path) -> Result<AppUninstallUndoOutput, String> {
    let Some(journal) = read_last_app_uninstall_journal(state_dir)? else {
        return Err("no uninstall is available to undo".to_string());
    };
    undo_app_uninstall_records(journal.records, Some(state_dir))
}

pub fn undo_app_uninstall_records(
    records: Vec<AppUninstallJournalRecord>,
    state_dir: Option<&Path>,
) -> Result<AppUninstallUndoOutput, String> {
    if records.is_empty() {
        return Err("no uninstall is available to undo".to_string());
    }

    let mut lines = Vec::new();
    let mut restored_apps = Vec::new();
    let mut retry_records = Vec::new();
    let mut restore_failed = false;

    for record in records.into_iter().rev() {
        let mut restored_any = false;
        let mut failed_moves = Vec::new();
        let plan = record.plan;

        for item in record.moves.into_iter().rev() {
            match trash_ops::restore_trashed_path(&item.original_path, &item.trashed_path) {
                Ok(()) => {
                    restored_any = true;
                    lines.push(format!(
                        "restored: {} -> {}",
                        item.trashed_path.display(),
                        item.original_path.display()
                    ));
                }
                Err(error) => {
                    restore_failed = true;
                    lines.push(format!("failed: {} ({error})", item.trashed_path.display()));
                    failed_moves.push(item);
                }
            }
        }

        if restored_any {
            restored_apps.push(plan.identity.display_name.clone());
        }
        if !failed_moves.is_empty() {
            failed_moves.reverse();
            retry_records.push(AppUninstallJournalRecord {
                plan,
                moves: failed_moves,
            });
        }
    }
    retry_records.reverse();

    if lines.is_empty() {
        return Err("undo could not restore any file".to_string());
    }

    if restore_failed {
        if let Some(state_dir) = state_dir
            && !retry_records.is_empty()
        {
            let journal = AppUninstallJournal::new(retry_records.clone());
            match write_last_app_uninstall_journal(state_dir, &journal) {
                Ok(path) => lines.push(format!("journal kept: {}", path.display())),
                Err(error) => lines.push(format!("journal keep failed: {error}")),
            }
        }
    } else if !restored_apps.is_empty()
        && let Some(state_dir) = state_dir
    {
        match clear_last_app_uninstall_journal(state_dir) {
            Ok(()) => lines.push("journal cleared".to_string()),
            Err(error) => lines.push(format!("journal clear failed: {error}")),
        }
    }

    Ok(AppUninstallUndoOutput {
        lines,
        restored_apps,
        retry_records,
    })
}

fn discover_related_path_items(identity: &AppIdentity, home: &Path) -> Vec<RelatedPath> {
    let app_name = identity.display_name.trim();
    if app_name.is_empty() {
        return Vec::new();
    }

    let mut paths = BTreeSet::new();
    let match_keys = identity.primary_match_keys();

    if matches!(identity.platform, AppPlatform::Macos) {
        let app_bundle = format!("{app_name}.app");
        for root in [
            PathBuf::from("/Applications"),
            PathBuf::from("/System/Applications"),
            home.join("Applications"),
        ] {
            let path = root.join(&app_bundle);
            if path.exists() {
                paths.insert((
                    path.display().to_string(),
                    RelatedPathKind::ApplicationBundle,
                    calculate_path_size(&path),
                ));
            }
        }
    }

    for (root, kind) in application_related_roots(identity.platform.clone(), home) {
        collect_matching_paths_under(&root, &match_keys, 2, kind, &mut paths);
    }

    paths
        .into_iter()
        .map(|(path, kind, estimated_size)| RelatedPath {
            path,
            kind,
            estimated_size,
        })
        .collect()
}

fn application_related_roots(
    platform: AppPlatform,
    home: &Path,
) -> Vec<(PathBuf, RelatedPathKind)> {
    match platform {
        AppPlatform::Linux => vec![
            (home.join(".config"), RelatedPathKind::Preference),
            (home.join(".cache"), RelatedPathKind::Cache),
            (home.join(".local/share"), RelatedPathKind::Support),
            (home.join(".local/state"), RelatedPathKind::Support),
        ],
        AppPlatform::Macos => vec![
            (
                home.join("Library/Application Support"),
                RelatedPathKind::Support,
            ),
            (home.join("Library/Caches"), RelatedPathKind::Cache),
            (home.join("Library/Logs"), RelatedPathKind::Log),
            (home.join("Library/HTTPStorages"), RelatedPathKind::Cache),
            (home.join("Library/WebKit"), RelatedPathKind::Cache),
            (
                home.join("Library/Preferences"),
                RelatedPathKind::Preference,
            ),
            (home.join("Library/Containers"), RelatedPathKind::Container),
            (
                home.join("Library/Group Containers"),
                RelatedPathKind::Container,
            ),
            (
                home.join("Library/Saved Application State"),
                RelatedPathKind::Support,
            ),
        ],
    }
}

fn collect_matching_paths_under(
    root: &Path,
    match_keys: &[String],
    max_depth: usize,
    kind: RelatedPathKind,
    out: &mut BTreeSet<(String, RelatedPathKind, u64)>,
) {
    collect_matching_paths_recursive(root, match_keys, 0, max_depth, kind, out);
}

fn collect_matching_paths_recursive(
    root: &Path,
    match_keys: &[String],
    depth: usize,
    max_depth: usize,
    kind: RelatedPathKind,
    out: &mut BTreeSet<(String, RelatedPathKind, u64)>,
) {
    if depth > max_depth || !root.exists() {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| value.to_string());
        if let Some(name) = name
            && path_name_matches_app(&name, match_keys)
        {
            out.insert((
                path.display().to_string(),
                kind.clone(),
                calculate_path_size(&path),
            ));
        }
        let is_real_dir = fs::symlink_metadata(&path)
            .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            .unwrap_or(false);
        if is_real_dir {
            collect_matching_paths_recursive(
                &path,
                match_keys,
                depth + 1,
                max_depth,
                kind.clone(),
                out,
            );
        }
    }
}

fn dedup_related_paths(paths: Vec<RelatedPath>) -> Vec<RelatedPath> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for path in paths {
        if seen.insert(path.path.clone()) {
            out.push(path);
        }
    }
    out
}

fn calculate_path_size(path: &Path) -> u64 {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return 0;
    };
    if metadata.is_file() {
        return metadata.len();
    }
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return 0;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| calculate_path_size(&entry.path()))
        .fold(0_u64, u64::saturating_add)
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use preen_core::app_uninstall::{AppSource, AppUpdateStatus};
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => unsafe {
                    std::env::set_var(self.key, value);
                },
                None => unsafe {
                    std::env::remove_var(self.key);
                },
            }
        }
    }

    #[test]
    fn planner_keeps_protected_flag_and_application_path() {
        let dir = tempfile::tempdir().unwrap();
        let app_path = dir.path().join("Demo.app");
        fs::create_dir_all(&app_path).unwrap();
        fs::write(app_path.join("Info.plist"), "demo").unwrap();

        let plan = build_uninstall_plan_for_application(InstalledApplication {
            identity: AppIdentity::macos("Demo"),
            path: app_path.to_string_lossy().to_string(),
            version: None,
            source: AppSource::System,
            estimated_size: 0,
            last_used_at: None,
            update_status: AppUpdateStatus::ManagedBySystem,
            protected: true,
        });

        assert!(plan.protected);
        assert!(
            plan.paths
                .iter()
                .any(|path| path.kind == RelatedPathKind::ApplicationBundle)
        );
    }

    #[test]
    fn linux_related_paths_use_xdg_roots() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join(".cache").join("demo");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("state"), "x").unwrap();

        let identity = AppIdentity::linux("Demo");
        let paths = discover_related_path_items(&identity, dir.path());

        assert!(
            paths
                .iter()
                .any(|path| path.path == cache.display().to_string()
                    && path.kind == RelatedPathKind::Cache)
        );
    }

    #[cfg(unix)]
    #[test]
    fn related_path_discovery_does_not_follow_symlinked_directories() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        let outside_demo = outside.join("demo");
        fs::create_dir_all(&outside_demo).unwrap();
        fs::write(outside_demo.join("state"), "x").unwrap();
        let config = dir.path().join(".config");
        fs::create_dir_all(&config).unwrap();
        std::os::unix::fs::symlink(&outside, config.join("linked-config")).unwrap();

        let identity = AppIdentity::linux("Demo");
        let paths = discover_related_path_items(&identity, dir.path());

        assert!(
            !paths
                .iter()
                .any(|path| path.path == outside_demo.display().to_string())
        );
    }

    #[test]
    fn execute_app_uninstall_moves_paths_and_writes_journal() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = EnvVarGuard::set("HOME", dir.path().to_string_lossy().as_ref());
        let state_dir = dir.path().join("state");
        let app_path = dir.path().join("Demo.app");
        fs::create_dir_all(&app_path).unwrap();
        fs::write(app_path.join("Info.plist"), "demo").unwrap();

        let output = execute_app_uninstall(
            vec![InstalledApplication {
                identity: AppIdentity::macos("Demo"),
                path: app_path.to_string_lossy().to_string(),
                version: None,
                source: AppSource::User,
                estimated_size: 0,
                last_used_at: None,
                update_status: AppUpdateStatus::NotManaged,
                protected: false,
            }],
            Some(&state_dir),
        )
        .unwrap();

        assert!(!app_path.exists());
        assert_eq!(output.removed_apps, vec!["Demo".to_string()]);
        assert_eq!(output.records.len(), 1);
        assert!(output.lines.iter().any(|line| line.starts_with("journal:")));
        assert!(
            read_last_app_uninstall_journal(&state_dir)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn undo_last_app_uninstall_restores_and_clears_journal() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let original_path = dir.path().join("Applications").join("Demo.app");
        let trashed_path = dir.path().join(".Trash").join("Demo.app");
        fs::create_dir_all(trashed_path.parent().unwrap()).unwrap();
        fs::write(&trashed_path, "demo").unwrap();

        let journal = AppUninstallJournal::new(vec![AppUninstallJournalRecord {
            plan: UninstallPlan::trash(
                AppIdentity::macos("Demo"),
                vec![RelatedPath {
                    path: original_path.display().to_string(),
                    kind: RelatedPathKind::ApplicationBundle,
                    estimated_size: 4,
                }],
            ),
            moves: vec![AppUninstallJournalMove {
                original_path: original_path.clone(),
                trashed_path: trashed_path.clone(),
            }],
        }]);
        write_last_app_uninstall_journal(&state_dir, &journal).unwrap();

        let output = undo_last_app_uninstall(&state_dir).unwrap();

        assert!(original_path.exists());
        assert!(!trashed_path.exists());
        assert_eq!(output.restored_apps, vec!["Demo".to_string()]);
        assert!(output.lines.iter().any(|line| line == "journal cleared"));
        assert!(
            read_last_app_uninstall_journal(&state_dir)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn undo_app_uninstall_records_keeps_failed_moves_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let restored_original = dir.path().join("Applications").join("Restored.app");
        let restored_trashed = dir.path().join(".Trash").join("Restored.app");
        let blocked_original = dir.path().join("Applications").join("Blocked.app");
        let blocked_trashed = dir.path().join(".Trash").join("Blocked.app");
        fs::create_dir_all(restored_trashed.parent().unwrap()).unwrap();
        fs::create_dir_all(blocked_original.parent().unwrap()).unwrap();
        fs::write(&restored_trashed, "restored").unwrap();
        fs::write(&blocked_original, "new").unwrap();
        fs::write(&blocked_trashed, "old").unwrap();

        let output = undo_app_uninstall_records(
            vec![AppUninstallJournalRecord {
                plan: UninstallPlan::trash(
                    AppIdentity::macos("Demo"),
                    vec![
                        RelatedPath {
                            path: restored_original.display().to_string(),
                            kind: RelatedPathKind::ApplicationBundle,
                            estimated_size: 8,
                        },
                        RelatedPath {
                            path: blocked_original.display().to_string(),
                            kind: RelatedPathKind::ApplicationBundle,
                            estimated_size: 3,
                        },
                    ],
                ),
                moves: vec![
                    AppUninstallJournalMove {
                        original_path: restored_original.clone(),
                        trashed_path: restored_trashed.clone(),
                    },
                    AppUninstallJournalMove {
                        original_path: blocked_original.clone(),
                        trashed_path: blocked_trashed.clone(),
                    },
                ],
            }],
            Some(&state_dir),
        )
        .unwrap();

        assert_eq!(fs::read_to_string(&restored_original).unwrap(), "restored");
        assert!(!restored_trashed.exists());
        assert_eq!(fs::read_to_string(&blocked_original).unwrap(), "new");
        assert_eq!(fs::read_to_string(&blocked_trashed).unwrap(), "old");
        assert_eq!(output.retry_records.len(), 1);
        assert_eq!(output.retry_records[0].moves.len(), 1);
        assert_eq!(
            output.retry_records[0].moves[0].original_path,
            blocked_original
        );
        assert!(
            output
                .lines
                .iter()
                .any(|line| line.starts_with("journal kept:"))
        );
    }

    #[test]
    fn app_uninstall_journal_round_trips_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let journal = AppUninstallJournal::new(vec![AppUninstallJournalRecord {
            plan: UninstallPlan::trash(
                AppIdentity::macos("Demo"),
                vec![RelatedPath {
                    path: "/Applications/Demo.app".to_string(),
                    kind: RelatedPathKind::ApplicationBundle,
                    estimated_size: 12,
                }],
            ),
            moves: vec![AppUninstallJournalMove {
                original_path: PathBuf::from("/Applications/Demo.app"),
                trashed_path: dir.path().join("Trash").join("Demo.app"),
            }],
        }]);

        let path = write_last_app_uninstall_journal(dir.path(), &journal).unwrap();

        assert_eq!(path, app_uninstall_journal_path(dir.path()));
        assert_eq!(
            read_last_app_uninstall_journal(dir.path()).unwrap(),
            Some(journal)
        );

        clear_last_app_uninstall_journal(dir.path()).unwrap();

        assert_eq!(read_last_app_uninstall_journal(dir.path()).unwrap(), None);
    }
}
