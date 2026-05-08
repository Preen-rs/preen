use crate::app_inventory;
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
    use preen_core::app_uninstall::AppSource;

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
