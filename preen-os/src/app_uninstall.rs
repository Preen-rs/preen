use crate::app_inventory;
use preen_core::app_uninstall::{
    AppIdentity, AppPlatform, InstalledApplication, RelatedPath, RelatedPathKind, UninstallPlan,
    path_name_matches_app,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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
        if path.is_dir() {
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
    let Ok(metadata) = fs::metadata(path) else {
        return 0;
    };
    if metadata.is_file() {
        return metadata.len();
    }
    if !metadata.is_dir() {
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
}
