use chrono::{DateTime, Utc};
use preen_core::app_uninstall::{
    AppIdentity, AppManagementSource, AppPackageDetectionConfidence, AppPackageManager,
    AppPackageMetadata, AppSource, AppUpdateAvailability, InstalledApplication,
    normalize_app_match_key,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

const MAX_DISCOVERED_APPS: usize = 400;
const INVENTORY_COMMAND_TIMEOUT: Duration = Duration::from_millis(1_500);
const METADATA_COMMAND_TIMEOUT: Duration = Duration::from_millis(300);
const APP_STORE_LOOKUP_TIMEOUT: Duration = Duration::from_millis(2_000);

pub fn collect_installed_applications() -> Vec<InstalledApplication> {
    collect_installed_applications_with_options(true)
}

pub fn collect_installed_application_names() -> Vec<String> {
    collect_installed_applications_with_options(false)
        .into_iter()
        .map(|app| app.identity.display_name)
        .collect()
}

fn collect_installed_applications_with_options(include_sizes: bool) -> Vec<InstalledApplication> {
    let mut apps = if cfg!(target_os = "macos") {
        collect_macos_applications(include_sizes)
    } else if cfg!(target_os = "linux") {
        collect_linux_applications(include_sizes)
    } else {
        Vec::new()
    };
    apps.sort_by(|a, b| {
        a.identity
            .display_name
            .to_ascii_lowercase()
            .cmp(&b.identity.display_name.to_ascii_lowercase())
            .then_with(|| a.path.cmp(&b.path))
    });
    apps.dedup_by(|a, b| a.path == b.path);
    apps.truncate(MAX_DISCOVERED_APPS);
    apps
}

fn collect_macos_applications(include_sizes: bool) -> Vec<InstalledApplication> {
    let mut roots = vec![
        (PathBuf::from("/Applications"), AppSource::Local, false),
        (
            PathBuf::from("/System/Applications"),
            AppSource::System,
            true,
        ),
    ];
    if let Some(home) = home_dir() {
        roots.push((home.join("Applications"), AppSource::User, false));
    }

    let mut discovered = Vec::new();
    let homebrew_casks = include_sizes.then(homebrew_cask_snapshot).flatten();
    for (root, source, protected) in roots {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || path.extension().and_then(|value| value.to_str()) != Some("app") {
                continue;
            }
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let fallback_name = file_name.trim_end_matches(".app").trim();
            if fallback_name.is_empty() {
                continue;
            }

            let plist = parse_macos_info_plist(&path.join("Contents/Info.plist"));
            let display_name = plist
                .get("CFBundleDisplayName")
                .or_else(|| plist.get("CFBundleName"))
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| fallback_name.to_string());
            let mut identity = AppIdentity::macos(display_name);
            identity.bundle_identifier = plist.get("CFBundleIdentifier").cloned();

            discovered.push(MacosApplicationCandidate {
                identity,
                path,
                version: plist
                    .get("CFBundleShortVersionString")
                    .or_else(|| plist.get("CFBundleVersion"))
                    .cloned(),
                source: source.clone(),
                protected,
            });
        }
    }
    let app_store_snapshot = include_sizes
        .then(|| mac_app_store_snapshot(&discovered))
        .flatten();

    let mut apps = Vec::new();
    for candidate in discovered {
        let management_source = macos_management_source(
            &candidate.path,
            &candidate.source,
            candidate.protected,
            &candidate.identity,
            homebrew_casks.as_ref(),
        );
        let update_availability = macos_update_availability(
            &candidate.path,
            &candidate.source,
            candidate.protected,
            &candidate.identity,
            homebrew_casks.as_ref(),
            app_store_snapshot.as_ref(),
        );
        let package_metadata = macos_package_metadata(
            &candidate.path,
            &candidate.source,
            candidate.protected,
            &candidate.identity,
            candidate.version.as_deref(),
            homebrew_casks.as_ref(),
            app_store_snapshot.as_ref(),
        );
        let path_string = candidate.path.to_string_lossy().to_string();

        apps.push(InstalledApplication {
            identity: candidate.identity,
            path: path_string,
            version: candidate.version,
            source: candidate.source,
            estimated_size: estimated_path_size(&candidate.path, include_sizes),
            last_used_at: if include_sizes {
                macos_last_used_at(&candidate.path)
                    .or_else(|| filesystem_last_used_at(&candidate.path))
            } else {
                None
            },
            management_source,
            update_availability,
            package_metadata,
            protected: candidate.protected,
        });
    }
    apps
}

#[derive(Debug, Clone)]
struct MacosApplicationCandidate {
    identity: AppIdentity,
    path: PathBuf,
    version: Option<String>,
    source: AppSource,
    protected: bool,
}

fn collect_linux_applications(include_sizes: bool) -> Vec<InstalledApplication> {
    let mut dirs = vec![
        (PathBuf::from("/usr/share/applications"), AppSource::System),
        (
            PathBuf::from("/usr/local/share/applications"),
            AppSource::Local,
        ),
    ];
    if let Some(home) = home_dir() {
        dirs.push((home.join(".local/share/applications"), AppSource::User));
    }

    let mut apps = Vec::new();
    let package_updates = include_sizes.then(linux_package_update_snapshot).flatten();
    for (dir, source) in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("desktop") {
                continue;
            }
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            let desktop = parse_desktop_entry(&content);
            if !is_visible_application_desktop_entry(&desktop) {
                continue;
            }
            let Some(name) = desktop.get("Name").filter(|value| !value.trim().is_empty()) else {
                continue;
            };

            let mut identity = AppIdentity::linux(name.clone());
            identity.desktop_id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .map(ToOwned::to_owned);
            let management_source = linux_management_source(&source, &desktop);
            let update_availability =
                linux_update_availability(&source, &desktop, &identity, package_updates.as_ref());
            let package_metadata =
                linux_package_metadata(&desktop, &identity, package_updates.as_ref());

            apps.push(InstalledApplication {
                identity,
                path: path.to_string_lossy().to_string(),
                version: desktop.get("X-Version").cloned(),
                source: source.clone(),
                estimated_size: estimated_path_size(&path, include_sizes),
                last_used_at: if include_sizes {
                    filesystem_last_used_at(&path)
                } else {
                    None
                },
                management_source,
                update_availability,
                package_metadata,
                protected: matches!(source, AppSource::System),
            });
        }
    }
    apps
}

fn parse_macos_info_plist(path: &Path) -> BTreeMap<String, String> {
    let Ok(content) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };

    let mut values = BTreeMap::new();
    let mut pending_key: Option<String> = None;
    for line in content.lines().map(str::trim) {
        if let Some(key) = extract_xml_tag_value(line, "key") {
            pending_key = Some(key);
            continue;
        }
        if let Some(key) = pending_key.take()
            && let Some(value) = extract_xml_tag_value(line, "string")
        {
            values.insert(key, value);
        }
    }
    values
}

fn parse_desktop_entry(content: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let mut in_desktop_entry = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_desktop_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_desktop_entry {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.contains('[') {
            continue;
        }
        values.insert(key.trim().to_string(), value.trim().to_string());
    }
    values
}

fn is_visible_application_desktop_entry(desktop: &BTreeMap<String, String>) -> bool {
    if desktop
        .get("Type")
        .is_some_and(|value| !value.eq_ignore_ascii_case("Application"))
    {
        return false;
    }
    if desktop
        .get("NoDisplay")
        .is_some_and(|value| is_truthy(value))
    {
        return false;
    }
    if desktop.get("Hidden").is_some_and(|value| is_truthy(value)) {
        return false;
    }
    true
}

fn extract_xml_tag_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = line.find(&open)? + open.len();
    let end = line[start..].find(&close)? + start;
    Some(unescape_basic_xml(&line[start..end]))
}

fn unescape_basic_xml(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes"
    )
}

fn estimated_path_size(path: &Path, include_size: bool) -> u64 {
    if include_size {
        calculate_path_size(path)
    } else {
        0
    }
}

fn macos_last_used_at(path: &Path) -> Option<DateTime<Utc>> {
    let mut command = Command::new("mdls");
    command
        .arg("-raw")
        .arg("-name")
        .arg("kMDItemLastUsedDate")
        .arg(path);
    let output = run_inventory_command_with_timeout(command, METADATA_COMMAND_TIMEOUT)?;
    if !output.status.success() {
        return None;
    }
    parse_macos_mdls_date(&String::from_utf8_lossy(&output.stdout))
}

fn parse_macos_mdls_date(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() || value == "(null)" {
        return None;
    }
    DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S %z")
        .ok()
        .map(|date| date.with_timezone(&Utc))
}

fn filesystem_last_used_at(path: &Path) -> Option<DateTime<Utc>> {
    let metadata = fs::metadata(path).ok()?;
    metadata
        .accessed()
        .or_else(|_| metadata.modified())
        .ok()
        .map(system_time_to_utc)
}

fn system_time_to_utc(value: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(value)
}

fn macos_management_source(
    path: &Path,
    source: &AppSource,
    protected: bool,
    identity: &AppIdentity,
    casks: Option<&HomebrewCaskSnapshot>,
) -> AppManagementSource {
    if protected || matches!(source, AppSource::System) {
        return AppManagementSource::System;
    }
    if path.join("Contents/_MASReceipt/receipt").is_file() {
        return AppManagementSource::AppStore;
    }
    if casks.is_some_and(|snapshot| snapshot.matches_app(identity, path)) {
        return AppManagementSource::PackageManager;
    }
    AppManagementSource::Manual
}

fn macos_update_availability(
    path: &Path,
    source: &AppSource,
    protected: bool,
    identity: &AppIdentity,
    casks: Option<&HomebrewCaskSnapshot>,
    app_store: Option<&MacAppStoreSnapshot>,
) -> AppUpdateAvailability {
    match macos_management_source(path, source, protected, identity, casks) {
        AppManagementSource::System => AppUpdateAvailability::Unsupported,
        AppManagementSource::AppStore => app_store
            .map(|snapshot| snapshot.app_update_availability(path))
            .unwrap_or(AppUpdateAvailability::NotChecked),
        AppManagementSource::PackageManager => casks
            .map(|snapshot| {
                if snapshot.app_has_update(identity, path) {
                    AppUpdateAvailability::UpdateAvailable
                } else {
                    AppUpdateAvailability::UpToDate
                }
            })
            .unwrap_or(AppUpdateAvailability::NotChecked),
        AppManagementSource::Manual => AppUpdateAvailability::Unsupported,
        AppManagementSource::Unknown => AppUpdateAvailability::Unknown,
    }
}

fn macos_package_metadata(
    path: &Path,
    source: &AppSource,
    protected: bool,
    identity: &AppIdentity,
    installed_version: Option<&str>,
    casks: Option<&HomebrewCaskSnapshot>,
    app_store: Option<&MacAppStoreSnapshot>,
) -> Option<AppPackageMetadata> {
    if protected || matches!(source, AppSource::System) {
        return None;
    }
    if path.join("Contents/_MASReceipt/receipt").is_file() {
        return app_store.and_then(|snapshot| snapshot.package_metadata(path, installed_version));
    }
    casks.and_then(|snapshot| snapshot.package_metadata(identity, path))
}

fn linux_management_source(
    source: &AppSource,
    desktop: &BTreeMap<String, String>,
) -> AppManagementSource {
    if desktop.contains_key("X-Flatpak") || desktop.contains_key("X-SnapInstanceName") {
        return AppManagementSource::PackageManager;
    }
    match source {
        AppSource::System | AppSource::Local => AppManagementSource::PackageManager,
        AppSource::User => AppManagementSource::Manual,
        AppSource::Unknown => AppManagementSource::Unknown,
    }
}

fn linux_update_availability(
    source: &AppSource,
    desktop: &BTreeMap<String, String>,
    identity: &AppIdentity,
    package_updates: Option<&LinuxPackageUpdateSnapshot>,
) -> AppUpdateAvailability {
    match linux_management_source(source, desktop) {
        AppManagementSource::PackageManager => package_updates
            .map(|snapshot| {
                if snapshot.app_has_update(identity, desktop) {
                    AppUpdateAvailability::UpdateAvailable
                } else {
                    AppUpdateAvailability::NotChecked
                }
            })
            .unwrap_or(AppUpdateAvailability::NotChecked),
        AppManagementSource::Manual => AppUpdateAvailability::Unsupported,
        AppManagementSource::Unknown => AppUpdateAvailability::Unknown,
        AppManagementSource::System | AppManagementSource::AppStore => {
            AppUpdateAvailability::Unknown
        }
    }
}

fn linux_package_metadata(
    desktop: &BTreeMap<String, String>,
    identity: &AppIdentity,
    package_updates: Option<&LinuxPackageUpdateSnapshot>,
) -> Option<AppPackageMetadata> {
    if let Some(package_id) = desktop
        .get("X-Flatpak")
        .filter(|value| !value.trim().is_empty())
    {
        return Some(AppPackageMetadata {
            manager: AppPackageManager::Flatpak,
            package_id: package_id.clone(),
            installed_version: None,
            latest_version: None,
            update_command: Some(format!("flatpak update {package_id}")),
            detection_confidence: AppPackageDetectionConfidence::Exact,
        });
    }
    if let Some(package_id) = desktop
        .get("X-SnapInstanceName")
        .filter(|value| !value.trim().is_empty())
    {
        return Some(AppPackageMetadata {
            manager: AppPackageManager::Snap,
            package_id: package_id.clone(),
            installed_version: None,
            latest_version: None,
            update_command: Some(format!("snap refresh {package_id}")),
            detection_confidence: AppPackageDetectionConfidence::Exact,
        });
    }
    package_updates.and_then(|snapshot| snapshot.package_metadata(identity, desktop))
}

#[derive(Debug, Clone, Default)]
struct MacAppStoreSnapshot {
    apps_by_path: BTreeMap<String, MacAppStoreMetadata>,
}

#[derive(Debug, Clone)]
struct MacAppStoreMetadata {
    adam_id: String,
    installed_version: Option<String>,
    latest_version: Option<String>,
}

impl MacAppStoreSnapshot {
    fn app_update_availability(&self, path: &Path) -> AppUpdateAvailability {
        let Some(metadata) = self.apps_by_path.get(&path_key(path)) else {
            return AppUpdateAvailability::NotChecked;
        };
        match (
            metadata.installed_version.as_deref(),
            metadata.latest_version.as_deref(),
        ) {
            (Some(installed), Some(latest)) if app_store_version_is_newer(installed, latest) => {
                AppUpdateAvailability::UpdateAvailable
            }
            (Some(_), Some(_)) => AppUpdateAvailability::UpToDate,
            _ => AppUpdateAvailability::NotChecked,
        }
    }

    fn package_metadata(
        &self,
        path: &Path,
        installed_version: Option<&str>,
    ) -> Option<AppPackageMetadata> {
        let metadata = self.apps_by_path.get(&path_key(path))?;
        Some(AppPackageMetadata {
            manager: AppPackageManager::MacAppStore,
            package_id: metadata.adam_id.clone(),
            installed_version: metadata
                .installed_version
                .clone()
                .or_else(|| installed_version.map(ToOwned::to_owned)),
            latest_version: metadata.latest_version.clone(),
            update_command: Some(format!("app-store update {}", metadata.adam_id)),
            detection_confidence: AppPackageDetectionConfidence::Exact,
        })
    }
}

fn mac_app_store_snapshot(apps: &[MacosApplicationCandidate]) -> Option<MacAppStoreSnapshot> {
    let mut apps_by_path = BTreeMap::new();
    let mut adam_ids = BTreeSet::new();
    for app in apps
        .iter()
        .filter(|app| !app.protected && app.path.join("Contents/_MASReceipt/receipt").is_file())
    {
        let Some(adam_id) = mac_app_store_adam_id(&app.path) else {
            continue;
        };
        adam_ids.insert(adam_id.clone());
        apps_by_path.insert(
            path_key(&app.path),
            MacAppStoreMetadata {
                adam_id,
                installed_version: app.version.clone(),
                latest_version: None,
            },
        );
    }
    if apps_by_path.is_empty() {
        return None;
    }

    let latest_versions = mac_app_store_latest_versions(&adam_ids).unwrap_or_default();
    for metadata in apps_by_path.values_mut() {
        metadata.latest_version = latest_versions.get(&metadata.adam_id).cloned();
    }
    Some(MacAppStoreSnapshot { apps_by_path })
}

fn mac_app_store_adam_id(path: &Path) -> Option<String> {
    let output = run_inventory_command_with_timeout(
        command_with_args(
            Path::new("/usr/bin/mdls"),
            &["-raw", "-name", "kMDItemAppStoreAdamID", path.to_str()?],
        ),
        METADATA_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return None;
    }
    parse_macos_app_store_adam_id(&String::from_utf8_lossy(&output.stdout))
}

fn parse_macos_app_store_adam_id(output: &str) -> Option<String> {
    let value = output.trim().trim_matches('"');
    if value.is_empty() || value == "(null)" || value == "0" {
        return None;
    }
    value
        .chars()
        .all(|ch| ch.is_ascii_digit())
        .then(|| value.to_string())
}

fn mac_app_store_latest_versions(adam_ids: &BTreeSet<String>) -> Option<BTreeMap<String, String>> {
    if adam_ids.is_empty() {
        return None;
    }
    let curl = find_executable_in_common_paths("curl", &["/usr/bin/curl"])?;
    let country = std::env::var("PREEN_APP_STORE_COUNTRY")
        .ok()
        .filter(|value| value.len() == 2)
        .unwrap_or_else(|| "us".to_string());
    let ids = adam_ids.iter().cloned().collect::<Vec<_>>().join(",");
    let url = format!(
        "https://itunes.apple.com/lookup?media=software&entity=desktopSoftware&country={country}&id={ids}"
    );
    let mut command = Command::new(curl);
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "2",
        &url,
    ]);
    let output = run_inventory_command_with_timeout(command, APP_STORE_LOOKUP_TIMEOUT)?;
    if !output.status.success() {
        return None;
    }
    parse_app_store_lookup_versions(&String::from_utf8_lossy(&output.stdout))
}

fn parse_app_store_lookup_versions(output: &str) -> Option<BTreeMap<String, String>> {
    let root = serde_json::from_str::<serde_json::Value>(output).ok()?;
    let results = root.get("results")?.as_array()?;
    let mut versions = BTreeMap::new();
    for app in results {
        let Some(adam_id) = app.get("trackId").and_then(|value| match value {
            serde_json::Value::Number(number) => Some(number.to_string()),
            serde_json::Value::String(value) => Some(value.clone()),
            _ => None,
        }) else {
            continue;
        };
        let Some(version) = app
            .get("version")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        versions.insert(adam_id, version.to_string());
    }
    Some(versions)
}

fn app_store_version_is_newer(installed: &str, latest: &str) -> bool {
    let installed = installed.trim();
    let latest = latest.trim();
    if installed.is_empty() || latest.is_empty() || installed == latest {
        return false;
    }
    compare_version_segments(installed, latest)
        .map(|ordering| ordering.is_lt())
        .unwrap_or(true)
}

fn compare_version_segments(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    let left_segments = version_segments(left)?;
    let right_segments = version_segments(right)?;
    let len = left_segments.len().max(right_segments.len());
    for index in 0..len {
        let left = left_segments.get(index).copied().unwrap_or(0);
        let right = right_segments.get(index).copied().unwrap_or(0);
        match left.cmp(&right) {
            std::cmp::Ordering::Equal => {}
            ordering => return Some(ordering),
        }
    }
    Some(std::cmp::Ordering::Equal)
}

fn version_segments(value: &str) -> Option<Vec<u64>> {
    let mut segments = Vec::new();
    for part in value.split(|ch: char| !ch.is_ascii_digit()) {
        if part.is_empty() {
            continue;
        }
        segments.push(part.parse::<u64>().ok()?);
    }
    (!segments.is_empty()).then_some(segments)
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[derive(Debug, Clone, Default)]
struct HomebrewCaskSnapshot {
    installed: BTreeMap<String, HomebrewCaskMetadata>,
    outdated: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
struct HomebrewCaskMetadata {
    token: String,
    installed_version: Option<String>,
}

impl HomebrewCaskSnapshot {
    fn matches_app(&self, identity: &AppIdentity, path: &Path) -> bool {
        let candidates = macos_app_match_candidates(identity, path);
        candidates
            .iter()
            .any(|candidate| self.installed.contains_key(candidate))
    }

    fn app_has_update(&self, identity: &AppIdentity, path: &Path) -> bool {
        self.matching_cask(identity, path)
            .map(|(_, cask)| {
                self.outdated
                    .contains(&normalize_app_match_key(&cask.token))
            })
            .unwrap_or(false)
    }

    fn package_metadata(&self, identity: &AppIdentity, path: &Path) -> Option<AppPackageMetadata> {
        let (matched_key, cask) = self.matching_cask(identity, path)?;
        Some(AppPackageMetadata {
            manager: AppPackageManager::HomebrewCask,
            package_id: cask.token.clone(),
            installed_version: cask.installed_version.clone(),
            latest_version: None,
            update_command: Some(format!("brew upgrade --cask {}", cask.token)),
            detection_confidence: homebrew_detection_confidence(identity, path, matched_key),
        })
    }

    fn matching_cask(
        &self,
        identity: &AppIdentity,
        path: &Path,
    ) -> Option<(&str, &HomebrewCaskMetadata)> {
        let candidates = macos_app_match_candidates(identity, path);
        candidates
            .iter()
            .find_map(|candidate| self.installed.get_key_value(candidate))
            .map(|(key, value)| (key.as_str(), value))
    }
}

fn homebrew_cask_snapshot() -> Option<HomebrewCaskSnapshot> {
    let brew = find_executable_in_common_paths(
        "brew",
        &["/opt/homebrew/bin/brew", "/usr/local/bin/brew"],
    )?;
    let installed_output = run_inventory_command_with_timeout(
        homebrew_command_with_args(&brew, &["list", "--cask", "--versions"]),
        INVENTORY_COMMAND_TIMEOUT,
    )?;
    if !installed_output.status.success() {
        return None;
    }
    let installed =
        parse_homebrew_installed_casks(&String::from_utf8_lossy(&installed_output.stdout));
    let installed = run_inventory_command_with_timeout(
        homebrew_command_with_args(&brew, &["info", "--cask", "--json=v2", "--installed"]),
        INVENTORY_COMMAND_TIMEOUT,
    )
    .filter(|output| output.status.success())
    .map(|output| {
        parse_homebrew_cask_info_json(&String::from_utf8_lossy(&output.stdout), installed.clone())
    })
    .unwrap_or(installed);
    if installed.is_empty() {
        return None;
    }

    let outdated = run_inventory_command_with_timeout(
        homebrew_command_with_args(&brew, &["outdated", "--cask", "--greedy", "--quiet"]),
        INVENTORY_COMMAND_TIMEOUT,
    )
    .filter(|output| output.status.success())
    .map(|output| parse_homebrew_cask_tokens(&String::from_utf8_lossy(&output.stdout)))
    .unwrap_or_default();

    Some(HomebrewCaskSnapshot {
        installed,
        outdated,
    })
}

fn parse_homebrew_cask_tokens(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(normalize_app_match_key)
        .filter(|token| !token.is_empty())
        .collect()
}

fn parse_homebrew_installed_casks(output: &str) -> BTreeMap<String, HomebrewCaskMetadata> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let token = parts.next()?;
            let normalized = normalize_app_match_key(token);
            if normalized.is_empty() {
                return None;
            }
            let version = parts.collect::<Vec<_>>().join(" ");
            Some((
                normalized,
                HomebrewCaskMetadata {
                    token: token.to_string(),
                    installed_version: (!version.is_empty()).then_some(version),
                },
            ))
        })
        .collect()
}

fn parse_homebrew_cask_info_json(
    output: &str,
    installed: BTreeMap<String, HomebrewCaskMetadata>,
) -> BTreeMap<String, HomebrewCaskMetadata> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(output) else {
        return installed;
    };
    let Some(casks) = root.get("casks").and_then(|value| value.as_array()) else {
        return installed;
    };

    let mut enriched = installed.clone();
    for cask in casks {
        let Some(token) = cask.get("token").and_then(|value| value.as_str()) else {
            continue;
        };
        let token_key = normalize_app_match_key(token);
        if token_key.is_empty() {
            continue;
        }
        let metadata = enriched
            .get(&token_key)
            .cloned()
            .or_else(|| installed.get(&token_key).cloned())
            .unwrap_or_else(|| HomebrewCaskMetadata {
                token: token.to_string(),
                installed_version: cask
                    .get("version")
                    .and_then(|value| value.as_str())
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned),
            });

        enriched.insert(token_key, metadata.clone());
        for alias in homebrew_cask_json_aliases(cask) {
            let alias_key = normalize_app_match_key(&alias);
            if !alias_key.is_empty() {
                enriched.insert(alias_key, metadata.clone());
            }
        }
    }
    enriched
}

fn homebrew_cask_json_aliases(cask: &serde_json::Value) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    for key in ["name", "aliases", "old_tokens"] {
        if let Some(values) = cask.get(key).and_then(|value| value.as_array()) {
            for value in values.iter().filter_map(|value| value.as_str()) {
                aliases.insert(value.to_string());
            }
        }
    }
    if let Some(artifacts) = cask.get("artifacts").and_then(|value| value.as_array()) {
        for artifact in artifacts {
            collect_homebrew_artifact_aliases(artifact, &mut aliases);
        }
    }
    aliases
}

fn collect_homebrew_artifact_aliases(artifact: &serde_json::Value, aliases: &mut BTreeSet<String>) {
    if let Some(value) = artifact.as_str() {
        push_homebrew_artifact_alias(value, aliases);
        return;
    }
    if let Some(values) = artifact.get("app").and_then(|value| value.as_array()) {
        for value in values.iter().filter_map(|value| value.as_str()) {
            push_homebrew_artifact_alias(value, aliases);
        }
    }
    if let Some(value) = artifact.get("app").and_then(|value| value.as_str()) {
        push_homebrew_artifact_alias(value, aliases);
    }
}

fn push_homebrew_artifact_alias(value: &str, aliases: &mut BTreeSet<String>) {
    let path = Path::new(value);
    if let Some(file_name) = path.file_name().and_then(|value| value.to_str()) {
        aliases.insert(file_name.to_string());
        aliases.insert(file_name.trim_end_matches(".app").to_string());
    }
}

fn homebrew_detection_confidence(
    identity: &AppIdentity,
    path: &Path,
    matched_key: &str,
) -> AppPackageDetectionConfidence {
    let path_key = path
        .file_stem()
        .and_then(|value| value.to_str())
        .map(normalize_app_match_key);
    if path_key.as_deref() == Some(matched_key) {
        return AppPackageDetectionConfidence::Strong;
    }
    if identity.bundle_identifier.as_ref().is_some_and(|value| {
        value
            .split(['.', '-'])
            .any(|part| normalize_app_match_key(part) == matched_key)
    }) {
        return AppPackageDetectionConfidence::Strong;
    }
    AppPackageDetectionConfidence::Fallback
}

fn macos_app_match_candidates(identity: &AppIdentity, path: &Path) -> BTreeSet<String> {
    let mut candidates = app_identity_match_candidates(identity);
    if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
        push_normalized_candidate(&mut candidates, stem);
    }
    candidates
}

#[derive(Debug, Clone, Default)]
struct LinuxPackageUpdateSnapshot {
    upgradable_packages: BTreeMap<String, LinuxPackageMetadata>,
}

#[derive(Debug, Clone)]
struct LinuxPackageMetadata {
    manager: AppPackageManager,
    package_id: String,
}

impl LinuxPackageUpdateSnapshot {
    fn app_has_update(&self, identity: &AppIdentity, desktop: &BTreeMap<String, String>) -> bool {
        self.matching_update_package(identity, desktop).is_some()
    }

    fn package_metadata(
        &self,
        identity: &AppIdentity,
        desktop: &BTreeMap<String, String>,
    ) -> Option<AppPackageMetadata> {
        let package = self.matching_update_package(identity, desktop)?;
        Some(AppPackageMetadata {
            manager: package.manager.clone(),
            package_id: package.package_id.clone(),
            installed_version: None,
            latest_version: None,
            update_command: None,
            detection_confidence: AppPackageDetectionConfidence::Fallback,
        })
    }

    fn matching_update_package(
        &self,
        identity: &AppIdentity,
        desktop: &BTreeMap<String, String>,
    ) -> Option<&LinuxPackageMetadata> {
        let candidates = linux_app_match_candidates(identity, desktop);
        candidates
            .iter()
            .find_map(|candidate| self.upgradable_packages.get(candidate))
    }
}

fn linux_package_update_snapshot() -> Option<LinuxPackageUpdateSnapshot> {
    let mut upgradable_packages = BTreeMap::new();

    if let Some(apt) = find_executable_in_common_paths("apt", &["/usr/bin/apt"]) {
        let output = run_inventory_command_with_timeout(
            command_with_args(&apt, &["list", "--upgradable"]),
            INVENTORY_COMMAND_TIMEOUT,
        );
        if let Some(output) = output.filter(|output| output.status.success()) {
            upgradable_packages.extend(parse_apt_upgradable_packages(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }
    }

    if let Some(dnf) = find_executable_in_common_paths("dnf", &["/usr/bin/dnf"]) {
        let output = run_inventory_command_with_timeout(
            command_with_args(&dnf, &["check-update", "--quiet"]),
            INVENTORY_COMMAND_TIMEOUT,
        );
        if let Some(output) =
            output.filter(|output| output.status.success() || output.status.code() == Some(100))
        {
            upgradable_packages.extend(parse_dnf_upgradable_packages(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }
    }

    if let Some(checkupdates) =
        find_executable_in_common_paths("checkupdates", &["/usr/bin/checkupdates"])
    {
        let output = run_inventory_command_with_timeout(
            command_with_args(&checkupdates, &[]),
            INVENTORY_COMMAND_TIMEOUT,
        );
        if let Some(output) = output.filter(|output| output.status.success()) {
            upgradable_packages.extend(parse_pacman_upgradable_packages(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }
    }

    if upgradable_packages.is_empty() {
        return None;
    }
    Some(LinuxPackageUpdateSnapshot {
        upgradable_packages,
    })
}

fn parse_apt_upgradable_packages(output: &str) -> BTreeMap<String, LinuxPackageMetadata> {
    output
        .lines()
        .filter_map(|line| line.split_once('/').map(|(name, _)| name.trim()))
        .filter_map(|name| linux_package_metadata_entry(AppPackageManager::Apt, name))
        .collect()
}

fn parse_dnf_upgradable_packages(output: &str) -> BTreeMap<String, LinuxPackageMetadata> {
    output
        .lines()
        .filter_map(|line| {
            let first = line.split_whitespace().next()?;
            if first.starts_with("Last") {
                return None;
            }
            Some(
                first
                    .rsplit_once('.')
                    .map(|(name, _)| name)
                    .unwrap_or(first),
            )
        })
        .filter_map(|name| linux_package_metadata_entry(AppPackageManager::Dnf, name))
        .collect()
}

fn parse_pacman_upgradable_packages(output: &str) -> BTreeMap<String, LinuxPackageMetadata> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|name| linux_package_metadata_entry(AppPackageManager::Pacman, name))
        .collect()
}

fn linux_package_metadata_entry(
    manager: AppPackageManager,
    package_id: &str,
) -> Option<(String, LinuxPackageMetadata)> {
    let normalized = normalize_app_match_key(package_id);
    if normalized.is_empty() {
        return None;
    }
    Some((
        normalized,
        LinuxPackageMetadata {
            manager,
            package_id: package_id.to_string(),
        },
    ))
}

fn linux_app_match_candidates(
    identity: &AppIdentity,
    desktop: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut candidates = app_identity_match_candidates(identity);
    if let Some(value) = desktop.get("Exec") {
        if let Some(command) = value.split_whitespace().next() {
            let executable = Path::new(command)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or(command);
            push_normalized_candidate(&mut candidates, executable);
        }
    }
    if let Some(value) = desktop.get("X-Flatpak") {
        push_normalized_candidate(&mut candidates, value);
    }
    if let Some(value) = desktop.get("X-SnapInstanceName") {
        push_normalized_candidate(&mut candidates, value);
    }
    candidates
}

fn app_identity_match_candidates(identity: &AppIdentity) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    push_normalized_candidate(&mut candidates, &identity.display_name);
    if let Some(value) = &identity.bundle_identifier {
        push_identifier_candidates(&mut candidates, value);
    }
    if let Some(value) = &identity.desktop_id {
        push_identifier_candidates(&mut candidates, value);
    }
    candidates
}

fn push_identifier_candidates(candidates: &mut BTreeSet<String>, value: &str) {
    push_normalized_candidate(candidates, value);
    for segment in value.split(['.', '-']) {
        push_normalized_candidate(candidates, segment);
    }
}

fn push_normalized_candidate(candidates: &mut BTreeSet<String>, value: &str) {
    let candidate = normalize_app_match_key(value);
    if !candidate.is_empty() {
        candidates.insert(candidate);
    }
}

fn command_with_args(program: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    command
}

fn homebrew_command_with_args(program: &Path, args: &[&str]) -> Command {
    let mut command = command_with_args(program, args);
    command.env("HOMEBREW_NO_AUTO_UPDATE", "1");
    command
}

fn find_executable_in_common_paths(name: &str, absolute_paths: &[&str]) -> Option<PathBuf> {
    for path in absolute_paths {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn run_inventory_command_with_timeout(mut command: Command, timeout: Duration) -> Option<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
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

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_info_plist_values() {
        let dir = tempfile::tempdir().unwrap();
        let plist = dir.path().join("Info.plist");
        fs::write(
            &plist,
            r#"<?xml version="1.0"?>
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>Demo</string>
  <key>CFBundleIdentifier</key>
  <string>com.example.demo</string>
</dict>
</plist>"#,
        )
        .unwrap();

        let values = parse_macos_info_plist(&plist);
        assert_eq!(values.get("CFBundleName").map(String::as_str), Some("Demo"));
        assert_eq!(
            values.get("CFBundleIdentifier").map(String::as_str),
            Some("com.example.demo")
        );
    }

    #[test]
    fn parses_desktop_entry_primary_section_only() {
        let values = parse_desktop_entry(
            r#"[Other]
Name=Wrong

[Desktop Entry]
Name=Demo
Name[de]=Demo DE
NoDisplay=false
X-Version=1.2.3
"#,
        );

        assert_eq!(values.get("Name").map(String::as_str), Some("Demo"));
        assert_eq!(values.get("X-Version").map(String::as_str), Some("1.2.3"));
        assert!(!values.contains_key("Name[de]"));
    }

    #[test]
    fn filters_hidden_and_non_application_desktop_entries() {
        let visible = parse_desktop_entry(
            r#"[Desktop Entry]
Type=Application
Name=Demo
"#,
        );
        let hidden = parse_desktop_entry(
            r#"[Desktop Entry]
Type=Application
Name=Hidden Demo
Hidden=true
"#,
        );
        let no_display = parse_desktop_entry(
            r#"[Desktop Entry]
Type=Application
Name=No Display Demo
NoDisplay=yes
"#,
        );
        let link = parse_desktop_entry(
            r#"[Desktop Entry]
Type=Link
Name=Docs
"#,
        );

        assert!(is_visible_application_desktop_entry(&visible));
        assert!(!is_visible_application_desktop_entry(&hidden));
        assert!(!is_visible_application_desktop_entry(&no_display));
        assert!(!is_visible_application_desktop_entry(&link));
    }

    #[test]
    fn calculates_recursive_directory_size() {
        let dir = tempfile::tempdir().unwrap();
        let app_bundle = dir.path().join("Demo.app");
        let resources = app_bundle.join("Contents").join("Resources");
        fs::create_dir_all(&resources).unwrap();
        fs::write(app_bundle.join("Contents").join("Info.plist"), "plist").unwrap();
        fs::write(resources.join("asset.bin"), [1_u8, 2, 3]).unwrap();

        assert_eq!(calculate_path_size(&app_bundle), 8);
    }

    #[test]
    fn estimated_path_size_can_skip_expensive_size_walks() {
        let dir = tempfile::tempdir().unwrap();
        let app_bundle = dir.path().join("Demo.app");
        fs::create_dir_all(&app_bundle).unwrap();
        fs::write(app_bundle.join("Info.plist"), "plist").unwrap();

        assert_eq!(estimated_path_size(&app_bundle, false), 0);
        assert_eq!(estimated_path_size(&app_bundle, true), 5);
    }

    #[test]
    fn parses_macos_mdls_last_used_date() {
        let parsed = parse_macos_mdls_date("2026-05-08 19:12:30 +0000\n").unwrap();

        assert_eq!(parsed.to_rfc3339(), "2026-05-08T19:12:30+00:00");
        assert!(parse_macos_mdls_date("(null)").is_none());
    }

    #[test]
    fn detects_macos_app_store_receipt_management() {
        let dir = tempfile::tempdir().unwrap();
        let app_bundle = dir.path().join("Demo.app");
        let receipt_dir = app_bundle.join("Contents").join("_MASReceipt");
        fs::create_dir_all(&receipt_dir).unwrap();
        fs::write(receipt_dir.join("receipt"), "receipt").unwrap();
        let identity = AppIdentity::macos("Demo".to_string());

        assert_eq!(
            macos_management_source(&app_bundle, &AppSource::Local, false, &identity, None),
            AppManagementSource::AppStore
        );
        assert_eq!(
            macos_update_availability(&app_bundle, &AppSource::Local, false, &identity, None, None,),
            AppUpdateAvailability::NotChecked
        );
        assert_eq!(
            macos_management_source(&app_bundle, &AppSource::System, true, &identity, None),
            AppManagementSource::System
        );
        assert_eq!(
            macos_update_availability(&app_bundle, &AppSource::System, true, &identity, None, None,),
            AppUpdateAvailability::Unsupported
        );
    }

    #[test]
    fn parses_homebrew_cask_tokens_from_versions_and_outdated_output() {
        let tokens = parse_homebrew_cask_tokens(
            r#"google-chrome 124.0
visual-studio-code 1.99.0
raycast
"#,
        );

        assert!(tokens.contains("googlechrome"));
        assert!(tokens.contains("visualstudiocode"));
        assert!(tokens.contains("raycast"));

        let installed = parse_homebrew_installed_casks("google-chrome 124.0\nraycast\n");
        assert_eq!(
            installed
                .get("googlechrome")
                .and_then(|cask| cask.installed_version.as_deref()),
            Some("124.0")
        );
        assert_eq!(
            installed.get("raycast").map(|cask| cask.token.as_str()),
            Some("raycast")
        );
    }

    #[test]
    fn detects_homebrew_cask_management_and_update_availability() {
        let dir = tempfile::tempdir().unwrap();
        let app_bundle = dir.path().join("Google Chrome.app");
        fs::create_dir_all(&app_bundle).unwrap();
        let identity = AppIdentity::macos("Google Chrome".to_string());
        let snapshot = HomebrewCaskSnapshot {
            installed: BTreeMap::from([(
                normalize_app_match_key("google-chrome"),
                HomebrewCaskMetadata {
                    token: "google-chrome".to_string(),
                    installed_version: Some("124.0".to_string()),
                },
            )]),
            outdated: BTreeSet::from([normalize_app_match_key("google-chrome")]),
        };

        assert_eq!(
            macos_management_source(
                &app_bundle,
                &AppSource::Local,
                false,
                &identity,
                Some(&snapshot)
            ),
            AppManagementSource::PackageManager
        );
        assert_eq!(
            macos_update_availability(
                &app_bundle,
                &AppSource::Local,
                false,
                &identity,
                Some(&snapshot),
                None,
            ),
            AppUpdateAvailability::UpdateAvailable
        );
        let package = macos_package_metadata(
            &app_bundle,
            &AppSource::Local,
            false,
            &identity,
            None,
            Some(&snapshot),
            None,
        )
        .unwrap();
        assert_eq!(package.manager, AppPackageManager::HomebrewCask);
        assert_eq!(package.package_id, "google-chrome");
        assert_eq!(package.installed_version.as_deref(), Some("124.0"));
        assert_eq!(
            package.update_command.as_deref(),
            Some("brew upgrade --cask google-chrome")
        );
    }

    #[test]
    fn detects_homebrew_cask_from_json_artifact_alias() {
        let installed = parse_homebrew_installed_casks("anaconda 2024.10-1\n");
        let enriched = parse_homebrew_cask_info_json(
            r#"{
  "casks": [
    {
      "token": "anaconda",
      "name": ["Anaconda Distribution"],
      "version": "2024.10-1",
      "artifacts": [
        { "app": ["Anaconda-Navigator.app"] }
      ]
    }
  ]
}"#,
            installed,
        );
        let dir = tempfile::tempdir().unwrap();
        let app_bundle = dir.path().join("Anaconda-Navigator.app");
        fs::create_dir_all(&app_bundle).unwrap();
        let identity = AppIdentity::macos("Anaconda Navigator".to_string());
        let snapshot = HomebrewCaskSnapshot {
            installed: enriched,
            outdated: BTreeSet::from([normalize_app_match_key("anaconda")]),
        };

        assert_eq!(
            macos_management_source(
                &app_bundle,
                &AppSource::Local,
                false,
                &identity,
                Some(&snapshot)
            ),
            AppManagementSource::PackageManager
        );
        assert_eq!(
            macos_update_availability(
                &app_bundle,
                &AppSource::Local,
                false,
                &identity,
                Some(&snapshot),
                None,
            ),
            AppUpdateAvailability::UpdateAvailable
        );
        assert_eq!(
            macos_package_metadata(
                &app_bundle,
                &AppSource::Local,
                false,
                &identity,
                None,
                Some(&snapshot),
                None,
            )
            .unwrap()
            .package_id,
            "anaconda"
        );
    }

    #[test]
    fn detects_homebrew_cask_up_to_date_when_installed_not_outdated() {
        let dir = tempfile::tempdir().unwrap();
        let app_bundle = dir.path().join("Raycast.app");
        fs::create_dir_all(&app_bundle).unwrap();
        let identity = AppIdentity::macos("Raycast".to_string());
        let snapshot = HomebrewCaskSnapshot {
            installed: BTreeMap::from([(
                normalize_app_match_key("raycast"),
                HomebrewCaskMetadata {
                    token: "raycast".to_string(),
                    installed_version: Some("1.2.3".to_string()),
                },
            )]),
            outdated: BTreeSet::new(),
        };

        assert_eq!(
            macos_update_availability(
                &app_bundle,
                &AppSource::Local,
                false,
                &identity,
                Some(&snapshot),
                None,
            ),
            AppUpdateAvailability::UpToDate
        );
    }

    #[test]
    fn parses_app_store_adam_id_from_mdls_output() {
        assert_eq!(
            parse_macos_app_store_adam_id("123456789\n").as_deref(),
            Some("123456789")
        );
        assert!(parse_macos_app_store_adam_id("(null)\n").is_none());
        assert!(parse_macos_app_store_adam_id("not-an-id\n").is_none());
    }

    #[test]
    fn parses_app_store_lookup_versions() {
        let versions = parse_app_store_lookup_versions(
            r#"{
  "resultCount": 1,
  "results": [
    { "trackId": 123456789, "version": "2.4.1" }
  ]
}"#,
        )
        .unwrap();

        assert_eq!(versions.get("123456789").map(String::as_str), Some("2.4.1"));
        assert!(app_store_version_is_newer("2.4.0", "2.4.1"));
        assert!(!app_store_version_is_newer("2.4.1", "2.4.1"));
    }

    #[test]
    fn app_store_snapshot_provides_package_metadata_and_update_status() {
        let dir = tempfile::tempdir().unwrap();
        let app_bundle = dir.path().join("Store Demo.app");
        fs::create_dir_all(&app_bundle).unwrap();
        let snapshot = MacAppStoreSnapshot {
            apps_by_path: BTreeMap::from([(
                app_bundle.to_string_lossy().to_string(),
                MacAppStoreMetadata {
                    adam_id: "123456789".to_string(),
                    installed_version: Some("1.0".to_string()),
                    latest_version: Some("1.1".to_string()),
                },
            )]),
        };

        assert_eq!(
            snapshot.app_update_availability(&app_bundle),
            AppUpdateAvailability::UpdateAvailable
        );
        let package = snapshot.package_metadata(&app_bundle, Some("1.0")).unwrap();
        assert_eq!(package.manager, AppPackageManager::MacAppStore);
        assert_eq!(package.package_id, "123456789");
        assert_eq!(package.latest_version.as_deref(), Some("1.1"));
    }

    #[test]
    fn parses_linux_package_update_outputs() {
        let apt = parse_apt_upgradable_packages(
            r#"Listing...
firefox/jammy-updates 124.0 amd64 [upgradable from: 123.0]
code/stable 1.99 amd64 [upgradable from: 1.98]
"#,
        );
        let dnf = parse_dnf_upgradable_packages(
            r#"Last metadata expiration check: 0:01:00 ago.
firefox.x86_64 124.0 updates
org.gnome.Calculator.x86_64 45.0 updates
"#,
        );
        let pacman = parse_pacman_upgradable_packages(
            r#"firefox 123.0 -> 124.0
visual-studio-code-bin 1.98 -> 1.99
"#,
        );

        assert!(apt.contains_key("firefox"));
        assert!(apt.contains_key("code"));
        assert!(dnf.contains_key("firefox"));
        assert!(dnf.contains_key("orggnomecalculator"));
        assert!(pacman.contains_key("firefox"));
        assert!(pacman.contains_key("visualstudiocodebin"));
        assert_eq!(
            apt.get("code").map(|package| &package.manager),
            Some(&AppPackageManager::Apt)
        );
        assert_eq!(
            dnf.get("firefox")
                .map(|package| package.package_id.as_str()),
            Some("firefox")
        );
    }

    #[test]
    fn linux_update_availability_uses_desktop_candidates() {
        let desktop = parse_desktop_entry(
            r#"[Desktop Entry]
Type=Application
Name=Visual Studio Code
Exec=/usr/bin/code --unity-launch
"#,
        );
        let mut identity = AppIdentity::linux("Visual Studio Code".to_string());
        identity.desktop_id = Some("code".to_string());
        let updates = LinuxPackageUpdateSnapshot {
            upgradable_packages: BTreeMap::from([(
                normalize_app_match_key("code"),
                LinuxPackageMetadata {
                    manager: AppPackageManager::Apt,
                    package_id: "code".to_string(),
                },
            )]),
        };

        assert_eq!(
            linux_update_availability(&AppSource::System, &desktop, &identity, Some(&updates)),
            AppUpdateAvailability::UpdateAvailable
        );
        let package = linux_package_metadata(&desktop, &identity, Some(&updates)).unwrap();
        assert_eq!(package.manager, AppPackageManager::Apt);
        assert_eq!(package.package_id, "code");
        assert_eq!(
            package.detection_confidence,
            AppPackageDetectionConfidence::Fallback
        );
    }

    #[cfg(unix)]
    #[test]
    fn calculate_path_size_does_not_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let app_bundle = dir.path().join("Demo.app");
        fs::create_dir_all(&app_bundle).unwrap();
        fs::write(app_bundle.join("Info.plist"), "plist").unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("large.bin"), [0_u8; 32]).unwrap();
        std::os::unix::fs::symlink(&outside, app_bundle.join("LinkedData")).unwrap();

        assert_eq!(calculate_path_size(&app_bundle), 5);
    }
}
