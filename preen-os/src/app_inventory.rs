use chrono::{DateTime, Utc};
use preen_core::app_uninstall::{
    AppIdentity, AppManagementSource, AppSource, AppUpdateAvailability, InstalledApplication,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

const MAX_DISCOVERED_APPS: usize = 400;

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

    let mut apps = Vec::new();
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

            apps.push(InstalledApplication {
                identity,
                path: path.to_string_lossy().to_string(),
                version: plist
                    .get("CFBundleShortVersionString")
                    .or_else(|| plist.get("CFBundleVersion"))
                    .cloned(),
                source: source.clone(),
                estimated_size: estimated_path_size(&path, include_sizes),
                last_used_at: if include_sizes {
                    macos_last_used_at(&path).or_else(|| filesystem_last_used_at(&path))
                } else {
                    None
                },
                management_source: macos_management_source(&path, &source, protected),
                update_availability: macos_update_availability(&path, &source, protected),
                protected,
            });
        }
    }
    apps
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
                management_source: linux_management_source(&source),
                update_availability: linux_update_availability(&source),
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
    let output = Command::new("mdls")
        .arg("-raw")
        .arg("-name")
        .arg("kMDItemLastUsedDate")
        .arg(path)
        .output()
        .ok()?;
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
) -> AppManagementSource {
    if protected || matches!(source, AppSource::System) {
        return AppManagementSource::System;
    }
    if path.join("Contents/_MASReceipt/receipt").is_file() {
        return AppManagementSource::AppStore;
    }
    AppManagementSource::Manual
}

fn macos_update_availability(
    path: &Path,
    source: &AppSource,
    protected: bool,
) -> AppUpdateAvailability {
    match macos_management_source(path, source, protected) {
        AppManagementSource::System => AppUpdateAvailability::Unsupported,
        AppManagementSource::AppStore => AppUpdateAvailability::NotChecked,
        AppManagementSource::Manual => AppUpdateAvailability::Unsupported,
        AppManagementSource::PackageManager | AppManagementSource::Unknown => {
            AppUpdateAvailability::Unknown
        }
    }
}

fn linux_management_source(source: &AppSource) -> AppManagementSource {
    match source {
        AppSource::System | AppSource::Local => AppManagementSource::PackageManager,
        AppSource::User => AppManagementSource::Manual,
        AppSource::Unknown => AppManagementSource::Unknown,
    }
}

fn linux_update_availability(source: &AppSource) -> AppUpdateAvailability {
    match linux_management_source(source) {
        AppManagementSource::PackageManager => AppUpdateAvailability::NotChecked,
        AppManagementSource::Manual => AppUpdateAvailability::Unsupported,
        AppManagementSource::Unknown => AppUpdateAvailability::Unknown,
        AppManagementSource::System | AppManagementSource::AppStore => {
            AppUpdateAvailability::Unknown
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

        assert_eq!(
            macos_management_source(&app_bundle, &AppSource::Local, false),
            AppManagementSource::AppStore
        );
        assert_eq!(
            macos_update_availability(&app_bundle, &AppSource::Local, false),
            AppUpdateAvailability::NotChecked
        );
        assert_eq!(
            macos_management_source(&app_bundle, &AppSource::System, true),
            AppManagementSource::System
        );
        assert_eq!(
            macos_update_availability(&app_bundle, &AppSource::System, true),
            AppUpdateAvailability::Unsupported
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
