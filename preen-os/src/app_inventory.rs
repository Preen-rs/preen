use preen_core::app_uninstall::{AppIdentity, AppSource, InstalledApplication};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_DISCOVERED_APPS: usize = 400;

pub fn collect_installed_applications() -> Vec<InstalledApplication> {
    let mut apps = if cfg!(target_os = "macos") {
        collect_macos_applications()
    } else if cfg!(target_os = "linux") {
        collect_linux_applications()
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

pub fn collect_installed_application_names() -> Vec<String> {
    collect_installed_applications()
        .into_iter()
        .map(|app| app.identity.display_name)
        .collect()
}

fn collect_macos_applications() -> Vec<InstalledApplication> {
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
                estimated_size: calculate_path_size(&path),
                protected,
            });
        }
    }
    apps
}

fn collect_linux_applications() -> Vec<InstalledApplication> {
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
                estimated_size: calculate_path_size(&path),
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

fn calculate_path_size(path: &Path) -> u64 {
    fs::metadata(path)
        .map(|metadata| {
            if metadata.is_file() {
                metadata.len()
            } else {
                0
            }
        })
        .unwrap_or(0)
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
}
