use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppPlatform {
    Macos,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppIdentity {
    pub display_name: String,
    pub platform: AppPlatform,
    pub bundle_identifier: Option<String>,
    pub desktop_id: Option<String>,
}

impl AppIdentity {
    pub fn macos(display_name: impl Into<String>) -> Self {
        Self {
            display_name: display_name.into(),
            platform: AppPlatform::Macos,
            bundle_identifier: None,
            desktop_id: None,
        }
    }

    pub fn linux(display_name: impl Into<String>) -> Self {
        Self {
            display_name: display_name.into(),
            platform: AppPlatform::Linux,
            bundle_identifier: None,
            desktop_id: None,
        }
    }

    pub fn primary_match_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        push_normalized_key(&mut keys, &self.display_name);
        if let Some(bundle_identifier) = &self.bundle_identifier {
            push_normalized_key(&mut keys, bundle_identifier);
            if let Some(last) = bundle_identifier.rsplit('.').next() {
                push_normalized_key(&mut keys, last);
            }
        }
        if let Some(desktop_id) = &self.desktop_id {
            push_normalized_key(&mut keys, desktop_id);
        }
        keys
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppSource {
    System,
    User,
    Local,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledApplication {
    pub identity: AppIdentity,
    pub path: String,
    pub version: Option<String>,
    pub source: AppSource,
    pub estimated_size: u64,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RelatedPathKind {
    ApplicationBundle,
    DesktopEntry,
    Cache,
    Preference,
    Log,
    Container,
    Support,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedPath {
    pub path: String,
    pub kind: RelatedPathKind,
    pub estimated_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UninstallDisposition {
    Trash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallPlan {
    pub identity: AppIdentity,
    pub paths: Vec<RelatedPath>,
    pub disposition: UninstallDisposition,
    pub protected: bool,
}

impl UninstallPlan {
    pub fn trash(identity: AppIdentity, paths: Vec<RelatedPath>) -> Self {
        Self::trash_with_protection(identity, paths, false)
    }

    pub fn trash_with_protection(
        identity: AppIdentity,
        paths: Vec<RelatedPath>,
        protected: bool,
    ) -> Self {
        Self {
            identity,
            paths,
            disposition: UninstallDisposition::Trash,
            protected,
        }
    }

    pub fn target_paths(&self) -> Vec<String> {
        self.paths.iter().map(|item| item.path.clone()).collect()
    }

    pub fn estimated_size(&self) -> u64 {
        self.paths
            .iter()
            .map(|item| item.estimated_size)
            .fold(0_u64, u64::saturating_add)
    }
}

pub fn normalize_app_match_key(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let trimmed = lower
        .strip_suffix(".app")
        .or_else(|| lower.strip_suffix(".desktop"))
        .or_else(|| lower.strip_suffix(".plist"))
        .unwrap_or(&lower);
    trimmed
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn push_normalized_key(keys: &mut Vec<String>, value: &str) {
    let normalized = normalize_app_match_key(value);
    if normalized.len() >= 3 && !keys.contains(&normalized) {
        keys.push(normalized);
    }
}

pub fn path_name_matches_app(path_name: &str, keys: &[String]) -> bool {
    let normalized = normalize_app_match_key(path_name);
    keys.iter()
        .any(|key| normalized == *key || (key.len() >= 5 && normalized.contains(key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_common_app_suffixes() {
        assert_eq!(normalize_app_match_key("Demo App.app"), "demoapp");
        assert_eq!(normalize_app_match_key("demo.desktop"), "demo");
        assert_eq!(
            normalize_app_match_key("com.example.Demo.plist"),
            "comexampledemo"
        );
    }

    #[test]
    fn identity_builds_deduplicated_keys() {
        let mut identity = AppIdentity::macos("Demo");
        identity.bundle_identifier = Some("com.example.Demo".to_string());

        assert_eq!(
            identity.primary_match_keys(),
            vec!["demo".to_string(), "comexampledemo".to_string()]
        );
    }

    #[test]
    fn uninstall_plan_reports_targets_and_size() {
        let plan = UninstallPlan::trash(
            AppIdentity::linux("Demo"),
            vec![
                RelatedPath {
                    path: "/tmp/a".to_string(),
                    kind: RelatedPathKind::Cache,
                    estimated_size: 3,
                },
                RelatedPath {
                    path: "/tmp/b".to_string(),
                    kind: RelatedPathKind::Log,
                    estimated_size: 4,
                },
            ],
        );

        assert_eq!(
            plan.target_paths(),
            vec!["/tmp/a".to_string(), "/tmp/b".to_string()]
        );
        assert_eq!(plan.estimated_size(), 7);
        assert_eq!(plan.disposition, UninstallDisposition::Trash);
        assert!(!plan.protected);
    }

    #[test]
    fn uninstall_plan_can_mark_protected_apps() {
        let plan =
            UninstallPlan::trash_with_protection(AppIdentity::macos("Preview"), Vec::new(), true);

        assert!(plan.protected);
    }

    #[test]
    fn installed_application_carries_identity_and_source() {
        let app = InstalledApplication {
            identity: AppIdentity::macos("Preview"),
            path: "/System/Applications/Preview.app".to_string(),
            version: Some("11.0".to_string()),
            source: AppSource::System,
            estimated_size: 42,
            protected: true,
        };

        assert_eq!(app.identity.display_name, "Preview");
        assert!(app.protected);
        assert_eq!(app.source, AppSource::System);
    }

    #[test]
    fn path_name_matching_allows_long_contained_keys_only() {
        assert!(path_name_matches_app(
            "com.google.Chrome.plist",
            &["chrome".to_string()]
        ));
        assert!(!path_name_matches_app(
            "com.example.ssh-helper",
            &["ssh".to_string()]
        ));
    }
}
