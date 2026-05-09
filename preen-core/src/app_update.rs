use serde::{Deserialize, Serialize};

use crate::app_uninstall::{AppPackageManager, InstalledApplication};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUpdatePlan {
    pub app_name: String,
    pub package_id: String,
    pub manager: AppPackageManager,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub command_preview: Vec<String>,
    pub executable: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUpdateBatchPlan {
    pub plans: Vec<AppUpdatePlan>,
}

impl AppUpdateBatchPlan {
    pub fn executable_plans(&self) -> impl Iterator<Item = &AppUpdatePlan> {
        self.plans.iter().filter(|plan| plan.executable)
    }

    pub fn is_empty(&self) -> bool {
        self.plans.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUpdateBatchResult {
    pub lines: Vec<String>,
    pub updated_apps: Vec<String>,
}

pub fn build_update_plan_for_app(app: &InstalledApplication) -> AppUpdatePlan {
    let app_name = app.identity.display_name.clone();
    let Some(package) = &app.package_metadata else {
        return AppUpdatePlan {
            app_name,
            package_id: String::new(),
            manager: AppPackageManager::Unknown,
            installed_version: app.version.clone(),
            latest_version: None,
            command_preview: Vec::new(),
            executable: false,
            reason: Some(
                "no supported executable updater detected; executable now: Homebrew cask, Flatpak, Snap; Mac App Store and Sparkle detection are native"
                    .to_string(),
            ),
        };
    };

    let (command_preview, executable, reason) = update_command_for_package(
        &package.manager,
        &package.package_id,
        package.update_command.as_deref(),
    );

    AppUpdatePlan {
        app_name,
        package_id: package.package_id.clone(),
        manager: package.manager.clone(),
        installed_version: package
            .installed_version
            .clone()
            .or_else(|| app.version.clone()),
        latest_version: package.latest_version.clone(),
        command_preview,
        executable,
        reason,
    }
}

pub fn build_update_batch_plan(applications: &[InstalledApplication]) -> AppUpdateBatchPlan {
    AppUpdateBatchPlan {
        plans: applications.iter().map(build_update_plan_for_app).collect(),
    }
}

fn update_command_for_package(
    manager: &AppPackageManager,
    package_id: &str,
    inventory_command: Option<&str>,
) -> (Vec<String>, bool, Option<String>) {
    if package_id.trim().is_empty() {
        return (
            Vec::new(),
            false,
            Some("package id is unavailable".to_string()),
        );
    }

    match manager {
        AppPackageManager::HomebrewCask => (
            vec![
                "brew".to_string(),
                "upgrade".to_string(),
                "--cask".to_string(),
                package_id.to_string(),
            ],
            true,
            None,
        ),
        AppPackageManager::MacAppStore => (
            inventory_command
                .map(split_command_preview)
                .unwrap_or_else(|| {
                    vec![
                        "app-store".to_string(),
                        "update".to_string(),
                        package_id.to_string(),
                    ]
                }),
            false,
            Some(
                "Mac App Store update detection is native; execution needs the App Store update helper"
                    .to_string(),
            ),
        ),
        AppPackageManager::Sparkle => (
            inventory_command
                .map(split_command_preview)
                .unwrap_or_else(|| {
                    vec![
                        "sparkle".to_string(),
                        "update".to_string(),
                        package_id.to_string(),
                    ]
                }),
            false,
            Some("Sparkle update detection is native; execution needs the Sparkle update helper".to_string()),
        ),
        AppPackageManager::Flatpak => (
            vec![
                "flatpak".to_string(),
                "update".to_string(),
                "-y".to_string(),
                package_id.to_string(),
            ],
            true,
            None,
        ),
        AppPackageManager::Snap => (
            vec![
                "snap".to_string(),
                "refresh".to_string(),
                package_id.to_string(),
            ],
            true,
            None,
        ),
        AppPackageManager::Apt | AppPackageManager::Dnf | AppPackageManager::Pacman => (
            inventory_command
                .map(split_command_preview)
                .unwrap_or_else(Vec::new),
            false,
            Some("system package updates require an elevated update flow".to_string()),
        ),
        AppPackageManager::Unknown => (
            Vec::new(),
            false,
            Some("package manager is unknown".to_string()),
        ),
    }
}

fn split_command_preview(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_uninstall::{
        AppIdentity, AppManagementSource, AppPackageDetectionConfidence, AppPackageMetadata,
        AppSource, AppUpdateAvailability,
    };

    fn app_with_manager(manager: AppPackageManager) -> InstalledApplication {
        InstalledApplication {
            identity: AppIdentity::macos("Demo"),
            path: "/Applications/Demo.app".to_string(),
            version: Some("1.0".to_string()),
            source: AppSource::Local,
            estimated_size: 0,
            last_used_at: None,
            management_source: AppManagementSource::PackageManager,
            update_availability: AppUpdateAvailability::UpdateAvailable,
            package_metadata: Some(AppPackageMetadata {
                manager,
                package_id: "demo".to_string(),
                installed_version: Some("1.0".to_string()),
                latest_version: Some("2.0".to_string()),
                update_command: None,
                detection_confidence: AppPackageDetectionConfidence::Exact,
            }),
            protected: false,
        }
    }

    #[test]
    fn homebrew_plan_is_executable() {
        let plan = build_update_plan_for_app(&app_with_manager(AppPackageManager::HomebrewCask));

        assert!(plan.executable);
        assert_eq!(plan.command_preview, ["brew", "upgrade", "--cask", "demo"]);
        assert_eq!(plan.latest_version.as_deref(), Some("2.0"));
    }

    #[test]
    fn apt_plan_is_not_executable_without_elevated_flow() {
        let plan = build_update_plan_for_app(&app_with_manager(AppPackageManager::Apt));

        assert!(!plan.executable);
        assert!(plan.reason.unwrap().contains("elevated"));
    }

    #[test]
    fn mac_app_store_plan_is_detectable_but_waits_for_native_helper() {
        let plan = build_update_plan_for_app(&app_with_manager(AppPackageManager::MacAppStore));

        assert!(!plan.executable);
        assert_eq!(plan.command_preview, ["app-store", "update", "demo"]);
        assert!(plan.reason.unwrap().contains("App Store update helper"));
    }

    #[test]
    fn sparkle_plan_is_detectable_but_waits_for_native_helper() {
        let plan = build_update_plan_for_app(&app_with_manager(AppPackageManager::Sparkle));

        assert!(!plan.executable);
        assert_eq!(plan.command_preview, ["sparkle", "update", "demo"]);
        assert!(plan.reason.unwrap().contains("Sparkle update helper"));
    }
}
