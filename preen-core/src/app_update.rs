use serde::{Deserialize, Serialize};

use crate::app_uninstall::{AppPackageManager, InstalledApplication};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUpdatePlan {
    pub app_name: String,
    pub app_path: String,
    pub package_id: String,
    pub manager: AppPackageManager,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub command_preview: Vec<String>,
    pub executable: bool,
    pub confirms_update_on_success: bool,
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
            app_path: app.path.clone(),
            package_id: String::new(),
            manager: AppPackageManager::Unknown,
            installed_version: app.version.clone(),
            latest_version: None,
            command_preview: Vec::new(),
            executable: false,
            confirms_update_on_success: false,
            reason: Some(
                "no supported updater detected; executable now: Homebrew cask, Flatpak, Snap, Mac App Store native flow, Sparkle native flow"
                    .to_string(),
            ),
        };
    };

    let (command_preview, executable, confirms_update_on_success, reason) =
        update_command_for_package(
            &package.manager,
            &package.package_id,
            &app.path,
            package.update_command.as_deref(),
        );

    AppUpdatePlan {
        app_name,
        app_path: app.path.clone(),
        package_id: package.package_id.clone(),
        manager: package.manager.clone(),
        installed_version: package
            .installed_version
            .clone()
            .or_else(|| app.version.clone()),
        latest_version: package.latest_version.clone(),
        command_preview,
        executable,
        confirms_update_on_success,
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
    app_path: &str,
    inventory_command: Option<&str>,
) -> (Vec<String>, bool, bool, Option<String>) {
    if package_id.trim().is_empty() {
        return (
            Vec::new(),
            false,
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
            true,
            None,
        ),
        AppPackageManager::MacAppStore => (
            vec![
                "open".to_string(),
                "macappstore://showUpdatesPage".to_string(),
            ],
            true,
            false,
            None,
        ),
        AppPackageManager::Sparkle => (
            vec!["open".to_string(), app_path.to_string()],
            true,
            false,
            None,
        ),
        AppPackageManager::Flatpak => (
            vec![
                "flatpak".to_string(),
                "update".to_string(),
                "-y".to_string(),
                package_id.to_string(),
            ],
            true,
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
            true,
            None,
        ),
        AppPackageManager::Apt | AppPackageManager::Dnf | AppPackageManager::Pacman => (
            inventory_command
                .map(split_command_preview)
                .unwrap_or_else(Vec::new),
            false,
            false,
            Some("system package updates require an elevated update flow".to_string()),
        ),
        AppPackageManager::Unknown => (
            Vec::new(),
            false,
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
        assert!(plan.confirms_update_on_success);
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
    fn mac_app_store_plan_opens_native_update_flow() {
        let plan = build_update_plan_for_app(&app_with_manager(AppPackageManager::MacAppStore));

        assert!(plan.executable);
        assert!(!plan.confirms_update_on_success);
        assert_eq!(
            plan.command_preview,
            ["open", "macappstore://showUpdatesPage"]
        );
        assert!(plan.reason.is_none());
    }

    #[test]
    fn sparkle_plan_opens_native_update_flow() {
        let plan = build_update_plan_for_app(&app_with_manager(AppPackageManager::Sparkle));

        assert!(plan.executable);
        assert!(!plan.confirms_update_on_success);
        assert_eq!(plan.command_preview, ["open", "/Applications/Demo.app"]);
        assert!(plan.reason.is_none());
    }
}
