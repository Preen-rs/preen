use serde::{Deserialize, Serialize};

use crate::app_uninstall::{AppPackageManager, InstalledApplication};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppUpdateExecutionMode {
    DirectCommand,
    NativeHelper,
    PrivilegedSystemPackage,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppUpdateRisk {
    UsesPrivateAppleFramework,
    UsesSparkleFramework,
    MayRequirePassword,
    MayQuitApplication,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppNativeUpdateRequest {
    pub schema_version: u32,
    pub provider: AppPackageManager,
    pub app_name: String,
    pub app_path: String,
    pub package_id: String,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub feed_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUpdatePlan {
    pub app_name: String,
    pub app_stable_id: String,
    pub app_path: String,
    pub package_id: String,
    pub manager: AppPackageManager,
    pub execution_mode: AppUpdateExecutionMode,
    pub risks: Vec<AppUpdateRisk>,
    pub native_request: Option<AppNativeUpdateRequest>,
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
    let app_stable_id = app.identity.stable_id(&app.path);
    let Some(package) = &app.package_metadata else {
        return AppUpdatePlan {
            app_name,
            app_stable_id,
            app_path: app.path.clone(),
            package_id: String::new(),
            manager: AppPackageManager::Unknown,
            execution_mode: AppUpdateExecutionMode::Unsupported,
            risks: Vec::new(),
            native_request: None,
            installed_version: app.version.clone(),
            latest_version: None,
            command_preview: Vec::new(),
            executable: false,
            confirms_update_on_success: false,
            reason: Some("no update executor is available for this app source".to_string()),
        };
    };

    let (command_preview, execution_mode, risks, executable, confirms_update_on_success, reason) =
        update_command_for_package(
            &package.manager,
            &package.package_id,
            package.update_command.as_deref(),
        );
    let native_request =
        matches!(execution_mode, AppUpdateExecutionMode::NativeHelper).then(|| {
            AppNativeUpdateRequest {
                schema_version: 1,
                provider: package.manager.clone(),
                app_name: app_name.clone(),
                app_path: app.path.clone(),
                package_id: package.package_id.clone(),
                installed_version: package
                    .installed_version
                    .clone()
                    .or_else(|| app.version.clone()),
                latest_version: package.latest_version.clone(),
                feed_url: app
                    .inventory_metadata
                    .as_ref()
                    .and_then(|metadata| metadata.sparkle_feed_url.clone()),
            }
        });

    AppUpdatePlan {
        app_name,
        app_stable_id,
        app_path: app.path.clone(),
        package_id: package.package_id.clone(),
        manager: package.manager.clone(),
        execution_mode,
        risks,
        native_request,
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
    inventory_command: Option<&str>,
) -> (
    Vec<String>,
    AppUpdateExecutionMode,
    Vec<AppUpdateRisk>,
    bool,
    bool,
    Option<String>,
) {
    if package_id.trim().is_empty() {
        return (
            Vec::new(),
            AppUpdateExecutionMode::Unsupported,
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
            AppUpdateExecutionMode::DirectCommand,
            Vec::new(),
            true,
            true,
            None,
        ),
        AppPackageManager::MacAppStore => (
            inventory_command
                .map(split_command_preview)
                .unwrap_or_else(Vec::new),
            AppUpdateExecutionMode::NativeHelper,
            vec![
                AppUpdateRisk::UsesPrivateAppleFramework,
                AppUpdateRisk::MayRequirePassword,
            ],
            true,
            true,
            None,
        ),
        AppPackageManager::Sparkle => (
            inventory_command
                .map(split_command_preview)
                .unwrap_or_else(Vec::new),
            AppUpdateExecutionMode::NativeHelper,
            vec![
                AppUpdateRisk::UsesSparkleFramework,
                AppUpdateRisk::MayQuitApplication,
            ],
            true,
            true,
            None,
        ),
        AppPackageManager::Flatpak => (
            vec![
                "flatpak".to_string(),
                "update".to_string(),
                "-y".to_string(),
                package_id.to_string(),
            ],
            AppUpdateExecutionMode::DirectCommand,
            Vec::new(),
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
            AppUpdateExecutionMode::DirectCommand,
            Vec::new(),
            true,
            true,
            None,
        ),
        AppPackageManager::Apt | AppPackageManager::Dnf | AppPackageManager::Pacman => (
            inventory_command
                .map(split_command_preview)
                .unwrap_or_else(Vec::new),
            AppUpdateExecutionMode::PrivilegedSystemPackage,
            vec![AppUpdateRisk::MayRequirePassword],
            false,
            false,
            Some("system package updates require an elevated update flow".to_string()),
        ),
        AppPackageManager::Unknown => (
            Vec::new(),
            AppUpdateExecutionMode::Unsupported,
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
            inventory_metadata: None,
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
    fn mac_app_store_plan_is_detectable_but_not_directly_executable() {
        let plan = build_update_plan_for_app(&app_with_manager(AppPackageManager::MacAppStore));

        assert!(plan.executable);
        assert_eq!(plan.execution_mode, AppUpdateExecutionMode::NativeHelper);
        assert!(plan.confirms_update_on_success);
        assert!(
            plan.risks
                .contains(&AppUpdateRisk::UsesPrivateAppleFramework)
        );
        assert!(plan.native_request.is_some());
        assert!(plan.command_preview.is_empty());
        assert!(plan.reason.is_none());
    }

    #[test]
    fn sparkle_plan_is_detectable_but_not_directly_executable() {
        let plan = build_update_plan_for_app(&app_with_manager(AppPackageManager::Sparkle));

        assert!(plan.executable);
        assert_eq!(plan.execution_mode, AppUpdateExecutionMode::NativeHelper);
        assert!(plan.confirms_update_on_success);
        assert!(plan.risks.contains(&AppUpdateRisk::UsesSparkleFramework));
        assert!(plan.native_request.is_some());
        assert!(plan.command_preview.is_empty());
        assert!(plan.reason.is_none());
    }
}
