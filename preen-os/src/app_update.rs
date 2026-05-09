use preen_core::app_uninstall::{AppPackageManager, AppUpdateAvailability, InstalledApplication};
use preen_core::app_update::{AppUpdateBatchResult, AppUpdatePlan, build_update_batch_plan};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const APP_UPDATE_COMMAND_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub fn execute_application_updates(
    applications: Vec<InstalledApplication>,
) -> Result<AppUpdateBatchResult, String> {
    if applications.is_empty() {
        return Err("no application selected for update".to_string());
    }

    let plan = build_update_batch_plan(&applications);
    if plan.is_empty() {
        return Err("no application selected for update".to_string());
    }

    let mut lines = Vec::new();
    let mut updated_apps = Vec::new();

    for update in plan.plans {
        if !update.executable {
            let reason = update
                .reason
                .as_deref()
                .unwrap_or("update is not executable yet");
            lines.push(format!("skipped: {} ({reason})", update.app_name));
            continue;
        }

        match execute_update_plan(&update) {
            Ok(output) if output.status.success() => {
                if update.confirms_update_on_success {
                    updated_apps.push(update.app_name.clone());
                    lines.push(format!(
                        "updated: {} via {}",
                        update.app_name,
                        update_manager_label(&update.manager)
                    ));
                } else {
                    lines.push(format!(
                        "opened: {} native update flow via {}",
                        update.app_name,
                        update_manager_label(&update.manager)
                    ));
                    lines.push("  finish the updater prompt, then run reanalyze".to_string());
                }
                append_command_output(&mut lines, &output);
            }
            Ok(output) => {
                lines.push(format!(
                    "failed: {} via {} (exit {:?})",
                    update.app_name,
                    update_manager_label(&update.manager),
                    output.status.code()
                ));
                append_command_output(&mut lines, &output);
            }
            Err(error) => {
                lines.push(format!("failed: {} ({error})", update.app_name));
            }
        }
    }

    if lines.is_empty() {
        return Err("no executable update plan found".to_string());
    }

    Ok(AppUpdateBatchResult {
        lines,
        updated_apps,
    })
}

pub fn applications_with_available_updates(
    applications: Vec<InstalledApplication>,
) -> Vec<InstalledApplication> {
    applications
        .into_iter()
        .filter(|app| app.update_availability == AppUpdateAvailability::UpdateAvailable)
        .collect()
}

fn execute_update_plan(plan: &AppUpdatePlan) -> Result<Output, String> {
    let Some(program_name) = plan.command_preview.first() else {
        return Err("update command is empty".to_string());
    };
    let program = executable_for_update_manager(&plan.manager, program_name)?;
    let mut command = Command::new(program);
    command.args(plan.command_preview.iter().skip(1));
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    match plan.manager {
        AppPackageManager::HomebrewCask => {
            command.env("HOMEBREW_NO_AUTO_UPDATE", "1");
            command.env("NONINTERACTIVE", "1");
        }
        AppPackageManager::Flatpak => {
            command.env("FLATPAK_SYSTEM_HELPER_ON_SESSION", "1");
        }
        _ => {}
    }
    run_command_with_timeout(command, APP_UPDATE_COMMAND_TIMEOUT)
        .ok_or_else(|| "update command timed out".to_string())
}

fn executable_for_update_manager(
    manager: &AppPackageManager,
    program_name: &str,
) -> Result<PathBuf, String> {
    let paths = match manager {
        AppPackageManager::HomebrewCask => &["/opt/homebrew/bin/brew", "/usr/local/bin/brew"][..],
        AppPackageManager::Flatpak => &["/usr/bin/flatpak", "/usr/local/bin/flatpak"][..],
        AppPackageManager::Snap => &["/usr/bin/snap", "/snap/bin/snap"][..],
        _ => &[][..],
    };
    find_executable_in_common_paths(program_name, paths)
        .ok_or_else(|| format!("{program_name} executable not found"))
}

fn append_command_output(lines: &mut Vec<String>, output: &Output) {
    for raw in String::from_utf8_lossy(&output.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&output.stderr).lines())
    {
        let line = raw.trim();
        if !line.is_empty() {
            lines.push(format!("  {line}"));
        }
    }
}

fn update_manager_label(manager: &AppPackageManager) -> &'static str {
    match manager {
        AppPackageManager::HomebrewCask => "Homebrew cask",
        AppPackageManager::MacAppStore => "Mac App Store",
        AppPackageManager::Sparkle => "Sparkle",
        AppPackageManager::Apt => "APT",
        AppPackageManager::Dnf => "DNF",
        AppPackageManager::Pacman => "pacman",
        AppPackageManager::Flatpak => "Flatpak",
        AppPackageManager::Snap => "Snap",
        AppPackageManager::Unknown => "unknown",
    }
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
            .find(|candidate| is_executable_file(candidate))
    })
}

fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn run_command_with_timeout(mut command: Command, timeout: Duration) -> Option<Output> {
    let mut child = command.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use preen_core::app_uninstall::{
        AppIdentity, AppManagementSource, AppPackageDetectionConfidence, AppPackageMetadata,
        AppSource,
    };

    fn updateable_app(name: &str) -> InstalledApplication {
        InstalledApplication {
            identity: AppIdentity::macos(name),
            path: format!("/Applications/{name}.app"),
            version: Some("1.0".to_string()),
            inventory_metadata: None,
            source: AppSource::Local,
            estimated_size: 0,
            last_used_at: None,
            management_source: AppManagementSource::PackageManager,
            update_availability: AppUpdateAvailability::UpdateAvailable,
            package_metadata: Some(AppPackageMetadata {
                manager: AppPackageManager::Apt,
                package_id: name.to_ascii_lowercase(),
                installed_version: Some("1.0".to_string()),
                latest_version: Some("2.0".to_string()),
                update_command: None,
                detection_confidence: AppPackageDetectionConfidence::Fallback,
            }),
            protected: false,
        }
    }

    #[test]
    fn filters_apps_without_available_updates() {
        let mut up_to_date = updateable_app("Keep");
        up_to_date.update_availability = AppUpdateAvailability::UpToDate;

        let apps = applications_with_available_updates(vec![updateable_app("Demo"), up_to_date]);

        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].identity.display_name, "Demo");
    }
}
