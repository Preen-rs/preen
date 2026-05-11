use preen_core::dashboard::DashboardSnapshot;
use preen_core::performance_view::{
    PerformanceAnalyzeOutput, PerformanceOptimizationTask, PerformanceOptimizeResult,
    PerformanceOptimizeSelection, PerformanceTaskDetail, PerformanceTaskRisk,
    PerformanceTaskTarget, PerformanceViewModel,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Duration, Instant};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

pub fn analyze(snapshot: &DashboardSnapshot) -> PerformanceAnalyzeOutput {
    let model = PerformanceViewModel::from_snapshot(snapshot);
    let details = model
        .optimization_tasks
        .iter()
        .map(|task| detail_for_task(task, snapshot))
        .collect();
    PerformanceAnalyzeOutput { model, details }
}

pub fn execute(
    snapshot: &DashboardSnapshot,
    details: &[PerformanceTaskDetail],
    selections: Vec<PerformanceOptimizeSelection>,
) -> PerformanceOptimizeResult {
    let detail_by_id = details
        .iter()
        .map(|detail| (detail.task_id.as_str(), detail))
        .collect::<BTreeMap<_, _>>();
    let mut lines = Vec::new();
    let mut completed_task_ids = Vec::new();

    if selections.is_empty() {
        return PerformanceOptimizeResult {
            lines: vec!["no optimization task selected".to_string()],
            completed_task_ids,
        };
    }

    for selection in selections {
        let target_ids = selection
            .target_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let result = match selection.task_id.as_str() {
            "inspect_top_processes" => inspect_top_processes(snapshot),
            "flush_dns_cache" => flush_dns_cache(),
            "sync_filesystem_buffers" => sync_filesystem_buffers(),
            "memory_pressure_relief" => memory_pressure_relief(),
            "inspect_login_items" => {
                let detail = detail_by_id.get(selection.task_id.as_str()).copied();
                update_login_items(detail, &target_ids)
            }
            "defer_heavy_maintenance" => vec![
                "skipped: heavy maintenance should run later when system pressure is lower"
                    .to_string(),
            ],
            other => vec![format!("skipped: unknown optimization task {other}")],
        };

        let ok = result.iter().any(|line| {
            line.starts_with("done:")
                || line.starts_with("removed:")
                || line.starts_with("inspected:")
        });
        if ok {
            completed_task_ids.push(selection.task_id);
        }
        lines.extend(result);
    }

    PerformanceOptimizeResult {
        lines,
        completed_task_ids,
    }
}

fn detail_for_task(
    task: &PerformanceOptimizationTask,
    snapshot: &DashboardSnapshot,
) -> PerformanceTaskDetail {
    match task.id.as_str() {
        "inspect_top_processes" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: "Review CPU and memory-heavy processes before changing the system".to_string(),
            notes: snapshot
                .metrics
                .top_processes
                .iter()
                .take(10)
                .map(|process| {
                    format!(
                        "{}: cpu {:.1}% | memory {:.1}%",
                        process.name, process.cpu_pct, process.memory_pct
                    )
                })
                .collect(),
            targets: Vec::new(),
        },
        "inspect_login_items" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: "Select startup agents that should be moved to Trash".to_string(),
            notes: vec![
                "User LaunchAgents can be removed directly.".to_string(),
                "System LaunchAgents and LaunchDaemons are shown but require a future privileged helper."
                    .to_string(),
            ],
            targets: login_item_targets(),
        },
        "flush_dns_cache" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Refreshes local DNS resolver state.".to_string(),
                "Does not delete user data.".to_string(),
            ],
            targets: Vec::new(),
        },
        "sync_filesystem_buffers" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec!["Asks the OS to flush pending filesystem buffers.".to_string()],
            targets: Vec::new(),
        },
        "memory_pressure_relief" => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![
                "Runs the OS-native memory relief command when available.".to_string(),
                "Best used after closing unnecessary applications.".to_string(),
            ],
            targets: Vec::new(),
        },
        _ => PerformanceTaskDetail {
            task_id: task.id.clone(),
            title: task.label.clone(),
            summary: task.description.clone(),
            notes: vec![task.reason.clone()],
            targets: Vec::new(),
        },
    }
}

fn inspect_top_processes(snapshot: &DashboardSnapshot) -> Vec<String> {
    let mut lines = vec!["inspected: top process pressure".to_string()];
    for process in snapshot.metrics.top_processes.iter().take(10) {
        lines.push(format!(
            "{}: cpu {:.1}% | memory {:.1}%",
            process.name, process.cpu_pct, process.memory_pct
        ));
    }
    if lines.len() == 1 {
        lines.push("no process sample available".to_string());
    }
    lines
}

fn flush_dns_cache() -> Vec<String> {
    let mut lines = vec!["checking: flushing DNS cache".to_string()];
    match std::env::consts::OS {
        "macos" => {
            lines.extend(run_command("dscacheutil", &["-flushcache"]));
            lines.extend(run_command("killall", &["-HUP", "mDNSResponder"]));
        }
        "linux" => {
            lines.extend(run_command("resolvectl", &["flush-caches"]));
        }
        _ => lines.push("skipped: DNS cache flush is not supported on this OS yet".to_string()),
    }
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: DNS cache refreshed".to_string());
    }
    lines
}

fn sync_filesystem_buffers() -> Vec<String> {
    let mut lines = vec!["checking: syncing filesystem buffers".to_string()];
    lines.extend(run_command("sync", &[]));
    if lines.iter().any(|line| line.starts_with("done:")) {
        lines.push("done: filesystem buffers synced".to_string());
    }
    lines
}

fn memory_pressure_relief() -> Vec<String> {
    let mut lines = vec!["checking: memory pressure relief".to_string()];
    if std::env::consts::OS != "macos" {
        lines.push("skipped: memory pressure relief is not supported on this OS yet".to_string());
        return lines;
    }
    for command in ["/usr/bin/purge", "/usr/sbin/purge"] {
        if Path::new(command).exists() {
            lines.extend(run_command(command, &[]));
            if lines.iter().any(|line| line.starts_with("done:")) {
                lines.push("done: memory pressure relief requested".to_string());
            }
            return lines;
        }
    }
    lines.push("skipped: purge command is not available".to_string());
    lines
}

fn update_login_items(
    detail: Option<&PerformanceTaskDetail>,
    selected_target_ids: &BTreeSet<String>,
) -> Vec<String> {
    let Some(detail) = detail else {
        return vec!["failed: login item detail is unavailable".to_string()];
    };
    if selected_target_ids.is_empty() {
        return vec!["skipped: no login item selected".to_string()];
    }

    let mut lines = Vec::new();
    for target in &detail.targets {
        if !selected_target_ids.contains(&target.id) {
            continue;
        }
        let Some(path) = target.path.as_deref().map(Path::new) else {
            lines.push(format!("skipped: {} has no path", target.label));
            continue;
        };
        if target.requires_admin {
            lines.push(format!(
                "skipped: {} requires a privileged helper",
                target.label
            ));
            continue;
        }
        if !is_user_launch_agent(path) {
            lines.push(format!(
                "skipped: {} is outside user LaunchAgents",
                target.label
            ));
            continue;
        }
        let _ = bootout_launch_agent(path);
        match trash::delete(path) {
            Ok(()) => lines.push(format!("removed: {}", target.label)),
            Err(error) => lines.push(format!("failed: {} ({error})", target.label)),
        }
    }
    if lines.is_empty() {
        lines.push("skipped: selected login items were not found".to_string());
    }
    lines
}

fn login_item_targets() -> Vec<PerformanceTaskTarget> {
    let mut targets = Vec::new();
    for root in login_item_roots() {
        let Ok(entries) = fs::read_dir(&root.path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("plist") {
                continue;
            }
            let fallback_label = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("login item")
                .to_string();
            let info = read_launch_plist_info(&path);
            let launch_label = info.label.as_deref().unwrap_or(&fallback_label);
            let label = human_launch_label(launch_label, info.executable.as_deref());
            let description =
                launch_item_description(&root, launch_label, info.executable.as_deref());
            targets.push(PerformanceTaskTarget {
                id: stable_target_id(&path),
                label,
                description,
                path: Some(path.to_string_lossy().into_owned()),
                selected_by_default: false,
                requires_admin: root.requires_admin,
                risk: if root.requires_admin {
                    PerformanceTaskRisk::Medium
                } else {
                    PerformanceTaskRisk::Low
                },
            });
        }
    }
    targets.sort_by(|left, right| {
        left.requires_admin
            .cmp(&right.requires_admin)
            .then_with(|| left.label.cmp(&right.label))
    });
    targets
}

#[derive(Debug, Default)]
struct LaunchPlistInfo {
    label: Option<String>,
    executable: Option<String>,
}

fn read_launch_plist_info(path: &Path) -> LaunchPlistInfo {
    let text = fs::read_to_string(path).ok();
    let label = text
        .as_deref()
        .and_then(|content| plist_string_value(content, "Label"))
        .or_else(|| plutil_extract(path, "Label"));
    let executable = text
        .as_deref()
        .and_then(|content| {
            plist_array_first_string(content, "ProgramArguments")
                .or_else(|| plist_string_value(content, "Program"))
        })
        .or_else(|| plutil_extract(path, "ProgramArguments.0"))
        .or_else(|| plutil_extract(path, "Program"));

    LaunchPlistInfo { label, executable }
}

fn plist_string_value(content: &str, key: &str) -> Option<String> {
    let key_marker = format!("<key>{key}</key>");
    let after_key = content.split(&key_marker).nth(1)?;
    let start = after_key.find("<string>")? + "<string>".len();
    let end = after_key[start..].find("</string>")? + start;
    Some(unescape_plist_string(&after_key[start..end])).filter(|value| !value.trim().is_empty())
}

fn plist_array_first_string(content: &str, key: &str) -> Option<String> {
    let key_marker = format!("<key>{key}</key>");
    let after_key = content.split(&key_marker).nth(1)?;
    let array_start = after_key.find("<array>")? + "<array>".len();
    let array_end = after_key[array_start..].find("</array>")? + array_start;
    let array_content = &after_key[array_start..array_end];
    let start = array_content.find("<string>")? + "<string>".len();
    let end = array_content[start..].find("</string>")? + start;
    Some(unescape_plist_string(&array_content[start..end])).filter(|value| !value.trim().is_empty())
}

fn unescape_plist_string(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .trim()
        .to_string()
}

fn plutil_extract(path: &Path, key_path: &str) -> Option<String> {
    if std::env::consts::OS != "macos" {
        return None;
    }
    let output = ProcessCommand::new("plutil")
        .args(["-extract", key_path, "raw", "-o", "-"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn launch_item_description(
    root: &LoginItemRoot,
    launch_label: &str,
    executable: Option<&str>,
) -> String {
    let mut parts = vec![root.label.to_string(), format!("id: {launch_label}")];
    if let Some(executable) = executable
        .map(clean_launch_executable)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("target: {executable}"));
    }
    parts.join(" | ")
}

fn clean_launch_executable(value: &str) -> String {
    value
        .strip_prefix("file://")
        .unwrap_or(value)
        .trim_matches('"')
        .to_string()
}

fn human_launch_label(launch_label: &str, executable: Option<&str>) -> String {
    let normalized = launch_label.to_ascii_lowercase();
    for (prefix, label) in known_launch_labels() {
        if normalized == *prefix || normalized.starts_with(prefix) {
            return label.to_string();
        }
    }

    let from_label = humanize_identifier(launch_label);
    if !from_label.eq_ignore_ascii_case("Helper")
        && !from_label.eq_ignore_ascii_case("Agent")
        && !from_label.eq_ignore_ascii_case("Service")
    {
        return from_label;
    }

    executable
        .and_then(|value| Path::new(value).file_stem())
        .and_then(|value| value.to_str())
        .map(humanize_identifier)
        .unwrap_or_else(|| "Login Item".to_string())
}

fn known_launch_labels() -> &'static [(&'static str, &'static str)] {
    &[
        ("com.apple", "Apple"),
        ("com.google.googleupdater", "Google Updater"),
        ("com.google.keystone", "Google Keystone"),
        ("com.jetbrains.toolbox", "JetBrains Toolbox"),
        ("com.macpaw.cleanmymac", "CleanMyMac"),
        ("com.openai.atlas", "OpenAI Atlas"),
        ("org.mozilla.firefox", "Firefox"),
        ("com.microsoft", "Microsoft"),
        ("com.docker", "Docker"),
        ("com.spotify", "Spotify"),
        ("com.tinyspeck.slackmacgap", "Slack"),
        ("us.zoom", "Zoom"),
    ]
}

fn humanize_identifier(value: &str) -> String {
    let mut pieces = value
        .trim_end_matches(".plist")
        .split(|ch: char| ch == '.' || ch == '_' || ch == '-' || ch == ' ')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();

    let junk_prefixes = ["com", "org", "net", "io", "dev", "app", "homebrew", "mxcl"];
    while pieces
        .first()
        .map(|part| junk_prefixes.contains(&part.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
    {
        pieces.remove(0);
    }

    let junk_suffixes = [
        "agent",
        "daemon",
        "helper",
        "helpers",
        "service",
        "xpc",
        "xpcservice",
        "updater",
        "update",
        "wake",
        "launcher",
        "login",
        "loginitem",
        "installer",
        "uninstaller",
        "background",
    ];
    while pieces
        .last()
        .map(|part| junk_suffixes.contains(&part.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
    {
        pieces.pop();
    }

    if pieces.is_empty() {
        return "Login Item".to_string();
    }

    pieces
        .into_iter()
        .map(|piece| titleize_identifier_piece(&piece))
        .collect::<Vec<_>>()
        .join(" ")
}

fn titleize_identifier_piece(piece: &str) -> String {
    if piece
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        && piece.len() > 1
    {
        return piece.to_string();
    }
    let mut out = String::new();
    let mut previous_lower = false;
    for ch in piece.chars() {
        if ch.is_ascii_uppercase() && previous_lower {
            out.push(' ');
        }
        out.push(ch);
        previous_lower = ch.is_ascii_lowercase();
    }
    out.split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

struct LoginItemRoot {
    label: &'static str,
    path: PathBuf,
    requires_admin: bool,
}

fn login_item_roots() -> Vec<LoginItemRoot> {
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(LoginItemRoot {
            label: "User LaunchAgent",
            path: PathBuf::from(home).join("Library").join("LaunchAgents"),
            requires_admin: false,
        });
    }
    if std::env::consts::OS == "macos" {
        roots.push(LoginItemRoot {
            label: "Global LaunchAgent",
            path: PathBuf::from("/Library/LaunchAgents"),
            requires_admin: true,
        });
        roots.push(LoginItemRoot {
            label: "System LaunchDaemon",
            path: PathBuf::from("/Library/LaunchDaemons"),
            requires_admin: true,
        });
    }
    roots
}

fn stable_target_id(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn is_user_launch_agent(path: &Path) -> bool {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return false;
    };
    path.starts_with(home.join("Library").join("LaunchAgents"))
}

fn bootout_launch_agent(path: &Path) -> Vec<String> {
    let uid = ProcessCommand::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(uid) = uid else {
        return vec!["warning: could not resolve uid for launchctl bootout".to_string()];
    };
    run_command(
        "launchctl",
        &["bootout", &format!("gui/{uid}"), &path.to_string_lossy()],
    )
}

fn run_command(command: &str, args: &[&str]) -> Vec<String> {
    let mut process = ProcessCommand::new(command);
    process.args(args);
    let start = Instant::now();
    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) => return vec![format!("failed: {command} ({error})")],
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return vec![format!("done: {command}")];
                }
                return vec![format!("failed: {command} exited with {status}")];
            }
            Ok(None) if start.elapsed() >= COMMAND_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return vec![format!("failed: {command} timed out")];
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(error) => return vec![format!("failed: {command} ({error})")],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_launch_label_prefers_known_app_names() {
        assert_eq!(
            human_launch_label("com.google.keystone.agent", None),
            "Google Keystone"
        );
        assert_eq!(
            human_launch_label("com.macpaw.CleanMyMac5.Updater", None),
            "CleanMyMac"
        );
        assert_eq!(
            human_launch_label("com.openai.atlas.update-helper", None),
            "OpenAI Atlas"
        );
    }

    #[test]
    fn human_launch_label_falls_back_to_meaningful_bundle_segment() {
        assert_eq!(human_launch_label("homebrew.mxcl.mailpit", None), "Mailpit");
        assert_eq!(
            human_launch_label("com.example.cool-app.helper", None),
            "Example Cool App"
        );
    }

    #[test]
    fn launch_plist_xml_parser_reads_label_and_program_arguments() {
        let content = r#"
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.example.cool-app.helper</string>
            <key>ProgramArguments</key>
            <array>
                <string>/Applications/Cool App.app/Contents/MacOS/Cool App</string>
                <string>--background</string>
            </array>
        </dict>
        </plist>
        "#;

        assert_eq!(
            plist_string_value(content, "Label").as_deref(),
            Some("com.example.cool-app.helper")
        );
        assert_eq!(
            plist_array_first_string(content, "ProgramArguments").as_deref(),
            Some("/Applications/Cool App.app/Contents/MacOS/Cool App")
        );
    }
}
