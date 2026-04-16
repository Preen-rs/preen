use crate::model::{ActiveView, AppState, DashboardSnapshot};
use preen_core::check_list_view::CheckListView;
use preen_core::plugin_list_view::PluginListView;
use ratatui::text::Line;

use super::dashboard;
use super::format::{short_rev, yes_no};

pub(super) fn build_main_lines(state: &AppState, content_width: usize) -> Vec<Line<'static>> {
    let Some(snapshot) = &state.snapshot else {
        return vec![
            Line::from("Collecting realtime snapshot..."),
            Line::from(""),
            Line::from("State worker is running in background."),
        ];
    };

    match state.active_view {
        ActiveView::Dashboard => dashboard::dashboard_lines(snapshot, content_width),
        ActiveView::Plugins => plugin_lines(state, snapshot),
        ActiveView::Checks => check_lines(state, snapshot),
        _ => coming_soon_lines(state),
    }
}

pub(super) fn plugin_lines(state: &AppState, snapshot: &DashboardSnapshot) -> Vec<Line<'static>> {
    let view = PluginListView::from_snapshot(snapshot);
    let mut lines = vec![
        Line::from("Plugin actions"),
        Line::from("  list(l) search(s) info(i) preflight(f) test(t) install(n)"),
        Line::from(format!(
            "  spec: {}{}",
            if state.plugin_spec.trim().is_empty() {
                "<empty>"
            } else {
                state.plugin_spec.trim()
            },
            if state.plugin_spec_editing {
                "  [editing]"
            } else {
                "  (press e to edit)"
            }
        )),
        Line::from(""),
        Line::from("Installed plugins snapshot"),
        Line::from(format!("Installed plugins: {}", view.total_plugins)),
        Line::from(""),
    ];
    if view.items.is_empty() {
        lines.push(Line::from("No plugin found in lockfile."));
        lines.push(Line::from("Run `preen plugin install <pack>@<version>`."));
        return lines;
    }

    for plugin in &view.items {
        lines.push(Line::from(format!(
            "- {}  v{}  [{}]  installed={}",
            plugin.pack_id,
            plugin.version,
            plugin.source,
            yes_no(plugin.installed)
        )));
        lines.push(Line::from(format!("  rev: {}", short_rev(&plugin.rev))));
        lines.push(Line::from(format!(
            "  identity: {}",
            plugin.trusted_identity
        )));
        lines.push(Line::from(""));
    }

    lines.push(Line::from("Command output"));
    if state.plugin_action_running {
        lines.push(Line::from("  running..."));
    } else if let Some(action) = state.plugin_last_action {
        lines.push(Line::from(format!("  last action: {}", action.label())));
    } else {
        lines.push(Line::from("  no command executed yet"));
    }
    if !state.plugin_last_output.is_empty() {
        for line in &state.plugin_last_output {
            lines.push(Line::from(format!("  {line}")));
        }
    }
    if !state.plugin_last_diagnostics.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Structured diagnostics"));
        for line in &state.plugin_last_diagnostics {
            lines.push(Line::from(format!("  {line}")));
        }
    }
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Error: {error}")));
    }
    lines
}

pub(super) fn check_lines(state: &AppState, snapshot: &DashboardSnapshot) -> Vec<Line<'static>> {
    let view = CheckListView::from_snapshot(snapshot);
    let mut lines = vec![
        Line::from(format!("Checks: {}", view.total_checks)),
        Line::from(""),
    ];
    for check in &view.items {
        lines.push(Line::from(format!(
            "- [{}] {}  ({})",
            if check.passed { "OK" } else { "NO" },
            check.label,
            check.severity_label
        )));
        lines.push(Line::from(format!("  {}", check.message)));
    }
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Error: {error}")));
    }
    lines
}

fn coming_soon_lines(state: &AppState) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("{} view is scaffolded.", state.active_view.title())),
        Line::from(""),
        Line::from("This menu is planned but not implemented yet."),
        Line::from("Architecture target:"),
        Line::from("- UI stays thin (render/input only)"),
        Line::from("- data and business logic come from preen-core/preen-os"),
        Line::from(""),
        Line::from("Current ready menus: Dashboard, Plugins, Checks."),
    ];
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Error: {error}")));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::{check_lines, plugin_lines};
    use crate::model::{ActiveView, AppState};
    use preen_core::dashboard::{
        CheckSeverity, DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
        DashboardMetrics, DashboardSnapshot, PluginRow, RegistrySummary, StatusCheck,
    };
    use std::path::PathBuf;

    fn base_snapshot() -> DashboardSnapshot {
        DashboardSnapshot {
            schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
            contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
            collected_at: std::time::SystemTime::now().into(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            state_dir: PathBuf::from("/tmp/preen"),
            health_score: 90,
            overall_passed: true,
            plugin_count: 1,
            installed_plugins_on_disk: 1,
            checks: vec![StatusCheck {
                id: "state_dir_exists".to_string(),
                label: "State directory exists".to_string(),
                severity: CheckSeverity::Critical,
                passed: true,
                message: "ok".to_string(),
            }],
            warnings: Vec::new(),
            suggested_actions: Vec::new(),
            registry: RegistrySummary::default(),
            metrics: DashboardMetrics::default(),
            plugins: vec![PluginRow {
                pack_id: "preen-rs.homebrew".to_string(),
                version: "1.0.7".to_string(),
                source: "registry".to_string(),
                rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
                installed: true,
                trusted_identity:
                    "https://github.com/Preen-rs/preen-rulepack-homebrew/.github/workflows/release-manual.yml@refs/heads/main"
                        .to_string(),
            }],
        }
    }

    #[test]
    fn plugin_lines_show_structured_diagnostics_when_present() {
        let snapshot = base_snapshot();
        let mut state = AppState {
            active_view: ActiveView::Plugins,
            plugin_spec: "preen-rs.homebrew@1.0.7".to_string(),
            ..AppState::default()
        };
        state.apply_plugin_command_result(
            crate::model::PluginActionKind::Test,
            true,
            vec![r#"{"schema_version":1,"kind":"plugin.test_spec","data":{"overall_passed":true,"duration_ms":42,"checks":[{"check":"signature_verified","passed":true}]}}"#.to_string()],
        );

        let lines = plugin_lines(&state, &snapshot);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Structured diagnostics"));
        assert!(text.contains("overall_passed: true"));
        assert!(text.contains("Signature verified=true"));
    }

    #[test]
    fn check_lines_show_severity_and_message() {
        let mut snapshot = base_snapshot();
        snapshot.checks = vec![StatusCheck {
            id: "registry_readable".to_string(),
            label: "Registry index readable".to_string(),
            severity: CheckSeverity::Warning,
            passed: false,
            message: "registry missing".to_string(),
        }];
        let state = AppState::default();

        let lines = check_lines(&state, &snapshot);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Checks: 1"));
        assert!(text.contains("Registry index readable"));
        assert!(text.contains("(warning)"));
        assert!(text.contains("registry missing"));
    }
}
