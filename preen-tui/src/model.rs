use crate::plugin_status::{parse_summary_from_cli_json, render_summary_lines_with_language};
pub use preen_core::dashboard::DashboardSnapshot;
pub use preen_os::plugin_command::PluginCommandKind as PluginActionKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveView {
    Dashboard,
    SmartCare,
    Cleanup,
    Protection,
    Performance,
    Applications,
    Plugins,
    Checks,
    MyTools,
    MyActivity,
}

#[derive(Debug, Clone, Copy)]
pub struct MenuSection {
    pub heading: Option<&'static str>,
    pub items: &'static [ActiveView],
}

const MENU_PRIMARY_ITEMS: [ActiveView; 7] = [
    ActiveView::Dashboard,
    ActiveView::SmartCare,
    ActiveView::Cleanup,
    ActiveView::Protection,
    ActiveView::Performance,
    ActiveView::Applications,
    ActiveView::Plugins,
];

const MENU_TOOLS_ITEMS: [ActiveView; 3] = [
    ActiveView::Checks,
    ActiveView::MyTools,
    ActiveView::MyActivity,
];

const MENU_CYCLE_ITEMS: [ActiveView; 10] = [
    ActiveView::Dashboard,
    ActiveView::SmartCare,
    ActiveView::Cleanup,
    ActiveView::Protection,
    ActiveView::Performance,
    ActiveView::Applications,
    ActiveView::Plugins,
    ActiveView::Checks,
    ActiveView::MyTools,
    ActiveView::MyActivity,
];

const MENU_SECTIONS: [MenuSection; 2] = [
    MenuSection {
        heading: None,
        items: &MENU_PRIMARY_ITEMS,
    },
    MenuSection {
        heading: Some("Tools"),
        items: &MENU_TOOLS_ITEMS,
    },
];

impl ActiveView {
    pub fn sections() -> &'static [MenuSection] {
        &MENU_SECTIONS
    }

    pub fn cycle_items() -> &'static [ActiveView] {
        &MENU_CYCLE_ITEMS
    }

    pub fn next(self) -> Self {
        let items = Self::cycle_items();
        let index = items.iter().position(|view| *view == self).unwrap_or(0);
        items[(index + 1) % items.len()]
    }

    pub fn previous(self) -> Self {
        let items = Self::cycle_items();
        let index = items.iter().position(|view| *view == self).unwrap_or(0);
        items[(index + items.len() - 1) % items.len()]
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::SmartCare => "Smart Care",
            Self::Cleanup => "Cleanup",
            Self::Protection => "Protection",
            Self::Performance => "Performance",
            Self::Applications => "Applications",
            Self::Plugins => "Plugins",
            Self::Checks => "Checks",
            Self::MyTools => "My Tools",
            Self::MyActivity => "My Activity",
        }
    }

    pub fn is_implemented(self) -> bool {
        matches!(self, Self::Dashboard | Self::Plugins | Self::Checks)
    }
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub active_view: ActiveView,
    pub snapshot: Option<DashboardSnapshot>,
    pub last_error: Option<String>,
    pub plugin_spec: String,
    pub plugin_spec_editing: bool,
    pub plugin_last_action: Option<PluginActionKind>,
    pub plugin_last_output: Vec<String>,
    pub plugin_last_diagnostics: Vec<String>,
    pub plugin_action_running: bool,
    pub main_scroll: u16,
    pub show_keybindings_popup: bool,
    pub keybindings_popup_scroll: u16,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            active_view: ActiveView::Dashboard,
            snapshot: None,
            last_error: None,
            plugin_spec: String::new(),
            plugin_spec_editing: false,
            plugin_last_action: None,
            plugin_last_output: Vec::new(),
            plugin_last_diagnostics: Vec::new(),
            plugin_action_running: false,
            main_scroll: 0,
            show_keybindings_popup: false,
            keybindings_popup_scroll: 0,
        }
    }
}

impl AppState {
    pub fn set_active_view(&mut self, next: ActiveView) {
        if self.active_view != next {
            self.active_view = next;
            self.main_scroll = 0;
        }
    }

    pub fn scroll_down(&mut self, amount: u16) {
        self.main_scroll = self.main_scroll.saturating_add(amount);
    }

    pub fn scroll_up(&mut self, amount: u16) {
        self.main_scroll = self.main_scroll.saturating_sub(amount);
    }

    pub fn scroll_to_top(&mut self) {
        self.main_scroll = 0;
    }

    pub fn toggle_keybindings_popup(&mut self) {
        self.show_keybindings_popup = !self.show_keybindings_popup;
        if self.show_keybindings_popup {
            self.keybindings_popup_scroll = 0;
        }
    }

    pub fn close_keybindings_popup(&mut self) {
        self.show_keybindings_popup = false;
        self.keybindings_popup_scroll = 0;
    }

    pub fn scroll_keybindings_down(&mut self, amount: u16) {
        self.keybindings_popup_scroll = self.keybindings_popup_scroll.saturating_add(amount);
    }

    pub fn scroll_keybindings_up(&mut self, amount: u16) {
        self.keybindings_popup_scroll = self.keybindings_popup_scroll.saturating_sub(amount);
    }

    pub fn begin_plugin_spec_edit(&mut self) {
        self.plugin_spec_editing = true;
    }

    pub fn end_plugin_spec_edit(&mut self) {
        self.plugin_spec_editing = false;
    }

    pub fn push_plugin_spec_char(&mut self, ch: char) {
        self.plugin_spec.push(ch);
    }

    pub fn pop_plugin_spec_char(&mut self) {
        let _ = self.plugin_spec.pop();
    }

    pub fn apply_plugin_command_started(&mut self, action: PluginActionKind) {
        self.plugin_action_running = true;
        self.plugin_last_action = Some(action);
        self.plugin_last_output.clear();
        self.plugin_last_diagnostics.clear();
        self.last_error = None;
    }

    pub fn apply_plugin_command_result(
        &mut self,
        action: PluginActionKind,
        ok: bool,
        lines: Vec<String>,
    ) {
        self.plugin_action_running = false;
        self.plugin_last_action = Some(action);
        self.plugin_last_diagnostics = extract_plugin_diagnostics(&lines);
        self.plugin_last_output = lines;
        if ok {
            self.last_error = None;
        }
    }
}

fn extract_plugin_diagnostics(lines: &[String]) -> Vec<String> {
    let payload = lines.iter().find(|line| line.trim_start().starts_with('{'));
    let Some(payload) = payload else {
        return fallback_diagnostics_from_stderr(lines);
    };
    let Ok(summary) = parse_summary_from_cli_json(payload) else {
        return fallback_diagnostics_from_stderr(lines);
    };
    render_summary_lines_with_language(&summary, "en-US")
}

fn fallback_diagnostics_from_stderr(lines: &[String]) -> Vec<String> {
    let errors = lines
        .iter()
        .filter_map(|line| line.strip_prefix("stderr:").map(str::trim))
        .filter(|line| !line.is_empty())
        .take(3)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if errors.is_empty() {
        return Vec::new();
    }
    let mut diagnostics = vec![
        "overall_passed: false".to_string(),
        "detail_code: unstructured_plugin_output".to_string(),
    ];
    diagnostics.extend(errors.into_iter().map(|line| format!("stderr: {line}")));
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_view_cycle_is_stable() {
        let cycle = ActiveView::cycle_items();
        for (idx, current) in cycle.iter().copied().enumerate() {
            let expected_next = cycle[(idx + 1) % cycle.len()];
            let expected_prev = cycle[(idx + cycle.len() - 1) % cycle.len()];
            assert_eq!(current.next(), expected_next);
            assert_eq!(current.previous(), expected_prev);
        }
    }

    #[test]
    fn set_active_view_resets_scroll_only_when_view_changes() {
        let mut state = AppState {
            main_scroll: 7,
            ..AppState::default()
        };

        state.set_active_view(ActiveView::Dashboard);
        assert_eq!(state.main_scroll, 7);

        state.set_active_view(ActiveView::Plugins);
        assert_eq!(state.active_view, ActiveView::Plugins);
        assert_eq!(state.main_scroll, 0);
    }

    #[test]
    fn keybindings_popup_toggle_resets_popup_scroll() {
        let mut state = AppState::default();
        state.keybindings_popup_scroll = 12;
        state.toggle_keybindings_popup();
        assert!(state.show_keybindings_popup);
        assert_eq!(state.keybindings_popup_scroll, 0);

        state.keybindings_popup_scroll = 4;
        state.toggle_keybindings_popup();
        assert!(!state.show_keybindings_popup);
        assert_eq!(state.keybindings_popup_scroll, 4);

        state.close_keybindings_popup();
        assert!(!state.show_keybindings_popup);
        assert_eq!(state.keybindings_popup_scroll, 0);
    }

    #[test]
    fn plugin_command_state_transitions_keep_last_error_on_failure() {
        let mut state = AppState {
            last_error: Some("old error".to_string()),
            ..AppState::default()
        };

        state.apply_plugin_command_started(PluginActionKind::Test);
        assert!(state.plugin_action_running);
        assert_eq!(state.plugin_last_action, Some(PluginActionKind::Test));
        assert!(state.plugin_last_output.is_empty());
        assert_eq!(state.last_error, None);

        state.last_error = Some("runtime failure".to_string());
        state.apply_plugin_command_result(
            PluginActionKind::Test,
            false,
            vec!["stderr: fail".to_string()],
        );
        assert!(!state.plugin_action_running);
        assert_eq!(state.plugin_last_action, Some(PluginActionKind::Test));
        assert_eq!(state.plugin_last_output, vec!["stderr: fail".to_string()]);
        assert_eq!(
            state.plugin_last_diagnostics[0],
            "overall_passed: false".to_string()
        );
        assert_eq!(state.last_error.as_deref(), Some("runtime failure"));

        state.apply_plugin_command_result(PluginActionKind::Test, true, vec!["ok".to_string()]);
        assert_eq!(state.last_error, None);
    }

    #[test]
    fn extracts_plugin_summary_diagnostics_from_json_output() {
        let mut state = AppState::default();
        state.apply_plugin_command_result(
            PluginActionKind::Test,
            true,
            vec![r#"{"schema_version":1,"kind":"plugin.test_spec","data":{"overall_passed":true,"duration_ms":25,"checks":[{"check":"signature_verified","passed":true},{"check":"trust_verified","passed":true}]}}"#.to_string()],
        );

        assert!(
            state
                .plugin_last_diagnostics
                .iter()
                .any(|line| line.contains("overall_passed: true"))
        );
        assert!(
            state
                .plugin_last_diagnostics
                .iter()
                .any(|line| line.contains("check [critical] Signature verified=true"))
        );
    }

    #[test]
    fn fallback_diagnostics_from_stderr_when_json_is_missing() {
        let mut state = AppState::default();
        state.apply_plugin_command_result(
            PluginActionKind::Install,
            false,
            vec![
                "stderr: clone failed".to_string(),
                "stderr: network unreachable".to_string(),
            ],
        );

        assert_eq!(
            state.plugin_last_diagnostics[0],
            "overall_passed: false".to_string()
        );
        assert!(
            state
                .plugin_last_diagnostics
                .iter()
                .any(|line| line.contains("detail_code: unstructured_plugin_output"))
        );
        assert!(
            state
                .plugin_last_diagnostics
                .iter()
                .any(|line| line.contains("clone failed"))
        );
    }
}
