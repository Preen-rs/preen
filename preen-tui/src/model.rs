use crate::plugin_status::{parse_summary_from_cli_json, render_summary_lines_with_language};
use preen_core::app_uninstall::{InstalledApplication, UninstallPlan};
pub use preen_core::dashboard::DashboardSnapshot;
pub use preen_core::smart_care::{
    SmartCareCapability, SmartCarePluginDescriptor, SmartCarePreview, SmartCareProfile,
    build_preview_from_descriptors,
};
use preen_os::app_inventory;
use preen_os::app_uninstall;
pub use preen_os::plugin_command::PluginCommandKind as PluginActionKind;
use preen_os::smart_care_runtime;
use preen_os::trash_ops;
use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

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
        matches!(
            self,
            Self::Dashboard
                | Self::SmartCare
                | Self::Cleanup
                | Self::Protection
                | Self::Performance
                | Self::Applications
                | Self::Plugins
                | Self::Checks
        )
    }

    pub const fn smart_care_capability(self) -> Option<SmartCareCapability> {
        match self {
            Self::Cleanup => Some(SmartCareCapability::Cleanup),
            Self::Protection => Some(SmartCareCapability::Protection),
            Self::Performance => Some(SmartCareCapability::Performance),
            Self::Applications => Some(SmartCareCapability::Applications),
            _ => None,
        }
    }

    pub const fn supports_smart_care_controls(self) -> bool {
        matches!(
            self,
            Self::SmartCare
                | Self::Cleanup
                | Self::Protection
                | Self::Performance
                | Self::Applications
        )
    }
}

#[derive(Debug, Clone)]
pub struct ApplicationUninstallRecord {
    pub plan: UninstallPlan,
    pub moved_paths: Vec<(PathBuf, PathBuf)>,
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
    pub smart_care_profile: SmartCareProfile,
    pub smart_care_descriptors: Vec<SmartCarePluginDescriptor>,
    pub smart_care_error: Option<String>,
    pub smart_care_source_summary: Option<String>,
    pub smart_care_skipped_pack_ids: BTreeSet<String>,
    pub smart_care_dev_fallback_pack_ids: BTreeSet<String>,
    pub smart_care_preview: Option<SmartCarePreview>,
    pub smart_care_selected_card: usize,
    pub smart_care_has_analyze_result: bool,
    pub smart_care_has_review_result: bool,
    pub smart_care_review_mode: bool,
    pub smart_care_review_scroll: u16,
    pub smart_care_review_selected_entry: usize,
    pub smart_care_review_disabled_entries: BTreeSet<String>,
    pub smart_care_last_run_report: Vec<String>,
    pub smart_care_last_analyze: Vec<String>,
    pub smart_care_apply_armed: bool,
    pub smart_care_action_running: bool,
    pub smart_care_action_label: Option<String>,
    pub smart_care_reopen_review_on_analyze: bool,
    pub main_scroll: u16,
    pub show_keybindings_popup: bool,
    pub keybindings_popup_scroll: u16,
    pub show_info_popup: bool,
    pub info_popup_scroll: u16,
    pub applications_selected_row: usize,
    pub applications_list_offset: usize,
    pub applications_selected_items: BTreeSet<String>,
    pub applications_inventory: Vec<String>,
    pub applications_inventory_metadata: Vec<InstalledApplication>,
    pub applications_inventory_revision: u64,
    pub applications_last_action_lines: Vec<String>,
    pub applications_info_target: Option<String>,
    pub applications_info_paths: Vec<String>,
    pub applications_show_paths_in_info: bool,
    pub applications_uninstall_confirm: bool,
    pub applications_pending_uninstall: Vec<String>,
    pub applications_last_uninstall: Vec<ApplicationUninstallRecord>,
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
            smart_care_profile: SmartCareProfile::default_profile(),
            smart_care_descriptors: Vec::new(),
            smart_care_error: None,
            smart_care_source_summary: None,
            smart_care_skipped_pack_ids: BTreeSet::new(),
            smart_care_dev_fallback_pack_ids: BTreeSet::new(),
            smart_care_preview: None,
            smart_care_selected_card: 0,
            smart_care_has_analyze_result: false,
            smart_care_has_review_result: false,
            smart_care_review_mode: false,
            smart_care_review_scroll: 0,
            smart_care_review_selected_entry: 0,
            smart_care_review_disabled_entries: BTreeSet::new(),
            smart_care_last_run_report: Vec::new(),
            smart_care_last_analyze: Vec::new(),
            smart_care_apply_armed: false,
            smart_care_action_running: false,
            smart_care_action_label: None,
            smart_care_reopen_review_on_analyze: false,
            main_scroll: 0,
            show_keybindings_popup: false,
            keybindings_popup_scroll: 0,
            show_info_popup: false,
            info_popup_scroll: 0,
            applications_selected_row: 0,
            applications_list_offset: 0,
            applications_selected_items: BTreeSet::new(),
            applications_inventory: Vec::new(),
            applications_inventory_metadata: Vec::new(),
            applications_inventory_revision: 0,
            applications_last_action_lines: Vec::new(),
            applications_info_target: None,
            applications_info_paths: Vec::new(),
            applications_show_paths_in_info: false,
            applications_uninstall_confirm: false,
            applications_pending_uninstall: Vec::new(),
            applications_last_uninstall: Vec::new(),
        }
    }
}

impl AppState {
    fn applications_state_dir(&self) -> Option<PathBuf> {
        self.snapshot
            .as_ref()
            .map(|snapshot| snapshot.state_dir.clone())
    }

    pub fn set_active_view(&mut self, next: ActiveView) {
        if self.active_view != next {
            self.active_view = next;
            self.main_scroll = 0;
            self.smart_care_apply_armed = false;
            self.close_info_popup();
            self.applications_cancel_uninstall_confirm();
            if let Some(capability) = next.smart_care_capability()
                && let Some(index) = self
                    .smart_care_profile
                    .capabilities
                    .iter()
                    .position(|selection| selection.capability == capability)
            {
                self.smart_care_selected_card = index;
            }
            self.applications_sync_selection();
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

    pub fn toggle_info_popup(&mut self) {
        self.show_info_popup = !self.show_info_popup;
        if self.show_info_popup {
            self.info_popup_scroll = 0;
            self.applications_show_paths_in_info = false;
        }
    }

    pub fn close_info_popup(&mut self) {
        self.show_info_popup = false;
        self.info_popup_scroll = 0;
        self.applications_show_paths_in_info = false;
    }

    pub fn applications_toggle_paths_popup(&mut self) {
        if self.show_info_popup && self.applications_show_paths_in_info {
            self.close_info_popup();
        } else {
            self.applications_prepare_info_for_selected();
            self.applications_show_paths_in_info = true;
            self.show_info_popup = true;
            self.info_popup_scroll = 0;
        }
    }

    pub fn applications_items(&self) -> Vec<String> {
        if !self.applications_inventory.is_empty() {
            return self.applications_inventory.clone();
        }
        let Some(snapshot) = &self.snapshot else {
            return Vec::new();
        };
        snapshot.metrics.installed_applications.clone()
    }

    pub fn applications_run_local_inventory_analyze(&mut self) {
        let previous_len = self.applications_inventory.len();
        self.applications_inventory_metadata = app_inventory::collect_installed_applications();
        self.applications_inventory = self
            .applications_inventory_metadata
            .iter()
            .map(|app| app.identity.display_name.clone())
            .collect();
        self.applications_inventory_revision =
            self.applications_inventory_revision.saturating_add(1);
        self.applications_selected_row = 0;
        self.applications_list_offset = 0;
        self.close_info_popup();
        self.applications_sync_selection();
        self.smart_care_has_analyze_result = true;
        self.smart_care_has_review_result = false;
        self.smart_care_review_mode = false;
        self.smart_care_review_scroll = 0;
        self.smart_care_review_selected_entry = 0;
        self.smart_care_review_disabled_entries.clear();
        self.smart_care_last_run_report.clear();
        let current_len = self.applications_inventory.len();
        let delta = current_len as isize - previous_len as isize;
        self.smart_care_last_analyze = vec![format!(
            "applications scan #{}: {} app(s) found ({delta:+})",
            self.applications_inventory_revision, current_len
        )];
        self.main_scroll = 0;
    }

    pub fn applications_sync_selection(&mut self) {
        let items = self.applications_items();
        self.applications_selected_items
            .retain(|item| items.iter().any(|value| value == item));
        if items.is_empty() {
            self.applications_selected_row = 0;
            self.applications_list_offset = 0;
            self.main_scroll = 0;
            return;
        }
        if self.applications_selected_row >= items.len() {
            self.applications_selected_row = items.len().saturating_sub(1);
        }
        self.applications_sync_main_scroll_with_selection();
    }

    pub fn applications_select_next(&mut self) {
        let items = self.applications_items();
        if items.is_empty() {
            self.applications_selected_row = 0;
            self.applications_list_offset = 0;
            return;
        }
        if self.applications_selected_row + 1 < items.len() {
            self.applications_selected_row += 1;
        }
        self.applications_sync_main_scroll_with_selection();
    }

    pub fn applications_select_previous(&mut self) {
        let items = self.applications_items();
        if items.is_empty() {
            self.applications_selected_row = 0;
            self.applications_list_offset = 0;
            return;
        }
        self.applications_selected_row = self.applications_selected_row.saturating_sub(1);
        self.applications_sync_main_scroll_with_selection();
    }

    pub fn applications_selected_app(&self) -> Option<String> {
        self.applications_items()
            .get(self.applications_selected_row)
            .cloned()
    }

    pub fn applications_is_selected(&self, app_name: &str) -> bool {
        self.applications_selected_items.contains(app_name)
    }

    pub fn applications_toggle_selected(&mut self) {
        let Some(app_name) = self.applications_selected_app() else {
            return;
        };
        if self.applications_selected_items.contains(&app_name) {
            self.applications_selected_items.remove(&app_name);
        } else {
            self.applications_selected_items.insert(app_name);
        }
    }

    pub fn applications_selected_count(&self) -> usize {
        self.applications_selected_items.len()
    }

    pub fn applications_prepare_info_for_selected(&mut self) {
        let Some(app_name) = self.applications_selected_app() else {
            self.applications_info_target = None;
            self.applications_info_paths.clear();
            return;
        };
        self.applications_info_paths = discover_application_related_paths(&app_name);
        self.applications_info_target = Some(app_name);
    }

    fn applications_sync_main_scroll_with_selection(&mut self) {
        // Main scroll is kept for legacy paragraph rendering paths.
        const APP_LIST_HEADER_LINES: usize = 18;
        self.main_scroll = APP_LIST_HEADER_LINES as u16;
    }

    fn applications_uninstall_targets(&self) -> Vec<String> {
        let mut targets = self
            .applications_selected_items
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        if targets.is_empty()
            && let Some(current) = self.applications_selected_app()
        {
            targets.push(current);
        }
        targets
    }

    pub fn applications_pending_uninstall_targets(&self) -> &[String] {
        &self.applications_pending_uninstall
    }

    pub fn applications_open_uninstall_confirm(&mut self) -> Result<(), String> {
        let targets = self.applications_uninstall_targets();
        if targets.is_empty() {
            return Err("hich applicationi baraye uninstall select nashode".to_string());
        }
        self.applications_pending_uninstall = targets;
        self.applications_uninstall_confirm = true;
        self.close_info_popup();
        Ok(())
    }

    pub fn applications_cancel_uninstall_confirm(&mut self) {
        self.applications_uninstall_confirm = false;
        self.applications_pending_uninstall.clear();
    }

    pub fn applications_confirm_uninstall_selected(&mut self) -> Result<(), String> {
        let targets = if self.applications_pending_uninstall.is_empty() {
            self.applications_uninstall_targets()
        } else {
            std::mem::take(&mut self.applications_pending_uninstall)
        };
        self.applications_uninstall_confirm = false;
        self.applications_execute_uninstall(targets)
    }

    fn applications_execute_uninstall(&mut self, targets: Vec<String>) -> Result<(), String> {
        if targets.is_empty() {
            return Err("hich applicationi baraye uninstall select nashode".to_string());
        }
        let mut logs = Vec::new();
        let mut removed_apps = BTreeSet::new();
        let mut uninstall_records = Vec::new();
        for app_name in targets {
            let plan = build_application_uninstall_plan(&app_name);
            if plan.protected {
                logs.push(format!("{app_name}: protected system application skipped"));
                continue;
            }
            if plan.paths.is_empty() {
                logs.push(format!("{app_name}: path peyda nashod"));
                continue;
            }
            let mut moved_paths = Vec::new();
            for related_path in &plan.paths {
                let path = PathBuf::from(&related_path.path);
                if !path.exists() {
                    continue;
                }
                match trash_ops::move_path_to_home_trash(&path) {
                    Ok(moved) => {
                        logs.push(format!(
                            "moved: {} -> {}",
                            path.display(),
                            moved.trashed_path.display()
                        ));
                        moved_paths.push((moved.original_path, moved.trashed_path));
                    }
                    Err(error) => logs.push(format!("failed: {} ({error})", path.display())),
                }
            }
            if !moved_paths.is_empty() {
                removed_apps.insert(app_name.clone());
                uninstall_records.push(ApplicationUninstallRecord { plan, moved_paths });
            }
        }

        if !removed_apps.is_empty() {
            self.applications_inventory
                .retain(|item| !removed_apps.contains(item));
            self.applications_selected_items
                .retain(|item| !removed_apps.contains(item));
            self.applications_sync_selection();
        }

        if !uninstall_records.is_empty() {
            if let Some(state_dir) = self.applications_state_dir() {
                let journal = app_uninstall_journal_from_records(&uninstall_records);
                match app_uninstall::write_last_app_uninstall_journal(&state_dir, &journal) {
                    Ok(path) => logs.push(format!("journal: {}", path.display())),
                    Err(error) => logs.push(format!("journal failed: {error}")),
                }
            }
            self.applications_last_uninstall = uninstall_records;
        }

        if logs.is_empty() {
            return Err("hich file jabeja nashod; momkene dastresi nadashte bashi".to_string());
        }
        self.applications_last_action_lines = logs;
        Ok(())
    }

    pub fn applications_undo_last_uninstall(&mut self) -> Result<(), String> {
        let records = if self.applications_last_uninstall.is_empty() {
            let records = self.applications_load_last_uninstall_from_journal()?;
            if records.is_empty() {
                return Err("hich uninstalli baraye undo vojod nadarad".to_string());
            }
            records
        } else {
            std::mem::take(&mut self.applications_last_uninstall)
        };
        if records.is_empty() {
            return Err("hich uninstalli baraye undo vojod nadarad".to_string());
        }

        let mut logs = Vec::new();
        let mut restored_apps = Vec::new();
        let mut restore_failed = false;

        for record in records.into_iter().rev() {
            let mut restored_any = false;
            for (original, trashed) in record.moved_paths.into_iter().rev() {
                match trash_ops::restore_trashed_path(&original, &trashed) {
                    Ok(()) => {
                        restored_any = true;
                        logs.push(format!(
                            "restored: {} -> {}",
                            trashed.display(),
                            original.display()
                        ));
                    }
                    Err(error) => {
                        restore_failed = true;
                        logs.push(format!("failed: {} ({error})", trashed.display()));
                    }
                }
            }
            if restored_any {
                restored_apps.push(record.plan.identity.display_name);
            }
        }

        let restored_any_app = !restored_apps.is_empty();
        if restored_any_app {
            for app in restored_apps {
                if !self.applications_inventory.iter().any(|item| item == &app) {
                    self.applications_inventory.push(app);
                }
            }
            self.applications_inventory.sort();
            self.applications_inventory.dedup();
            self.applications_sync_selection();
        }

        if logs.is_empty() {
            return Err("undo natavanest file ha ra restore konad".to_string());
        }

        if !restore_failed
            && restored_any_app
            && let Some(state_dir) = self.applications_state_dir()
        {
            match app_uninstall::clear_last_app_uninstall_journal(&state_dir) {
                Ok(()) => logs.push("journal cleared".to_string()),
                Err(error) => logs.push(format!("journal clear failed: {error}")),
            }
        }

        self.applications_last_action_lines = logs;
        Ok(())
    }

    fn applications_load_last_uninstall_from_journal(
        &self,
    ) -> Result<Vec<ApplicationUninstallRecord>, String> {
        let Some(state_dir) = self.applications_state_dir() else {
            return Ok(Vec::new());
        };
        let Some(journal) = app_uninstall::read_last_app_uninstall_journal(&state_dir)? else {
            return Ok(Vec::new());
        };
        Ok(app_uninstall_records_from_journal(journal))
    }

    pub fn scroll_info_popup_down(&mut self, amount: u16) {
        self.info_popup_scroll = self.info_popup_scroll.saturating_add(amount);
    }

    pub fn scroll_info_popup_up(&mut self, amount: u16) {
        self.info_popup_scroll = self.info_popup_scroll.saturating_sub(amount);
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

    pub fn begin_smart_care_action(
        &mut self,
        label: impl Into<String>,
        reopen_review_on_analyze: bool,
    ) -> bool {
        if self.smart_care_action_running {
            return false;
        }
        self.smart_care_action_running = true;
        self.smart_care_action_label = Some(label.into());
        self.smart_care_reopen_review_on_analyze = reopen_review_on_analyze;
        true
    }

    pub fn clear_smart_care_action_state(&mut self) {
        self.smart_care_action_running = false;
        self.smart_care_action_label = None;
        self.smart_care_reopen_review_on_analyze = false;
    }

    pub fn apply_smart_care_analyze_result(
        &mut self,
        preview: SmartCarePreview,
        lines: Vec<String>,
    ) {
        self.smart_care_preview = Some(preview);
        self.smart_care_last_analyze = lines;
        self.smart_care_has_analyze_result = true;
        self.smart_care_has_review_result = false;
        self.smart_care_review_mode = false;
        self.smart_care_review_scroll = 0;
        self.smart_care_review_selected_entry = 0;
        self.smart_care_review_disabled_entries.clear();
        self.smart_care_apply_armed = false;
        let reopen = self.smart_care_reopen_review_on_analyze;
        self.clear_smart_care_action_state();
        if reopen {
            self.smart_care_open_review();
        }
    }

    pub fn apply_smart_care_run_result(&mut self, lines: Vec<String>) {
        self.smart_care_last_run_report = lines;
        self.smart_care_review_mode = true;
        self.smart_care_review_scroll = 0;
        self.smart_care_apply_armed = false;
        self.clear_smart_care_action_state();
    }

    pub fn apply_smart_care_descriptor_snapshot(
        &mut self,
        descriptors: Vec<SmartCarePluginDescriptor>,
        resolver_error: Option<String>,
        source_summary: Option<String>,
        skipped_pack_ids: BTreeSet<String>,
        dev_fallback_pack_ids: BTreeSet<String>,
    ) {
        let changed = self.smart_care_descriptors != descriptors
            || self.smart_care_error != resolver_error
            || self.smart_care_source_summary != source_summary
            || self.smart_care_skipped_pack_ids != skipped_pack_ids
            || self.smart_care_dev_fallback_pack_ids != dev_fallback_pack_ids;

        self.smart_care_descriptors = descriptors;
        self.smart_care_error = resolver_error;
        self.smart_care_source_summary = source_summary;
        self.smart_care_skipped_pack_ids = skipped_pack_ids;
        self.smart_care_dev_fallback_pack_ids = dev_fallback_pack_ids;

        if changed {
            self.smart_care_preview = None;
            self.smart_care_has_analyze_result = false;
            self.smart_care_has_review_result = false;
            self.smart_care_review_mode = false;
            self.smart_care_review_scroll = 0;
            self.smart_care_review_selected_entry = 0;
            self.smart_care_review_disabled_entries.clear();
            self.smart_care_last_analyze.clear();
            self.smart_care_apply_armed = false;
        }
    }

    pub fn apply_smart_care_undo_result(&mut self, lines: Vec<String>) {
        self.smart_care_last_run_report = lines;
        self.smart_care_review_mode = true;
        self.smart_care_review_scroll = 0;
        self.smart_care_apply_armed = false;
        self.clear_smart_care_action_state();
    }

    pub fn smart_care_toggle_capability(&mut self, capability: SmartCareCapability) {
        if let Some(selection) = self
            .smart_care_profile
            .capabilities
            .iter_mut()
            .find(|selection| selection.capability == capability)
        {
            selection.enabled = !selection.enabled;
            self.smart_care_preview = None;
            self.smart_care_has_analyze_result = false;
            self.smart_care_has_review_result = false;
            self.smart_care_review_mode = false;
            self.smart_care_review_scroll = 0;
            self.smart_care_review_selected_entry = 0;
            self.smart_care_review_disabled_entries.clear();
            self.smart_care_last_run_report.clear();
            self.smart_care_last_analyze.clear();
            self.smart_care_apply_armed = false;
            self.clear_smart_care_action_state();
            self.main_scroll = 0;
        }
    }

    pub fn smart_care_reset_profile(&mut self) {
        self.smart_care_profile = SmartCareProfile::default_profile();
        self.smart_care_preview = None;
        self.smart_care_selected_card = 0;
        self.smart_care_has_analyze_result = false;
        self.smart_care_has_review_result = false;
        self.smart_care_review_mode = false;
        self.smart_care_review_scroll = 0;
        self.smart_care_review_selected_entry = 0;
        self.smart_care_review_disabled_entries.clear();
        self.smart_care_last_run_report.clear();
        self.smart_care_last_analyze.clear();
        self.smart_care_apply_armed = false;
        self.clear_smart_care_action_state();
        self.main_scroll = 0;
    }

    pub fn smart_care_arm_apply(&mut self) {
        self.smart_care_apply_armed = true;
    }

    pub fn smart_care_disarm_apply(&mut self) {
        self.smart_care_apply_armed = false;
    }

    pub fn smart_care_validate_run_request(&self) -> Result<(), String> {
        if !self.smart_care_has_review_result {
            return Err("review ro aval ba 'v' anjam bede".to_string());
        }
        if !self.smart_care_apply_armed {
            return Err("baraye apply, aval Shift+X ro bezan".to_string());
        }
        let preview = self.smart_care_current_preview();
        if !preview.overall_ready {
            if let Some(blocker) = preview.blockers.first() {
                return Err(format!("smart care blocker: {blocker}"));
            }
            return Err("smart care blocker: preview not ready".to_string());
        }
        let selected_entries = preview
            .review_entries
            .iter()
            .filter(|entry| !self.smart_care_review_disabled_entries.contains(&entry.id))
            .count();
        if selected_entries == 0 {
            return Err(
                "run blocker: hich review entry select nashode; ba space ya 1/2/3/4 entekhab kon"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn smart_care_current_preview(&self) -> SmartCarePreview {
        self.smart_care_preview.clone().unwrap_or_else(|| {
            build_preview_from_descriptors(&self.smart_care_profile, &self.smart_care_descriptors)
        })
    }

    pub fn smart_care_disabled_entry_ids(&self) -> HashSet<String> {
        self.smart_care_review_disabled_entries
            .iter()
            .cloned()
            .collect()
    }

    pub fn smart_care_run_local_analyze(&mut self) {
        let output = smart_care_runtime::analyze(
            &self.smart_care_profile,
            &self.smart_care_descriptors,
            None,
        );
        self.smart_care_last_analyze = output.lines;
        self.smart_care_preview = Some(output.preview);
        self.smart_care_has_analyze_result = true;
        self.smart_care_has_review_result = false;
        self.smart_care_review_mode = false;
        self.smart_care_review_scroll = 0;
        self.smart_care_review_selected_entry = 0;
        self.smart_care_review_disabled_entries.clear();
    }

    pub fn smart_care_select_next_card(&mut self) {
        let card_count = self.smart_care_profile.capabilities.len();
        if card_count == 0 {
            return;
        }
        self.smart_care_selected_card = (self.smart_care_selected_card + 1) % card_count;
    }

    pub fn smart_care_select_previous_card(&mut self) {
        let card_count = self.smart_care_profile.capabilities.len();
        if card_count == 0 {
            return;
        }
        self.smart_care_selected_card =
            (self.smart_care_selected_card + card_count - 1) % card_count;
    }

    pub fn smart_care_toggle_selected_card(&mut self) {
        let Some(capability) = self
            .smart_care_profile
            .capabilities
            .get(self.smart_care_selected_card)
            .map(|selection| selection.capability)
        else {
            return;
        };
        self.smart_care_toggle_capability(capability);
    }

    pub fn smart_care_open_review(&mut self) {
        if !self.smart_care_has_analyze_result {
            self.last_error = Some("run analyze first with 'a' before opening review".to_string());
            return;
        }
        if self.smart_care_preview.is_none() {
            self.smart_care_run_local_analyze();
        }
        self.smart_care_has_review_result = true;
        self.smart_care_review_mode = true;
        self.smart_care_review_scroll = 0;
        self.smart_care_review_selected_entry = 0;
    }

    pub fn smart_care_close_review(&mut self) {
        self.smart_care_review_mode = false;
        self.smart_care_review_scroll = 0;
    }

    pub fn smart_care_review_select_next_entry(&mut self) {
        let Some(preview) = &self.smart_care_preview else {
            return;
        };
        let total = preview.review_entries.len();
        if total == 0 {
            self.smart_care_review_selected_entry = 0;
            return;
        }
        self.smart_care_review_selected_entry = (self.smart_care_review_selected_entry + 1) % total;
    }

    pub fn smart_care_review_select_previous_entry(&mut self) {
        let Some(preview) = &self.smart_care_preview else {
            return;
        };
        let total = preview.review_entries.len();
        if total == 0 {
            self.smart_care_review_selected_entry = 0;
            return;
        }
        self.smart_care_review_selected_entry =
            (self.smart_care_review_selected_entry + total - 1) % total;
    }

    pub fn smart_care_review_toggle_selected_entry(&mut self) {
        let Some(preview) = &self.smart_care_preview else {
            return;
        };
        let Some(entry) = preview
            .review_entries
            .get(self.smart_care_review_selected_entry)
        else {
            return;
        };
        if !self
            .smart_care_review_disabled_entries
            .insert(entry.id.clone())
        {
            self.smart_care_review_disabled_entries.remove(&entry.id);
        }
        self.smart_care_apply_armed = false;
    }

    pub fn smart_care_review_select_all_entries(&mut self) {
        self.smart_care_review_disabled_entries.clear();
        self.smart_care_apply_armed = false;
    }

    pub fn smart_care_review_unselect_all_entries(&mut self) {
        let Some(preview) = &self.smart_care_preview else {
            return;
        };
        self.smart_care_review_disabled_entries = preview
            .review_entries
            .iter()
            .map(|entry| entry.id.clone())
            .collect();
        self.smart_care_apply_armed = false;
    }

    pub fn smart_care_review_toggle_capability_entries(&mut self, capability: SmartCareCapability) {
        let Some(preview) = &self.smart_care_preview else {
            return;
        };
        let capability_entries = preview
            .review_entries
            .iter()
            .filter(|entry| entry.capability == capability)
            .collect::<Vec<_>>();
        if capability_entries.is_empty() {
            return;
        }

        let all_selected = capability_entries
            .iter()
            .all(|entry| !self.smart_care_review_disabled_entries.contains(&entry.id));
        if all_selected {
            for entry in capability_entries {
                self.smart_care_review_disabled_entries
                    .insert(entry.id.clone());
            }
        } else {
            for entry in capability_entries {
                self.smart_care_review_disabled_entries.remove(&entry.id);
            }
        }
        self.smart_care_apply_armed = false;
    }

    #[cfg(test)]
    pub fn smart_care_review_selected_count(&self) -> usize {
        let Some(preview) = &self.smart_care_preview else {
            return 0;
        };
        preview
            .review_entries
            .iter()
            .filter(|entry| !self.smart_care_review_disabled_entries.contains(&entry.id))
            .count()
    }

    #[cfg(test)]
    pub fn smart_care_run_local_execute(&mut self) {
        let preview = self.smart_care_current_preview();
        let output = smart_care_runtime::execute_local_dry_run(
            &preview,
            &self.smart_care_disabled_entry_ids(),
            self.smart_care_has_review_result,
        );
        self.smart_care_last_run_report = output.lines;
        self.smart_care_review_mode = true;
        self.smart_care_review_scroll = 0;
    }

    #[cfg(test)]
    pub fn smart_care_run_local_undo(&mut self) {
        let output =
            smart_care_runtime::undo_local_dry_run(!self.smart_care_last_run_report.is_empty());
        self.smart_care_last_run_report = output.lines;
        self.smart_care_review_mode = true;
        self.smart_care_review_scroll = 0;
    }

    pub fn smart_care_scroll_review_down(&mut self, amount: u16) {
        self.smart_care_review_scroll = self.smart_care_review_scroll.saturating_add(amount);
    }

    pub fn smart_care_scroll_review_up(&mut self, amount: u16) {
        self.smart_care_review_scroll = self.smart_care_review_scroll.saturating_sub(amount);
    }

    pub fn smart_care_scroll_review_to_top(&mut self) {
        self.smart_care_review_scroll = 0;
    }

    pub fn smart_care_is_enabled(&self, capability: SmartCareCapability) -> bool {
        self.smart_care_profile
            .capabilities
            .iter()
            .find(|selection| selection.capability == capability)
            .is_some_and(|selection| selection.enabled)
    }

    pub fn smart_care_selected_capability(&self) -> Option<SmartCareCapability> {
        if let Some(capability) = self.active_view.smart_care_capability() {
            return Some(capability);
        }
        if !matches!(self.active_view, ActiveView::SmartCare) {
            return None;
        }
        self.smart_care_profile
            .capabilities
            .get(self.smart_care_selected_card)
            .map(|selection| selection.capability)
    }

    pub fn preferred_plugin_spec_for_capability(&self, capability: SmartCareCapability) -> String {
        preen_core::smart_care::preferred_plugin_spec_for_capability(
            capability,
            &self.smart_care_descriptors,
        )
    }

    pub fn preferred_plugin_spec_for_active_smart_care_context(&self) -> Option<String> {
        self.smart_care_selected_capability()
            .map(|capability| self.preferred_plugin_spec_for_capability(capability))
    }
}

fn extract_plugin_diagnostics(lines: &[String]) -> Vec<String> {
    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with('{')
            && let Ok(summary) = parse_summary_from_cli_json(trimmed)
        {
            return render_summary_lines_with_language(&summary, "en-US");
        }
        if let Some(idx) = trimmed.find('{') {
            let payload = &trimmed[idx..];
            if let Ok(summary) = parse_summary_from_cli_json(payload) {
                return render_summary_lines_with_language(&summary, "en-US");
            }
        }
    }
    fallback_diagnostics_from_stderr(lines)
}

fn fallback_diagnostics_from_stderr(lines: &[String]) -> Vec<String> {
    let errors = lines
        .iter()
        .filter_map(|line| line.strip_prefix("stderr:").map(str::trim))
        .filter(|line| !line.is_empty())
        .take(3)
        .map(|line| clamp_diagnostic_line(line, 140))
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

fn clamp_diagnostic_line(line: &str, max_chars: usize) -> String {
    if line.chars().count() <= max_chars {
        return line.to_string();
    }
    if max_chars <= 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    for ch in line.chars().take(max_chars - 1) {
        out.push(ch);
    }
    out.push('…');
    out
}

fn app_uninstall_journal_from_records(
    records: &[ApplicationUninstallRecord],
) -> app_uninstall::AppUninstallJournal {
    app_uninstall::AppUninstallJournal::new(
        records
            .iter()
            .map(|record| app_uninstall::AppUninstallJournalRecord {
                plan: record.plan.clone(),
                moves: record
                    .moved_paths
                    .iter()
                    .map(
                        |(original_path, trashed_path)| app_uninstall::AppUninstallJournalMove {
                            original_path: original_path.clone(),
                            trashed_path: trashed_path.clone(),
                        },
                    )
                    .collect(),
            })
            .collect(),
    )
}

fn app_uninstall_records_from_journal(
    journal: app_uninstall::AppUninstallJournal,
) -> Vec<ApplicationUninstallRecord> {
    journal
        .records
        .into_iter()
        .map(|record| ApplicationUninstallRecord {
            plan: record.plan,
            moved_paths: record
                .moves
                .into_iter()
                .map(|item| (item.original_path, item.trashed_path))
                .collect(),
        })
        .collect()
}

fn discover_application_related_paths(app_name: &str) -> Vec<String> {
    app_uninstall::build_uninstall_plan_for_name(app_name).target_paths()
}

fn build_application_uninstall_plan(app_name: &str) -> UninstallPlan {
    app_uninstall::build_uninstall_plan_for_name(app_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use preen_core::smart_care::{SmartCareCapabilitySelection, SmartCareCapabilityStatus};

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
    fn capability_views_are_marked_implemented_and_support_smart_care_controls() {
        for view in [
            ActiveView::Cleanup,
            ActiveView::Protection,
            ActiveView::Performance,
            ActiveView::Applications,
        ] {
            assert!(view.is_implemented());
            assert!(view.supports_smart_care_controls());
            assert!(view.smart_care_capability().is_some());
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
        let mut state = AppState {
            keybindings_popup_scroll: 12,
            ..AppState::default()
        };
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

    #[test]
    fn smart_care_toggle_and_reset_work() {
        let mut state = AppState::default();
        assert_eq!(
            state
                .smart_care_profile
                .capabilities
                .iter()
                .filter(|selection| selection.enabled)
                .count(),
            4
        );
        state.smart_care_toggle_capability(SmartCareCapability::Cleanup);
        assert!(
            state
                .smart_care_profile
                .capabilities
                .iter()
                .find(|selection| selection.capability == SmartCareCapability::Cleanup)
                .is_some_and(|selection| !selection.enabled)
        );
        state.smart_care_reset_profile();
        assert!(
            state
                .smart_care_profile
                .capabilities
                .iter()
                .find(|selection| selection.capability == SmartCareCapability::Cleanup)
                .is_some_and(|selection| selection.enabled)
        );
    }

    #[test]
    fn smart_care_local_analyze_requires_trusted_plugin() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        }];
        state.smart_care_profile = SmartCareProfile {
            id: "test".to_string(),
            name: "Test".to_string(),
            capabilities: vec![SmartCareCapabilitySelection::enabled(
                SmartCareCapability::Cleanup,
            )],
        };

        state.smart_care_run_local_analyze();
        assert!(
            state
                .smart_care_last_analyze
                .iter()
                .any(|line| line == "overall: ready")
        );
        assert!(
            state
                .smart_care_last_analyze
                .iter()
                .any(|line| line.contains("plan: preen-rs.cleanup.base@1.0.0"))
        );
    }

    #[test]
    fn smart_care_local_analyze_is_ready_for_all_capabilities() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.cleanup.base".to_string(),
                capability: SmartCareCapability::Cleanup,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.performance.base".to_string(),
                capability: SmartCareCapability::Performance,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.applications.base".to_string(),
                capability: SmartCareCapability::Applications,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.protection.base".to_string(),
                capability: SmartCareCapability::Protection,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
        ];

        state.smart_care_run_local_analyze();
        assert!(
            state
                .smart_care_last_analyze
                .iter()
                .any(|line| line == "overall: ready")
        );

        let preview = state.smart_care_current_preview();
        assert!(preview.overall_ready);
        for capability in [
            SmartCareCapability::Cleanup,
            SmartCareCapability::Performance,
            SmartCareCapability::Applications,
            SmartCareCapability::Protection,
        ] {
            let card = preview
                .cards
                .iter()
                .find(|card| card.capability == capability)
                .unwrap();
            assert_eq!(card.status, SmartCareCapabilityStatus::Ready);
        }

        state.smart_care_open_review();
        assert_eq!(state.smart_care_review_selected_count(), 4);

        state.smart_care_run_local_execute();
        assert!(
            state
                .smart_care_last_run_report
                .iter()
                .any(|line| line == "capability=cleanup entries=1")
        );
        assert!(
            state
                .smart_care_last_run_report
                .iter()
                .any(|line| line == "capability=performance entries=1")
        );
        assert!(
            state
                .smart_care_last_run_report
                .iter()
                .any(|line| line == "capability=applications entries=1")
        );
        assert!(
            state
                .smart_care_last_run_report
                .iter()
                .any(|line| line == "capability=protection entries=1")
        );
    }

    #[test]
    fn smart_care_local_execute_and_undo_emit_report() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        }];
        state.smart_care_profile = SmartCareProfile {
            id: "test".to_string(),
            name: "Test".to_string(),
            capabilities: vec![SmartCareCapabilitySelection::enabled(
                SmartCareCapability::Cleanup,
            )],
        };

        state.smart_care_run_local_analyze();
        state.smart_care_open_review();
        state.smart_care_run_local_execute();
        assert!(
            state
                .smart_care_last_run_report
                .iter()
                .any(|line| line.starts_with("run: local-dry-run-"))
        );
        assert!(state.smart_care_review_mode);

        state.smart_care_run_local_undo();
        assert!(
            state
                .smart_care_last_run_report
                .iter()
                .any(|line| line == "undo: local-dry-run rollback")
        );
    }

    #[test]
    fn smart_care_previous_card_moves_to_previous_index() {
        let mut state = AppState::default();
        state.smart_care_selected_card = 3;
        state.smart_care_select_previous_card();
        assert_eq!(state.smart_care_selected_card, 2);

        state.smart_care_selected_card = 0;
        state.smart_care_select_previous_card();
        assert_eq!(state.smart_care_selected_card, 3);
    }

    #[test]
    fn smart_care_review_requires_analyze_before_open() {
        let mut state = AppState::default();
        state.smart_care_open_review();
        assert!(!state.smart_care_review_mode);
        assert!(!state.smart_care_has_review_result);
        assert!(
            state
                .last_error
                .as_deref()
                .is_some_and(|line| line.contains("run analyze first"))
        );

        state.smart_care_run_local_analyze();
        state.smart_care_open_review();
        assert!(state.smart_care_review_mode);
        assert!(state.smart_care_has_review_result);
    }

    #[test]
    fn smart_care_review_toggle_affects_selected_count() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.cleanup.base".to_string(),
                capability: SmartCareCapability::Cleanup,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.performance.base".to_string(),
                capability: SmartCareCapability::Performance,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.1.0".to_string()),
            },
        ];
        state.smart_care_run_local_analyze();
        state.smart_care_open_review();
        assert_eq!(state.smart_care_review_selected_count(), 2);

        state.smart_care_review_toggle_selected_entry();
        assert_eq!(state.smart_care_review_selected_count(), 1);
        state.smart_care_review_select_next_entry();
        state.smart_care_review_toggle_selected_entry();
        assert_eq!(state.smart_care_review_selected_count(), 0);

        state.smart_care_review_select_all_entries();
        assert_eq!(state.smart_care_review_selected_count(), 2);
    }

    #[test]
    fn smart_care_review_changes_disarm_apply() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        }];
        state.smart_care_run_local_analyze();
        state.smart_care_open_review();
        state.smart_care_arm_apply();
        assert!(state.smart_care_apply_armed);

        state.smart_care_review_toggle_selected_entry();
        assert!(!state.smart_care_apply_armed);

        state.smart_care_arm_apply();
        state.smart_care_review_select_all_entries();
        assert!(!state.smart_care_apply_armed);

        state.smart_care_arm_apply();
        state.smart_care_review_unselect_all_entries();
        assert!(!state.smart_care_apply_armed);
    }

    #[test]
    fn smart_care_review_toggle_capability_entries_toggles_group() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.cleanup.base".to_string(),
                capability: SmartCareCapability::Cleanup,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.performance.base".to_string(),
                capability: SmartCareCapability::Performance,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
        ];
        state.smart_care_run_local_analyze();
        state.smart_care_open_review();
        assert_eq!(state.smart_care_review_selected_count(), 2);

        state.smart_care_review_toggle_capability_entries(SmartCareCapability::Cleanup);
        assert_eq!(state.smart_care_review_selected_count(), 1);

        state.smart_care_review_toggle_capability_entries(SmartCareCapability::Cleanup);
        assert_eq!(state.smart_care_review_selected_count(), 2);
    }

    #[test]
    fn descriptor_snapshot_refresh_invalidates_stale_analyze_state_when_changed() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        }];
        state.smart_care_source_summary = Some("state-only (packs=1)".to_string());
        state.smart_care_run_local_analyze();
        state.smart_care_open_review();
        state.smart_care_arm_apply();
        assert!(state.smart_care_has_analyze_result);
        assert!(state.smart_care_review_mode);
        assert!(state.smart_care_apply_armed);

        state.apply_smart_care_descriptor_snapshot(
            vec![SmartCarePluginDescriptor {
                pack_id: "preen-rs.cleanup.base".to_string(),
                capability: SmartCareCapability::Cleanup,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.1.0".to_string()),
            }],
            None,
            Some("state-only (packs=1)".to_string()),
            BTreeSet::new(),
            BTreeSet::new(),
        );

        assert!(!state.smart_care_has_analyze_result);
        assert!(!state.smart_care_has_review_result);
        assert!(!state.smart_care_review_mode);
        assert!(!state.smart_care_apply_armed);
        assert!(state.smart_care_preview.is_none());
        assert!(state.smart_care_last_analyze.is_empty());
    }

    #[test]
    fn descriptor_snapshot_refresh_keeps_analyze_state_when_unchanged() {
        let mut state = AppState::default();
        let descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        }];
        state.smart_care_descriptors = descriptors.clone();
        state.smart_care_source_summary = Some("state-only (packs=1)".to_string());
        state.smart_care_run_local_analyze();
        state.smart_care_open_review();
        state.smart_care_arm_apply();

        state.apply_smart_care_descriptor_snapshot(
            descriptors,
            None,
            Some("state-only (packs=1)".to_string()),
            BTreeSet::new(),
            BTreeSet::new(),
        );

        assert!(state.smart_care_has_analyze_result);
        assert!(state.smart_care_has_review_result);
        assert!(state.smart_care_review_mode);
        assert!(state.smart_care_apply_armed);
        assert!(state.smart_care_preview.is_some());
    }

    #[test]
    fn smart_care_run_is_blocked_until_review_is_opened() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        }];
        state.smart_care_profile = SmartCareProfile {
            id: "test".to_string(),
            name: "Test".to_string(),
            capabilities: vec![SmartCareCapabilitySelection::enabled(
                SmartCareCapability::Cleanup,
            )],
        };

        state.smart_care_run_local_analyze();
        state.smart_care_run_local_execute();

        assert!(
            state
                .smart_care_last_run_report
                .iter()
                .any(|line| line == "reason: review is required before run")
        );

        state.smart_care_open_review();
        state.smart_care_run_local_execute();

        assert!(
            state
                .smart_care_last_run_report
                .iter()
                .any(|line| line.starts_with("run: local-dry-run-"))
        );
    }

    #[test]
    fn smart_care_validate_run_request_covers_main_blockers() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        }];
        state.smart_care_profile = SmartCareProfile {
            id: "test".to_string(),
            name: "Test".to_string(),
            capabilities: vec![SmartCareCapabilitySelection::enabled(
                SmartCareCapability::Cleanup,
            )],
        };

        let review_error = state.smart_care_validate_run_request().unwrap_err();
        assert!(review_error.contains("review"));

        state.smart_care_run_local_analyze();
        state.smart_care_open_review();
        let arm_error = state.smart_care_validate_run_request().unwrap_err();
        assert!(arm_error.contains("Shift+X"));

        state.smart_care_arm_apply();
        assert!(state.smart_care_validate_run_request().is_ok());

        state.smart_care_review_unselect_all_entries();
        state.smart_care_arm_apply();
        let selection_error = state.smart_care_validate_run_request().unwrap_err();
        assert!(selection_error.contains("review entry"));
    }

    #[test]
    fn selected_capability_and_preferred_spec_follow_active_context() {
        let mut state = AppState::default();
        state.smart_care_descriptors = vec![
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.cleanup.alt".to_string(),
                capability: SmartCareCapability::Cleanup,
                enabled: true,
                trusted_identity: None,
                version: Some("2.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.cleanup.base".to_string(),
                capability: SmartCareCapability::Cleanup,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
        ];
        state.active_view = ActiveView::SmartCare;
        state.smart_care_selected_card = 0;

        assert_eq!(
            state.smart_care_selected_capability(),
            Some(SmartCareCapability::Cleanup)
        );
        assert_eq!(
            state.preferred_plugin_spec_for_active_smart_care_context(),
            Some("preen-rs.cleanup.base@1.0.0".to_string())
        );

        state.active_view = ActiveView::Performance;
        assert_eq!(
            state.smart_care_selected_capability(),
            Some(SmartCareCapability::Performance)
        );
        assert_eq!(
            state.preferred_plugin_spec_for_active_smart_care_context(),
            Some("preen-rs.performance.base".to_string())
        );
    }
}
