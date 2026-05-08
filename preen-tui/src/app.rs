use crate::model::{ActiveView, AppState, PluginActionKind, SmartCareCapability};
use crate::ui;
use crate::worker::{StatusWorker, WorkerEvent};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use std::io::{self, Stdout};
use std::process::Command as ProcessCommand;
use std::time::Duration;

pub fn run() -> Result<(), String> {
    let mut terminal = setup_terminal()?;
    let run_result = run_loop(&mut terminal);
    let restore_result = restore_terminal(&mut terminal);

    match (run_result, restore_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(_), Ok(_)) => Ok(()),
    }
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<(), String> {
    let (mut worker, worker_rx) = StatusWorker::spawn(Duration::from_secs(1));
    worker.refresh_now();
    let mut state = AppState::default();

    loop {
        while let Ok(event) = worker_rx.try_recv() {
            match event {
                WorkerEvent::Snapshot {
                    snapshot,
                    smart_care_descriptors,
                    smart_care_error,
                    smart_care_source_summary,
                    smart_care_skipped_pack_ids,
                    smart_care_dev_fallback_pack_ids,
                } => {
                    let snapshot = *snapshot;
                    if state.plugin_spec.is_empty()
                        && let Some(plugin) = snapshot.plugins.first()
                    {
                        state.plugin_spec = format!("{}@{}", plugin.pack_id, plugin.version);
                    }
                    state.snapshot = Some(snapshot);
                    state.applications_sync_selection();
                    state.apply_smart_care_descriptor_snapshot(
                        smart_care_descriptors,
                        smart_care_error,
                        smart_care_source_summary,
                        smart_care_skipped_pack_ids.into_iter().collect(),
                        smart_care_dev_fallback_pack_ids.into_iter().collect(),
                    );
                    state.last_error = None;
                }
                WorkerEvent::Error(error) => {
                    if state.smart_care_action_running {
                        state.clear_smart_care_action_state();
                    }
                    state.clear_busy_view();
                    state.last_error = Some(error);
                }
                WorkerEvent::PluginActionResult { action, ok, lines } => {
                    state.apply_plugin_command_result(action, ok, lines);
                    if !ok {
                        state.last_error = Some(format!("plugin {} failed", action.label()));
                    } else if matches!(action, PluginActionKind::Install) {
                        worker.refresh_now();
                    }
                }
                WorkerEvent::ApplicationsInventoryAnalyzeResult { applications } => {
                    state.apply_applications_inventory_analyze_result(applications);
                    state.last_error = None;
                }
                WorkerEvent::SmartCareAnalyzeResult { preview, lines } => {
                    state.apply_smart_care_analyze_result(preview, lines);
                    state.last_error = None;
                }
                WorkerEvent::SmartCareRunResult { lines } => {
                    state.apply_smart_care_run_result(lines);
                    state.last_error = None;
                }
                WorkerEvent::SmartCareUndoResult { lines } => {
                    state.apply_smart_care_undo_result(lines);
                    state.last_error = None;
                }
            }
        }

        state.advance_ui_tick();
        terminal
            .draw(|frame| ui::render(frame, &state))
            .map_err(|error| error.to_string())?;

        if event::poll(Duration::from_millis(120)).map_err(|error| error.to_string())? {
            match event::read().map_err(|error| error.to_string())? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    if state.show_keybindings_popup {
                        match key.code {
                            KeyCode::Esc => state.close_keybindings_popup(),
                            KeyCode::Char('?') => state.toggle_keybindings_popup(),
                            KeyCode::Char('j') | KeyCode::Down => state.scroll_keybindings_down(1),
                            KeyCode::Char('k') | KeyCode::Up => state.scroll_keybindings_up(1),
                            KeyCode::PageDown => state.scroll_keybindings_down(10),
                            KeyCode::PageUp => state.scroll_keybindings_up(10),
                            KeyCode::Char('g') => state.keybindings_popup_scroll = 0,
                            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                                worker.shutdown();
                                return Ok(());
                            }
                            _ => {}
                        }
                        continue;
                    }

                    if state.show_info_popup && state.active_view.supports_smart_care_controls() {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('i') => state.close_info_popup(),
                            KeyCode::Char('p')
                                if key.modifiers == KeyModifiers::NONE
                                    && matches!(state.active_view, ActiveView::Applications)
                                    && state.applications_show_paths_in_info =>
                            {
                                state.close_info_popup();
                            }
                            KeyCode::Char('r')
                                if key.modifiers == KeyModifiers::NONE
                                    && matches!(state.active_view, ActiveView::Applications) =>
                            {
                                state.close_info_popup();
                                dispatch_applications_inventory_analyze(&mut state, &worker);
                            }
                            KeyCode::Char('j') | KeyCode::Down => state.scroll_info_popup_down(1),
                            KeyCode::Char('k') | KeyCode::Up => state.scroll_info_popup_up(1),
                            KeyCode::PageDown => state.scroll_info_popup_down(10),
                            KeyCode::PageUp => state.scroll_info_popup_up(10),
                            KeyCode::Char('g') => state.info_popup_scroll = 0,
                            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                                worker.shutdown();
                                return Ok(());
                            }
                            _ => {}
                        }
                        continue;
                    }

                    if state.applications_uninstall_confirm
                        && matches!(state.active_view, ActiveView::Applications)
                    {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('n') => {
                                state.applications_cancel_uninstall_confirm();
                            }
                            KeyCode::Enter | KeyCode::Char('y') => {
                                if let Err(error) = state.applications_confirm_uninstall_selected()
                                {
                                    state.last_error = Some(error);
                                } else {
                                    state.last_error = None;
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }

                    if state.plugin_spec_editing {
                        match key.code {
                            KeyCode::Esc => state.end_plugin_spec_edit(),
                            KeyCode::Enter => state.end_plugin_spec_edit(),
                            KeyCode::Backspace => state.pop_plugin_spec_char(),
                            KeyCode::Char(ch)
                                if key.modifiers == KeyModifiers::NONE
                                    || key.modifiers == KeyModifiers::SHIFT =>
                            {
                                state.push_plugin_spec_char(ch);
                            }
                            _ => {}
                        }
                        continue;
                    }

                    if state.smart_care_review_mode
                        && state.active_view.supports_smart_care_controls()
                    {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('v') => {
                                state.smart_care_close_review();
                            }
                            KeyCode::Char('j') | KeyCode::Down => {
                                state.smart_care_scroll_review_down(1);
                            }
                            KeyCode::Char('k') | KeyCode::Up => {
                                state.smart_care_scroll_review_up(1);
                            }
                            KeyCode::PageDown => state.smart_care_scroll_review_down(10),
                            KeyCode::PageUp => state.smart_care_scroll_review_up(10),
                            KeyCode::Char('g') => state.smart_care_scroll_review_to_top(),
                            KeyCode::Char('h') if key.modifiers == KeyModifiers::NONE => {
                                state.smart_care_review_select_next_entry();
                            }
                            KeyCode::Char('l') if key.modifiers == KeyModifiers::NONE => {
                                state.smart_care_review_select_previous_entry();
                            }
                            KeyCode::Char(' ') if key.modifiers == KeyModifiers::NONE => {
                                state.smart_care_review_toggle_selected_entry();
                            }
                            KeyCode::Char('A') if key.modifiers == KeyModifiers::SHIFT => {
                                state.smart_care_review_select_all_entries();
                            }
                            KeyCode::Char('N') if key.modifiers == KeyModifiers::SHIFT => {
                                state.smart_care_review_unselect_all_entries();
                            }
                            KeyCode::Char('1') if key.modifiers == KeyModifiers::NONE => {
                                state.smart_care_review_toggle_capability_entries(
                                    SmartCareCapability::Cleanup,
                                );
                            }
                            KeyCode::Char('2') if key.modifiers == KeyModifiers::NONE => {
                                state.smart_care_review_toggle_capability_entries(
                                    SmartCareCapability::Performance,
                                );
                            }
                            KeyCode::Char('3') if key.modifiers == KeyModifiers::NONE => {
                                state.smart_care_review_toggle_capability_entries(
                                    SmartCareCapability::Applications,
                                );
                            }
                            KeyCode::Char('4') if key.modifiers == KeyModifiers::NONE => {
                                state.smart_care_review_toggle_capability_entries(
                                    SmartCareCapability::Protection,
                                );
                            }
                            KeyCode::Char('a') if key.modifiers == KeyModifiers::NONE => {
                                dispatch_smart_care_analyze(&mut state, &worker, true);
                            }
                            KeyCode::Char('x') if key.modifiers == KeyModifiers::NONE => {
                                dispatch_smart_care_run(&mut state, &worker);
                            }
                            KeyCode::Char('X') if key.modifiers == KeyModifiers::SHIFT => {
                                state.smart_care_arm_apply();
                                state.last_error = None;
                            }
                            KeyCode::Char('u') if key.modifiers == KeyModifiers::NONE => {
                                dispatch_smart_care_undo(&mut state, &worker);
                            }
                            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                                worker.shutdown();
                                return Ok(());
                            }
                            _ => {}
                        }
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            worker.shutdown();
                            return Ok(());
                        }
                        KeyCode::Char('p')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Applications) =>
                        {
                            if state.smart_care_has_analyze_result {
                                state.applications_toggle_paths_popup();
                            } else {
                                state.last_error = Some(
                                    "aval ba 'a' analyze kon, bad ba 'p' app paths ro bebin"
                                        .to_string(),
                                );
                            }
                        }
                        KeyCode::Char('r')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Applications) =>
                        {
                            if state.smart_care_has_analyze_result {
                                dispatch_applications_inventory_analyze(&mut state, &worker);
                            } else {
                                state.last_error = Some(
                                    "aval ba 'a' analyze kon, bad ba 'r' reanalyze kon".to_string(),
                                );
                            }
                        }
                        KeyCode::Char('r') => worker.refresh_now(),
                        KeyCode::Char('?') => state.toggle_keybindings_popup(),
                        KeyCode::Char('j') | KeyCode::Down
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Applications)
                                && state.smart_care_has_analyze_result =>
                        {
                            state.applications_select_next();
                        }
                        KeyCode::Char('k') | KeyCode::Up
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Applications)
                                && state.smart_care_has_analyze_result =>
                        {
                            state.applications_select_previous();
                        }
                        KeyCode::Char('j') | KeyCode::Down => state.scroll_down(1),
                        KeyCode::Char('k') | KeyCode::Up => state.scroll_up(1),
                        KeyCode::PageDown => state.scroll_down(10),
                        KeyCode::PageUp => state.scroll_up(10),
                        KeyCode::Char('g') => state.scroll_to_top(),
                        KeyCode::Tab | KeyCode::Right => {
                            let next = state.active_view.next();
                            state.set_active_view(next);
                        }
                        KeyCode::BackTab | KeyCode::Left => {
                            let previous = state.active_view.previous();
                            state.set_active_view(previous);
                        }
                        KeyCode::Char('d') if key.modifiers == KeyModifiers::NONE => {
                            state.set_active_view(ActiveView::Dashboard)
                        }
                        KeyCode::Char('m') if key.modifiers == KeyModifiers::NONE => {
                            state.set_active_view(ActiveView::SmartCare)
                        }
                        KeyCode::Char('p') if key.modifiers == KeyModifiers::NONE => {
                            state.set_active_view(ActiveView::Plugins)
                        }
                        KeyCode::Char('c') if key.modifiers == KeyModifiers::NONE => {
                            state.set_active_view(ActiveView::Checks)
                        }
                        KeyCode::Char('e')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Plugins) =>
                        {
                            state.begin_plugin_spec_edit();
                        }
                        KeyCode::Char('1')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            state.smart_care_toggle_capability(
                                crate::model::SmartCareCapability::Cleanup,
                            );
                        }
                        KeyCode::Char('2')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            state.smart_care_toggle_capability(
                                crate::model::SmartCareCapability::Performance,
                            );
                        }
                        KeyCode::Char('3')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            state.smart_care_toggle_capability(
                                crate::model::SmartCareCapability::Applications,
                            );
                        }
                        KeyCode::Char('4')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            state.smart_care_toggle_capability(
                                crate::model::SmartCareCapability::Protection,
                            );
                        }
                        KeyCode::Char('a')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Applications) =>
                        {
                            dispatch_applications_inventory_analyze(&mut state, &worker);
                        }
                        KeyCode::Char('a')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            dispatch_smart_care_analyze(&mut state, &worker, false);
                        }
                        KeyCode::Char('v')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            state.smart_care_open_review();
                        }
                        KeyCode::Char('b')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            state.smart_care_close_review();
                        }
                        KeyCode::Char('x')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Applications) =>
                        {
                            state.last_error = Some(
                                "update flow dar hale hazer tayyar nist; alan uninstall ba 'u' faal ast"
                                    .to_string(),
                            );
                        }
                        KeyCode::Char('x')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            dispatch_smart_care_run(&mut state, &worker);
                        }
                        KeyCode::Char('X')
                            if key.modifiers == KeyModifiers::SHIFT
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            state.smart_care_arm_apply();
                            state.last_error = None;
                        }
                        KeyCode::Char('u')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Applications) =>
                        {
                            if let Err(error) = state.applications_open_uninstall_confirm() {
                                state.last_error = Some(error);
                            } else {
                                state.last_error = None;
                            }
                        }
                        KeyCode::Char('z')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Applications) =>
                        {
                            if let Err(error) = state.applications_undo_last_uninstall() {
                                state.last_error = Some(error);
                            } else {
                                state.last_error = None;
                            }
                        }
                        KeyCode::Char('u')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            dispatch_smart_care_undo(&mut state, &worker);
                        }
                        KeyCode::Char('n')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            dispatch_smart_care_capability_plugin_action(
                                &mut state,
                                &worker,
                                PluginActionKind::Install,
                            );
                        }
                        KeyCode::Char('f')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            dispatch_smart_care_capability_plugin_action(
                                &mut state,
                                &worker,
                                PluginActionKind::Preflight,
                            );
                        }
                        KeyCode::Char('t')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            dispatch_smart_care_capability_plugin_action(
                                &mut state,
                                &worker,
                                PluginActionKind::Test,
                            );
                        }
                        KeyCode::Char('h')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls()
                                && !state.smart_care_review_mode =>
                        {
                            state.smart_care_select_next_card();
                        }
                        KeyCode::Char('l')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls()
                                && !state.smart_care_review_mode =>
                        {
                            state.smart_care_select_previous_card();
                        }
                        KeyCode::Char(' ')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Applications)
                                && state.smart_care_has_analyze_result =>
                        {
                            state.applications_toggle_selected();
                        }
                        KeyCode::Char(' ')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls()
                                && !state.smart_care_review_mode =>
                        {
                            state.smart_care_toggle_selected_card();
                        }
                        KeyCode::Char('0')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls() =>
                        {
                            state.smart_care_reset_profile();
                        }
                        KeyCode::Char('l')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Plugins) =>
                        {
                            dispatch_plugin_action(&mut state, &worker, PluginActionKind::List);
                        }
                        KeyCode::Char('s')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Plugins) =>
                        {
                            dispatch_plugin_action(&mut state, &worker, PluginActionKind::Search);
                        }
                        KeyCode::Char('i')
                            if key.modifiers == KeyModifiers::NONE
                                && state.active_view.supports_smart_care_controls()
                                && !state.smart_care_review_mode =>
                        {
                            state.toggle_info_popup();
                        }
                        KeyCode::Char('i')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Plugins) =>
                        {
                            dispatch_plugin_action(&mut state, &worker, PluginActionKind::Info);
                        }
                        KeyCode::Char('f')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Plugins) =>
                        {
                            dispatch_plugin_action(
                                &mut state,
                                &worker,
                                PluginActionKind::Preflight,
                            );
                        }
                        KeyCode::Char('t')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Plugins) =>
                        {
                            dispatch_plugin_action(&mut state, &worker, PluginActionKind::Test);
                        }
                        KeyCode::Char('n')
                            if key.modifiers == KeyModifiers::NONE
                                && matches!(state.active_view, ActiveView::Plugins) =>
                        {
                            dispatch_plugin_action(&mut state, &worker, PluginActionKind::Install);
                        }
                        KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                            worker.shutdown();
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    let size = terminal.size().map_err(|error| error.to_string())?;
                    let area = Rect::new(0, 0, size.width, size.height);
                    match mouse.kind {
                        MouseEventKind::ScrollDown => {
                            handle_mouse_scroll_down(&mut state, area, mouse.column, mouse.row);
                        }
                        MouseEventKind::ScrollUp => {
                            handle_mouse_scroll_up(&mut state, area, mouse.column, mouse.row);
                        }
                        MouseEventKind::Down(MouseButton::Left) => {
                            if let Some(target) = ui::footer_link_at(area, mouse.column, mouse.row)
                                && let Err(error) = open_footer_link(target)
                            {
                                state.last_error = Some(error);
                                continue;
                            }
                            if state.show_keybindings_popup
                                || (state.show_info_popup
                                    && state.active_view.supports_smart_care_controls())
                                || (state.smart_care_review_mode
                                    && state.active_view.supports_smart_care_controls())
                            {
                                continue;
                            }
                            if let Some(view) = ui::sidebar_view_at(area, mouse.column, mouse.row) {
                                state.set_active_view(view);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
}

fn dispatch_plugin_action(state: &mut AppState, worker: &StatusWorker, action: PluginActionKind) {
    if state.plugin_action_running {
        state.last_error = Some("plugin action already running".to_string());
        return;
    }

    if action.requires_spec() {
        let spec = state.plugin_spec.trim().to_string();
        if spec.is_empty() {
            state.last_error = Some("plugin spec is empty (press e to edit)".to_string());
            return;
        }
        dispatch_plugin_action_with_spec(state, worker, action, spec);
        return;
    }

    state.apply_plugin_command_started(action);
    worker.run_plugin_action(action, None);
}

fn dispatch_plugin_action_with_spec(
    state: &mut AppState,
    worker: &StatusWorker,
    action: PluginActionKind,
    spec: String,
) {
    state.plugin_spec = spec.clone();
    state.apply_plugin_command_started(action);
    worker.run_plugin_action(action, Some(spec));
}

fn dispatch_smart_care_capability_plugin_action(
    state: &mut AppState,
    worker: &StatusWorker,
    action: PluginActionKind,
) {
    if state.plugin_action_running || state.smart_care_action_running {
        state.last_error = Some("background action already running".to_string());
        return;
    }
    let Some(spec) = state.preferred_plugin_spec_for_active_smart_care_context() else {
        state.last_error = Some("no smart care capability selected".to_string());
        return;
    };
    dispatch_plugin_action_with_spec(state, worker, action, spec);
}

fn dispatch_smart_care_analyze(state: &mut AppState, worker: &StatusWorker, reopen_review: bool) {
    if state.smart_care_action_running || state.plugin_action_running {
        state.last_error = Some("background action already running".to_string());
        return;
    }
    if !state.begin_smart_care_action("analyze", reopen_review) {
        state.last_error = Some("smart care action already running".to_string());
        return;
    }
    state.smart_care_disarm_apply();
    worker.run_smart_care_analyze(
        state.smart_care_profile.clone(),
        state.smart_care_descriptors.clone(),
    );
}

fn dispatch_smart_care_run(state: &mut AppState, worker: &StatusWorker) {
    if state.smart_care_action_running || state.plugin_action_running {
        state.last_error = Some("background action already running".to_string());
        return;
    }
    if !state.begin_smart_care_action("run", false) {
        state.last_error = Some("smart care action already running".to_string());
        return;
    }
    if let Err(error) = state.smart_care_validate_run_request() {
        state.clear_smart_care_action_state();
        state.last_error = Some(error);
        return;
    }
    worker.run_smart_care_execute(
        state.smart_care_current_preview(),
        state.smart_care_disabled_entry_ids(),
        true,
        true,
    );
    state.smart_care_disarm_apply();
}

fn dispatch_smart_care_undo(state: &mut AppState, worker: &StatusWorker) {
    if state.smart_care_action_running || state.plugin_action_running {
        state.last_error = Some("background action already running".to_string());
        return;
    }
    if !state.begin_smart_care_action("undo", false) {
        state.last_error = Some("smart care action already running".to_string());
        return;
    }
    state.smart_care_disarm_apply();
    worker.run_smart_care_undo(!state.smart_care_last_run_report.is_empty());
}

fn dispatch_applications_inventory_analyze(state: &mut AppState, worker: &StatusWorker) {
    if state.is_busy() || state.smart_care_action_running || state.plugin_action_running {
        state.last_error = Some("background action already running".to_string());
        return;
    }
    state.begin_busy_view(
        "Analyzing applications",
        "Scanning installed apps and reading uninstall metadata",
        "Applications",
    );
    state.last_error = None;
    worker.run_applications_inventory_analyze();
}

fn handle_mouse_scroll_down(state: &mut AppState, root: Rect, column: u16, row: u16) {
    if state.show_keybindings_popup {
        if rect_contains(ui::keybindings_popup_area(root), column, row) {
            state.scroll_keybindings_down(1);
        }
        return;
    }
    if state.smart_care_review_mode && state.active_view.supports_smart_care_controls() {
        if rect_contains(ui::smart_care_review_popup_area(root), column, row) {
            state.smart_care_scroll_review_down(1);
        }
        return;
    }
    if state.show_info_popup && state.active_view.supports_smart_care_controls() {
        if rect_contains(ui::info_popup_area(root), column, row) {
            state.scroll_info_popup_down(1);
        }
        return;
    }
    if rect_contains(ui::main_container_area(root), column, row) {
        state.scroll_down(1);
    }
}

fn handle_mouse_scroll_up(state: &mut AppState, root: Rect, column: u16, row: u16) {
    if state.show_keybindings_popup {
        if rect_contains(ui::keybindings_popup_area(root), column, row) {
            state.scroll_keybindings_up(1);
        }
        return;
    }
    if state.smart_care_review_mode && state.active_view.supports_smart_care_controls() {
        if rect_contains(ui::smart_care_review_popup_area(root), column, row) {
            state.smart_care_scroll_review_up(1);
        }
        return;
    }
    if state.show_info_popup && state.active_view.supports_smart_care_controls() {
        if rect_contains(ui::info_popup_area(root), column, row) {
            state.scroll_info_popup_up(1);
        }
        return;
    }
    if rect_contains(ui::main_container_area(root), column, row) {
        state.scroll_up(1);
    }
}

fn rect_contains(area: Rect, column: u16, row: u16) -> bool {
    column >= area.x
        && column < area.x.saturating_add(area.width)
        && row >= area.y
        && row < area.y.saturating_add(area.height)
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>, String> {
    enable_raw_mode().map_err(|error| error.to_string())?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|error| error.to_string())?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).map_err(|error| error.to_string())
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<(), String> {
    disable_raw_mode().map_err(|error| error.to_string())?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(|error| error.to_string())?;
    terminal.show_cursor().map_err(|error| error.to_string())
}

fn open_footer_link(target: ui::FooterLinkTarget) -> Result<(), String> {
    let url = ui::repo_url_for_footer_link(target);
    open_url(url)
}

fn open_url(url: &str) -> Result<(), String> {
    let mut command = match std::env::consts::OS {
        "macos" => {
            let mut cmd = ProcessCommand::new("open");
            cmd.arg(url);
            cmd
        }
        "linux" => {
            let mut cmd = ProcessCommand::new("xdg-open");
            cmd.arg(url);
            cmd
        }
        other => return Err(format!("unsupported OS for opening links: {other}")),
    };
    command
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("failed to open browser: {error}"))
}
