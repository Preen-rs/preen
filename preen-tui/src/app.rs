use crate::model::{ActiveView, AppState, PluginActionKind};
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
                WorkerEvent::Snapshot(snapshot) => {
                    if state.plugin_spec.is_empty()
                        && let Some(plugin) = snapshot.plugins.first()
                    {
                        state.plugin_spec = format!("{}@{}", plugin.pack_id, plugin.version);
                    }
                    state.snapshot = Some(snapshot);
                    state.last_error = None;
                }
                WorkerEvent::Error(error) => {
                    state.last_error = Some(error);
                }
                WorkerEvent::PluginActionResult { action, ok, lines } => {
                    state.apply_plugin_command_result(action, ok, lines);
                    if !ok {
                        state.last_error = Some(format!("plugin {} failed", action.label()));
                    }
                }
            }
        }

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

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            worker.shutdown();
                            return Ok(());
                        }
                        KeyCode::Char('r') => worker.refresh_now(),
                        KeyCode::Char('?') => state.toggle_keybindings_popup(),
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
                    if mouse.kind != MouseEventKind::Down(MouseButton::Left) {
                        continue;
                    }
                    let size = terminal.size().map_err(|error| error.to_string())?;
                    let area = Rect::new(0, 0, size.width, size.height);
                    if let Some(target) = ui::footer_link_at(area, mouse.column, mouse.row)
                        && let Err(error) = open_footer_link(target)
                    {
                        state.last_error = Some(error);
                    }
                }
                _ => {}
            }
        }
    }
}

fn dispatch_plugin_action(state: &mut AppState, worker: &StatusWorker, action: PluginActionKind) {
    if action.requires_spec() {
        let spec = state.plugin_spec.trim().to_string();
        if spec.is_empty() {
            state.last_error = Some("plugin spec is empty (press e to edit)".to_string());
            return;
        }
        state.apply_plugin_command_started(action);
        worker.run_plugin_action(action, Some(spec));
        return;
    }

    state.apply_plugin_command_started(action);
    worker.run_plugin_action(action, None);
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
