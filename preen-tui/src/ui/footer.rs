use crate::model::{ActiveView, AppState};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const DONATE_URL: &str = "Donate";
const ASK_QUESTION_URL: &str = "Ask Question";
const REPO_URL: &str = "https://github.com/Preen-rs/preen";
const FOOTER_HEIGHT: u16 = 2;
const FOOTER_LEFT_PADDING: u16 = 1;
const FOOTER_RIGHT_PADDING: u16 = 2;

pub enum FooterLinkTarget {
    Donate,
    AskQuestion,
}

pub fn repo_url_for_footer_link(_target: FooterLinkTarget) -> &'static str {
    REPO_URL
}

pub(super) fn render_footer(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let bg_style = Style::default()
        .bg(Color::Rgb(32, 35, 48))
        .fg(Color::Rgb(191, 148, 255));
    frame.render_widget(
        Paragraph::new(" ".repeat(area.width as usize)).style(bg_style),
        area,
    );
    let text_row = Rect {
        x: area.x,
        y: area.y.saturating_add(area.height.saturating_sub(1)),
        width: area.width,
        height: 1,
    };
    let content_row = footer_content_row(text_row);

    let left_text = footer_context_text(state);
    frame.render_widget(
        Paragraph::new(format!(" {left_text}")).style(bg_style),
        content_row,
    );
    frame.render_widget(
        Paragraph::new(footer_right_line())
            .style(Style::default().bg(Color::Rgb(32, 35, 48)))
            .alignment(Alignment::Right),
        content_row,
    );
}

pub(super) fn render_keybindings_popup(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let popup_area = centered_rect(80, 72, area);
    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .title(" Keybindings ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::LightGreen));

    let lines = keybindings_popup_lines(state.active_view);
    let viewport_height = popup_area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(viewport_height) as u16;
    let effective_scroll = state.keybindings_popup_scroll.min(max_scroll);
    let paragraph = Paragraph::new(lines)
        .block(block)
        .scroll((effective_scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, popup_area);
}

pub fn footer_link_at(root: Rect, column: u16, row: u16) -> Option<FooterLinkTarget> {
    let footer_outer = layout_footer_outer(root)?;
    let text_row = footer_outer
        .y
        .saturating_add(footer_outer.height.saturating_sub(1));
    if row != text_row {
        return None;
    }
    let content_row = footer_content_row(Rect {
        x: footer_outer.x,
        y: text_row,
        width: footer_outer.width,
        height: 1,
    });
    let text = footer_right_plain_text();
    let text_width = text.len() as u16;
    let start = content_row
        .x
        .saturating_add(content_row.width.saturating_sub(text_width));
    let donate_start = start;
    let donate_end = donate_start.saturating_add(DONATE_URL.len() as u16);
    if column >= donate_start && column < donate_end {
        return Some(FooterLinkTarget::Donate);
    }

    let ask_start = donate_end.saturating_add(2);
    let ask_end = ask_start.saturating_add(ASK_QUESTION_URL.len() as u16);
    if column >= ask_start && column < ask_end {
        return Some(FooterLinkTarget::AskQuestion);
    }
    None
}

pub(super) fn footer_height() -> u16 {
    FOOTER_HEIGHT
}

fn footer_right_line() -> Line<'static> {
    Line::from(vec![
        Span::styled(
            DONATE_URL,
            Style::default()
                .fg(Color::Rgb(247, 114, 205))
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        ),
        Span::raw("  "),
        Span::styled(
            ASK_QUESTION_URL,
            Style::default()
                .fg(Color::Rgb(248, 244, 143))
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        ),
        Span::raw("  "),
        Span::styled(
            format!("v{APP_VERSION}"),
            Style::default()
                .fg(Color::Rgb(191, 191, 191))
                .add_modifier(Modifier::BOLD),
        ),
    ])
}

fn footer_right_plain_text() -> String {
    format!("{DONATE_URL}  {ASK_QUESTION_URL}  v{APP_VERSION}")
}

fn footer_context_text(state: &AppState) -> String {
    if state.show_keybindings_popup {
        return "Popup: j/k or Up/Down scroll | Close: ? / Esc".to_string();
    }
    match state.active_view {
        ActiveView::Dashboard => {
            "Dashboard: d | Plugins: p | Checks: c | Menu: Tab/Shift+Tab | Quit: q | Keybinding: ?"
                .to_string()
        }
        ActiveView::Plugins => {
            "Plugins: p | Edit spec: e | Run: l/s/i/f/t/n | Dashboard: d | Checks: c | Keybinding: ?"
                .to_string()
        }
        ActiveView::Checks => {
            "Checks: c | Scroll: j/k PgUp/PgDn | Dashboard: d | Plugins: p | Keybinding: ?"
                .to_string()
        }
        _ => format!(
            "{} (soon) | Dashboard: d | Plugins: p | Checks: c | Menu: Tab/Shift+Tab | Keybinding: ?",
            state.active_view.title()
        ),
    }
}

fn keybindings_popup_lines(view: ActiveView) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Global"),
        Line::from("  q / Esc      Quit app"),
        Line::from("  r            Refresh snapshot now"),
        Line::from("  d / p / c    Open Dashboard/Plugins/Checks"),
        Line::from("  Tab          Next menu (full sidebar cycle)"),
        Line::from("  Shift+Tab    Previous menu (full sidebar cycle)"),
        Line::from("  Left/Right   Switch menu"),
        Line::from("  j/k          Scroll main container"),
        Line::from("  Up/Down      Scroll main container"),
        Line::from("  PgUp/PgDn    Fast scroll"),
        Line::from("  g            Scroll to top"),
        Line::from("  ?            Open/close this popup"),
        Line::from(""),
        Line::from("Popup Navigation"),
        Line::from("  j/k or Up/Down  Scroll inside popup"),
        Line::from("  PgUp/PgDn       Fast scroll inside popup"),
        Line::from("  Esc or ?        Close popup"),
        Line::from(""),
    ];

    match view {
        ActiveView::Dashboard => {
            lines.push(Line::from("Current menu: Dashboard"));
            lines.push(Line::from("  Realtime system status and health overview."));
        }
        ActiveView::Plugins => {
            lines.push(Line::from("Current menu: Plugins"));
            lines.push(Line::from("  e             Edit plugin spec"));
            lines.push(Line::from("  l             plugin list"));
            lines.push(Line::from("  s             plugin search"));
            lines.push(Line::from("  i             plugin info <spec>"));
            lines.push(Line::from("  f             plugin preflight <spec>"));
            lines.push(Line::from("  t             plugin test <spec>"));
            lines.push(Line::from("  n             plugin install <spec>"));
            lines.push(Line::from(
                "  Shows installed plugins from lockfile and identity/rev.",
            ));
        }
        ActiveView::Checks => {
            lines.push(Line::from("Current menu: Checks"));
            lines.push(Line::from(
                "  Shows detailed checks with severity and messages.",
            ));
        }
        _ => {
            lines.push(Line::from(format!(
                "Current menu: {} (planned)",
                view.title()
            )));
            lines.push(Line::from(
                "  This view is scaffolded; implementation is in roadmap.",
            ));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Links"));
    lines.push(Line::from("  Donate: https://github.com/sponsors/Preen-rs"));
    lines.push(Line::from(
        "  Ask Question: https://github.com/Preen-rs/preen/issues",
    ));
    lines
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1]);
    horizontal[1]
}

fn layout_footer_outer(root: Rect) -> Option<Rect> {
    if root.height < FOOTER_HEIGHT {
        return None;
    }
    let footer_y = root
        .y
        .saturating_add(root.height.saturating_sub(FOOTER_HEIGHT));
    Some(Rect {
        x: root.x,
        y: footer_y,
        width: root.width,
        height: FOOTER_HEIGHT,
    })
}

fn footer_content_row(row: Rect) -> Rect {
    let total_pad = FOOTER_LEFT_PADDING.saturating_add(FOOTER_RIGHT_PADDING);
    if row.width <= total_pad {
        return row;
    }
    Rect {
        x: row.x.saturating_add(FOOTER_LEFT_PADDING),
        y: row.y,
        width: row.width.saturating_sub(total_pad),
        height: row.height,
    }
}
