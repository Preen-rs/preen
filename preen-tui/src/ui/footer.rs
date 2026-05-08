use crate::i18n::TextKey;
use crate::model::{ActiveView, AppState};
use ratatui::Frame;
use ratatui::layout::{Alignment, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::components::wrap_plain_lines;
use super::layout;
use super::{PALETTE_ACCENT, PALETTE_LINE};

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
    let popup_area = keybindings_popup_area(area);
    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .title(" Keybindings ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::LightGreen));
    frame.render_widget(block, popup_area);
    let inner = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });

    let mut viewport_height = inner.height as usize;
    let mut content_width = inner.width as usize;
    let mut lines = wrap_plain_lines(keybindings_popup_lines(state.active_view), content_width);
    if viewport_height > 0 && lines.len() > viewport_height && content_width > 0 {
        content_width = content_width.saturating_sub(1);
        lines = wrap_plain_lines(keybindings_popup_lines(state.active_view), content_width);
    }
    let show_scrollbar = viewport_height > 0 && lines.len() > viewport_height;
    let content_area = if show_scrollbar && inner.width > 1 {
        Rect {
            x: inner.x,
            y: inner.y,
            width: inner.width - 1,
            height: inner.height,
        }
    } else {
        inner
    };
    viewport_height = content_area.height as usize;
    let content_length = lines.len();
    let max_scroll = lines.len().saturating_sub(viewport_height) as u16;
    let effective_scroll = state.keybindings_popup_scroll.min(max_scroll);
    let paragraph = Paragraph::new(lines).scroll((effective_scroll, 0));
    frame.render_widget(paragraph, content_area);
    if show_scrollbar && inner.width > 1 {
        render_popup_vertical_scrollbar(
            frame,
            popup_scrollbar_area(inner),
            viewport_height,
            content_length,
            effective_scroll as usize,
        );
    }
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

pub(super) fn keybindings_popup_area(area: Rect) -> Rect {
    layout::keybindings_popup_area(area)
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
        return "Popup: j/k or Up/Down or wheel scroll | Close: ? / Esc".to_string();
    }
    if state.show_info_popup && state.active_view.supports_smart_care_controls() {
        return "Info: j/k or Up/Down or wheel scroll | Close: i / Esc".to_string();
    }
    if state.smart_care_action_running && state.active_view.supports_smart_care_controls() {
        return format!(
            "Smart Care: {} running... wait for completion | Keybinding: ?",
            state.smart_care_action_label.as_deref().unwrap_or("action")
        );
    }
    if state.plugin_action_running && state.active_view.supports_smart_care_controls() {
        let capability = state
            .smart_care_selected_capability()
            .map(|capability| capability.title())
            .unwrap_or("Smart Care");
        let action = state
            .plugin_last_action
            .map(|action| action.label().to_string())
            .unwrap_or_else(|| "command".to_string());
        return format!(
            "{capability} plugin {action} running... wait for completion | Keybinding: ?"
        );
    }
    if state.smart_care_review_mode && state.active_view.supports_smart_care_controls() {
        return "Review: j/k | space | 1/2/3/4 | A all | N none | Shift+X arm | x run | u undo | close: b/v/Esc | ?: keys".to_string();
    }
    match state.active_view {
        ActiveView::Dashboard => {
            "Dashboard: d | SmartCare: m | Plugins: p | Checks: c | Settings: o | Tab menu | q quit | ?: keys"
                .to_string()
        }
        ActiveView::Settings => state.tr(TextKey::SettingsFooter).to_string(),
        ActiveView::SmartCare => {
            let run_hint = if state.smart_care_validate_run_request().is_ok() {
                "x run"
            } else {
                "x blocked"
            };
            format!(
                "SmartCare: h/l select | space/1/2/3/4 toggle | a analyze | v review | n/f/t plugin | Shift+X arm | {run_hint} | u undo | i info | ?: keys"
            )
        }
        ActiveView::Applications => format!(
            "Applications: a analyze | r reanalyze | j/k move | space select | p paths | u uninstall(selected) | z undo | i info | ?: keys"
        ),
        ActiveView::Cleanup | ActiveView::Protection | ActiveView::Performance => format!(
            "{}: h/l select | space toggle | a analyze | v review | n/f/t plugin | Shift+X arm | {} | u undo | i info | ?: keys",
            state.active_view.title_for_language(state.effective_language()),
            if state.smart_care_validate_run_request().is_ok() {
                "x run"
            } else {
                "x blocked"
            }
        ),
        ActiveView::Plugins => {
            "Plugins: l/s/i/f/t/n | e edit spec | d/m/c switch | q quit | ?: keys".to_string()
        }
        ActiveView::Checks => "Checks: j/k scroll | d/m/p switch | q quit | ?: keys".to_string(),
        _ => format!(
            "{} (soon) | d/m/p/c switch | Tab menu | q quit | ?: keys",
            state.active_view.title_for_language(state.effective_language())
        ),
    }
}

fn keybindings_popup_lines(view: ActiveView) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Global"),
        Line::from("  q / Esc      Quit app"),
        Line::from("  r            Refresh snapshot now"),
        Line::from("  d / m / p / c Open Dashboard/Smart Care/Plugins/Checks"),
        Line::from("  o            Open Settings"),
        Line::from("  Tab          Next menu (full sidebar cycle)"),
        Line::from("  Shift+Tab    Previous menu (full sidebar cycle)"),
        Line::from("  Left/Right   Switch menu"),
        Line::from("  j/k          Scroll main container"),
        Line::from("  Up/Down      Scroll main container"),
        Line::from("  Mouse wheel  Scroll active container/popup"),
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
        ActiveView::SmartCare => {
            lines.push(Line::from("Current menu: Smart Care"));
            lines.push(Line::from(
                "  Shows capability-pack readiness for Smart Care orchestration.",
            ));
            lines.push(Line::from(
                "  1/2/3/4       Toggle Cleanup/Performance/Applications/Protection",
            ));
            lines.push(Line::from(
                "  h/l           Select next/previous capability card",
            ));
            lines.push(Line::from(
                "  space         Toggle selected capability card",
            ));
            lines.push(Line::from("  a             Run local analyze preview"));
            lines.push(Line::from(
                "  v             Open review popup (only after analyze)",
            ));
            lines.push(Line::from(
                "  n / f / t     Install / Preflight / Test selected capability plugin",
            ));
            lines.push(Line::from("  b             Close review mode"));
            lines.push(Line::from("  j/k           Move in review entries"));
            lines.push(Line::from("  space         Toggle selected review entry"));
            lines.push(Line::from(
                "  1/2/3/4       Toggle Cleanup/Performance/Applications/Protection entries",
            ));
            lines.push(Line::from(
                "  A / N         Select all / Unselect all entries",
            ));
            lines.push(Line::from("  Shift+X       Arm apply execution"));
            lines.push(Line::from(
                "  x             Run apply execution (after review + arm)",
            ));
            lines.push(Line::from(
                "  u             Undo last Smart Care run (journal-based)",
            ));
            lines.push(Line::from(
                "  0             Reset Smart Care profile to defaults",
            ));
        }
        ActiveView::Cleanup
        | ActiveView::Protection
        | ActiveView::Performance
        | ActiveView::Applications => {
            lines.push(Line::from(format!("Current menu: {}", view.title())));
            lines.push(Line::from(
                "  Shows installed capability plugins and trust readiness.",
            ));
            lines.push(Line::from(
                "  1/2/3/4       Toggle Cleanup/Performance/Applications/Protection",
            ));
            lines.push(Line::from(
                "  h/l           Select next/previous capability card",
            ));
            lines.push(Line::from(
                "  space         Toggle selected capability card",
            ));
            lines.push(Line::from("  a             Run local analyze preview"));
            lines.push(Line::from(
                "  v             Open review popup (only after analyze)",
            ));
            lines.push(Line::from(
                "  n / f / t     Install / Preflight / Test active capability plugin",
            ));
            lines.push(Line::from("  b             Close review mode"));
            lines.push(Line::from("  j/k           Move in review entries"));
            lines.push(Line::from("  space         Toggle selected review entry"));
            lines.push(Line::from(
                "  1/2/3/4       Toggle Cleanup/Performance/Applications/Protection entries",
            ));
            lines.push(Line::from(
                "  A / N         Select all / Unselect all entries",
            ));
            lines.push(Line::from("  Shift+X       Arm apply execution"));
            lines.push(Line::from(
                "  x             Run apply execution (after review + arm)",
            ));
            lines.push(Line::from(
                "  u             Undo last Smart Care run (journal-based)",
            ));
            lines.push(Line::from("  m             Jump to Smart Care dashboard"));
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
        ActiveView::Settings => {
            lines.push(Line::from("Current menu: Settings"));
            lines.push(Line::from("  l             Cycle language preference"));
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

fn render_popup_vertical_scrollbar(
    frame: &mut Frame<'_>,
    track: Rect,
    viewport_height: usize,
    content_length: usize,
    position: usize,
) {
    if track.width == 0
        || track.height == 0
        || viewport_height == 0
        || content_length <= viewport_height
    {
        return;
    }

    let track_height = track.height as usize;
    let max_scroll = content_length.saturating_sub(viewport_height);
    let thumb_height =
        ((viewport_height * track_height).div_ceil(content_length)).clamp(1, track_height);
    let max_thumb_offset = track_height.saturating_sub(thumb_height);
    let thumb_offset = if max_scroll == 0 {
        0
    } else {
        position.min(max_scroll) * max_thumb_offset / max_scroll
    };
    for row in 0..track_height {
        let is_thumb = row >= thumb_offset && row < thumb_offset + thumb_height;
        let symbol = if is_thumb { "█" } else { "│" };
        let style = if is_thumb {
            Style::default().fg(PALETTE_ACCENT)
        } else {
            Style::default().fg(PALETTE_LINE)
        };
        frame.render_widget(
            Paragraph::new(symbol).style(style),
            Rect {
                x: track.x,
                y: track.y.saturating_add(row as u16),
                width: 1,
                height: 1,
            },
        );
    }
}

fn popup_scrollbar_area(inner: Rect) -> Rect {
    Rect {
        x: inner.x.saturating_add(inner.width.saturating_sub(1)),
        y: inner.y,
        width: 1,
        height: inner.height,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PluginActionKind;

    #[test]
    fn smart_care_plugin_running_context_includes_capability_and_action() {
        let mut state = AppState {
            active_view: ActiveView::SmartCare,
            plugin_action_running: true,
            ..AppState::default()
        };
        state.plugin_last_action = Some(PluginActionKind::Preflight);
        state.smart_care_selected_card = 0;

        let text = footer_context_text(&state);
        assert!(text.contains("Cleanup plugin preflight running"));
    }

    #[test]
    fn smart_care_plugin_running_context_falls_back_when_no_action_present() {
        let state = AppState {
            active_view: ActiveView::SmartCare,
            plugin_action_running: true,
            plugin_last_action: None,
            ..AppState::default()
        };

        let text = footer_context_text(&state);
        assert!(text.contains("Cleanup plugin command running"));
    }
}
