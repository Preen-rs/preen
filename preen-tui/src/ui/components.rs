use crate::i18n::{Language, TextKey, tr};
use crate::model::{ActiveView, AppState};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use super::layout;
use super::{PALETTE_ACCENT, PALETTE_LINE, PALETTE_TEXT, PALETTE_WARN};
use super::{theme, views};

pub(super) fn render_header(frame: &mut Frame<'_>, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(PALETTE_LINE));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(Line::from(" PREEN")).style(
            Style::default()
                .fg(PALETTE_TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        inner,
    );
}

pub(super) fn render_sidebar(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let rows = sidebar_rows(state.effective_language());

    let items: Vec<ListItem<'_>> = rows.iter().map(|(_, item)| item.clone()).collect();
    let selected = rows
        .iter()
        .position(|(view, _)| view.is_some_and(|view| view == state.active_view))
        .unwrap_or(0);
    let mut list_state = ListState::default();
    list_state.select(Some(selected));
    let list = List::new(items)
        .block(sidebar_block(state.tr(TextKey::Menu)))
        .style(Style::default().fg(PALETTE_TEXT))
        .highlight_style(Style::default().bg(PALETTE_ACCENT).fg(Color::Black))
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, area, &mut list_state);
}

pub(super) fn sidebar_view_at(area: Rect, column: u16, row: u16) -> Option<ActiveView> {
    let inner = sidebar_block("Menu").inner(area);
    if column < inner.x
        || column >= inner.x.saturating_add(inner.width)
        || row < inner.y
        || row >= inner.y.saturating_add(inner.height)
    {
        return None;
    }
    let index = row.saturating_sub(inner.y) as usize;
    sidebar_rows(crate::i18n::Language::English)
        .get(index)
        .and_then(|(view, _)| *view)
}

pub(super) fn render_main_container(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    if matches!(state.active_view, ActiveView::Applications) && state.smart_care_has_analyze_result
    {
        render_applications_main_container(frame, area, state);
        return;
    }

    let (border_color, title_color) = theme::main_container_colors(state);
    let title = Line::from(vec![Span::styled(
        format!(
            " {} ",
            state
                .active_view
                .title_for_language(state.effective_language())
        ),
        Style::default()
            .fg(title_color)
            .add_modifier(Modifier::BOLD),
    )]);
    let viewport_height = area.height.saturating_sub(2) as usize;
    let mut content_width = area.width.saturating_sub(2) as usize;
    let mut lines = views::build_main_lines(state, content_width);
    drop_duplicate_view_title(state, &mut lines);
    if viewport_height > 0 && lines.len() > viewport_height {
        content_width = area.width.saturating_sub(3) as usize;
        lines = views::build_main_lines(state, content_width);
        drop_duplicate_view_title(state, &mut lines);
    }
    let content_length = lines.len();
    let max_scroll = lines.len().saturating_sub(viewport_height) as u16;
    let effective_scroll = state.main_scroll.min(max_scroll);
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .style(Style::default().fg(PALETTE_TEXT))
        .scroll((effective_scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
    render_vertical_scrollbar(
        frame,
        area,
        viewport_height,
        content_length,
        effective_scroll as usize,
    );
}

fn drop_duplicate_view_title(state: &AppState, lines: &mut Vec<Line<'static>>) {
    let title = state
        .active_view
        .title_for_language(state.effective_language())
        .to_string();
    if lines.first().is_some_and(|line| line.to_string() == title) {
        lines.remove(0);
    }
}

fn render_applications_main_container(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let (border_color, title_color) = theme::main_container_colors(state);
    let title = Line::from(vec![Span::styled(
        format!(
            " {} ",
            state
                .active_view
                .title_for_language(state.effective_language())
        ),
        Style::default()
            .fg(title_color)
            .add_modifier(Modifier::BOLD),
    )]);
    let container = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let inner = container.inner(area);
    frame.render_widget(container, area);

    let show_last_action = !state.applications_last_action_lines.is_empty();
    let vertical = if show_last_action {
        Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(8),
            Constraint::Length(7),
        ])
        .split(inner)
    } else {
        Layout::vertical([Constraint::Length(2), Constraint::Min(8)]).split(inner)
    };

    let header = Paragraph::new(vec![
        Line::from(localized(
            state,
            "a analyze | r reanalyze | j/k move | space select | p paths | u uninstall(selected)",
            "a Analyse | r erneut | j/k bewegen | Leertaste wählen | p Pfade | u deinstallieren",
        )),
        Line::from(""),
    ])
    .style(Style::default().fg(PALETTE_TEXT));
    frame.render_widget(header, vertical[0]);

    let app_items = state.applications_items();
    let list_items = if app_items.is_empty() {
        vec![ListItem::new(localized(
            state,
            "  no application found",
            "  keine Anwendung gefunden",
        ))]
    } else {
        app_items
            .iter()
            .map(|app_name| {
                let selected = if state.applications_is_selected(app_name) {
                    "[x]"
                } else {
                    "[ ]"
                };
                ListItem::new(format!(" {selected} {app_name}"))
            })
            .collect::<Vec<_>>()
    };

    let list_inner = Block::default()
        .title("")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(PALETTE_LINE))
        .inner(vertical[1]);
    let viewport_height = list_inner.height as usize;
    let content_length = app_items.len().max(1);
    let max_scroll = content_length.saturating_sub(viewport_height);

    let mut list_state = ListState::default();
    let mut list_scroll_offset = 0usize;
    if app_items.is_empty() {
        list_state.select(None);
    } else {
        let selected = state
            .applications_selected_row
            .min(app_items.len().saturating_sub(1));
        // Deterministic offset avoids jumpy list behavior near boundaries.
        let computed_offset = selected
            .saturating_sub(viewport_height.saturating_sub(1))
            .min(max_scroll);
        list_scroll_offset = computed_offset;
        list_state.select(Some(selected));
        list_state = list_state.with_offset(computed_offset);
    }

    let scan_suffix = if state.applications_inventory_revision > 0 {
        format!(
            " · {} #{}",
            localized(state, "scan", "Scan"),
            state.applications_inventory_revision
        )
    } else {
        String::new()
    };

    let list_widget = List::new(list_items)
        .block(
            Block::default()
                .title(format!(
                    " {} ({}/{}){} ",
                    localized(state, "Installed applications", "Installierte Anwendungen"),
                    state.applications_selected_count(),
                    app_items.len(),
                    scan_suffix
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PALETTE_LINE)),
        )
        .style(Style::default().fg(PALETTE_TEXT))
        .highlight_style(Style::default().bg(PALETTE_ACCENT).fg(Color::Black))
        .highlight_symbol("▶");
    frame.render_stateful_widget(list_widget, vertical[1], &mut list_state);

    if show_last_action {
        let logs = {
            let mut lines = vec![Line::from(localized(state, "Last action", "Letzte Aktion"))];
            for line in state.applications_last_action_lines.iter().take(4) {
                lines.push(Line::from(format!("- {line}")));
            }
            lines
        };
        let logs_widget = Paragraph::new(logs)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(PALETTE_LINE)),
            )
            .style(Style::default().fg(PALETTE_TEXT))
            .wrap(Wrap { trim: false });
        frame.render_widget(logs_widget, vertical[2]);
    }

    render_vertical_scrollbar(
        frame,
        list_inner,
        viewport_height,
        content_length,
        list_scroll_offset,
    );
}

pub(super) fn render_smart_care_review_popup(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let popup_area = smart_care_review_popup_area(area);
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(" Smart Care Review ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(PALETTE_ACCENT));
    frame.render_widget(block, popup_area);
    let inner = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });

    let mut viewport_height = inner.height as usize;
    let mut content_width = inner.width as usize;
    let mut lines = wrap_plain_lines(
        views::build_smart_care_review_popup_lines(state),
        content_width,
    );
    if viewport_height > 0 && lines.len() > viewport_height && content_width > 0 {
        content_width = content_width.saturating_sub(1);
        lines = wrap_plain_lines(
            views::build_smart_care_review_popup_lines(state),
            content_width,
        );
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
    let effective_scroll = state.smart_care_review_scroll.min(max_scroll);

    let paragraph = Paragraph::new(lines)
        .style(Style::default().fg(PALETTE_TEXT))
        .scroll((effective_scroll, 0));
    frame.render_widget(paragraph, content_area);
    if show_scrollbar && inner.width > 1 {
        render_vertical_scrollbar(
            frame,
            vertical_scrollbar_area(inner),
            viewport_height,
            content_length,
            effective_scroll as usize,
        );
    }
}

pub(super) fn smart_care_review_popup_area(area: Rect) -> Rect {
    layout::smart_care_review_popup_area(area)
}

pub(super) fn render_info_popup(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let popup_area = info_popup_area(area);
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(info_popup_title(state))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(PALETTE_ACCENT));
    frame.render_widget(block, popup_area);
    let inner = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });

    let mut viewport_height = inner.height as usize;
    let lines = views::build_info_popup_lines(state);
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
    let effective_scroll = state.info_popup_scroll.min(max_scroll);
    let visible_lines = lines
        .into_iter()
        .skip(effective_scroll as usize)
        .take(viewport_height)
        .collect::<Vec<_>>();

    let paragraph = Paragraph::new(visible_lines).style(Style::default().fg(PALETTE_TEXT));
    frame.render_widget(paragraph, content_area);
    if show_scrollbar && inner.width > 1 {
        render_vertical_scrollbar(
            frame,
            vertical_scrollbar_area(inner),
            viewport_height,
            content_length,
            effective_scroll as usize,
        );
    }
}

pub(super) fn info_popup_area(area: Rect) -> Rect {
    layout::smart_care_review_popup_area(area)
}

fn info_popup_title(state: &AppState) -> String {
    if matches!(state.active_view, ActiveView::Applications) {
        if let Some(target) = &state.applications_info_target {
            return format!(" {target} ");
        }
        if let Some(selected) = state.applications_selected_app() {
            return format!(" {selected} ");
        }
    }
    format!(" {} ", localized(state, "Info", "Info"))
}

pub(super) fn render_busy_overlay(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let Some(busy) = &state.busy_view else {
        return;
    };
    let popup_width = area.width.saturating_sub(4).min((area.width / 2).max(52));
    let popup_height = 11u16.min(area.height.saturating_sub(4).max(9));
    let popup_area = Rect {
        x: area
            .x
            .saturating_add(area.width.saturating_sub(popup_width) / 2),
        y: area
            .y
            .saturating_add(area.height.saturating_sub(popup_height) / 2),
        width: popup_width,
        height: popup_height,
    };
    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .title(format!(" {} ", busy.context))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(PALETTE_ACCENT));
    frame.render_widget(block, popup_area);
    let inner = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 2,
    });

    let content_width = inner.width as usize;
    let spinner = ["◐", "◓", "◑", "◒"][(state.ui_tick as usize / 2) % 4];
    let bar_width = content_width.max(12);
    let active = (state.ui_tick as usize) % bar_width;
    let mut bar = String::with_capacity(bar_width);
    for idx in 0..bar_width {
        let distance = idx.abs_diff(active);
        if distance <= 1 {
            bar.push('█');
        } else if distance <= 3 {
            bar.push('▓');
        } else {
            bar.push('░');
        }
    }

    let lines = vec![
        Line::from(vec![
            Span::styled(spinner, Style::default().fg(PALETTE_ACCENT)),
            Span::raw(" "),
            Span::styled(
                busy.title.clone(),
                Style::default()
                    .fg(PALETTE_TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(busy.detail.clone()),
        Line::from(""),
        Line::from(vec![Span::styled(bar, Style::default().fg(PALETTE_ACCENT))]),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(PALETTE_TEXT))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

pub(super) fn render_applications_uninstall_confirm_popup(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &AppState,
) {
    let targets = state.applications_pending_uninstall_targets();
    let target_count = targets.len();
    let popup_width = area.width.saturating_sub(4).min((area.width / 2).max(48));
    let popup_height = 11u16
        .saturating_add(target_count.min(8) as u16)
        .min(area.height.saturating_sub(4).max(10));
    let popup_area = Rect {
        x: area
            .x
            .saturating_add(area.width.saturating_sub(popup_width) / 2),
        y: area
            .y
            .saturating_add(area.height.saturating_sub(popup_height) / 2),
        width: popup_width,
        height: popup_height,
    };
    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .title(format!(
            " {} ",
            localized(state, "Confirm uninstall", "Deinstallation bestätigen")
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(PALETTE_WARN));
    frame.render_widget(block, popup_area);
    let inner = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });

    let mut lines = vec![
        Line::from(vec![Span::styled(
            localized(
                state,
                "Uninstall selected applications?",
                "Ausgewählte Anwendungen deinstallieren?",
            ),
            Style::default()
                .fg(PALETTE_WARN)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(match state.effective_language() {
            Language::English => format!("{target_count} app(s) will be moved to Trash."),
            Language::German => format!("{target_count} App(s) werden in den Papierkorb bewegt."),
        }),
        Line::from(""),
    ];
    for app in targets.iter().take(8) {
        lines.push(Line::from(format!("  - {app}")));
    }
    if target_count > 8 {
        lines.push(Line::from(format!("  ... and {} more", target_count - 8)));
    }

    let action_line = Line::from(vec![
        Span::styled(
            localized(state, "[ Enter / y ] Confirm", "[ Enter / y ] Bestätigen"),
            Style::default().fg(PALETTE_WARN),
        ),
        Span::raw("    "),
        Span::styled(
            localized(state, "[ Esc / n ] Cancel", "[ Esc / n ] Abbrechen"),
            Style::default().fg(PALETTE_ACCENT),
        ),
    ]);
    let actions_area = Rect {
        x: inner.x,
        y: inner.y.saturating_add(inner.height.saturating_sub(1)),
        width: inner.width,
        height: inner.height.min(1),
    };
    let body_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: inner.height.saturating_sub(2),
    };

    let mut viewport_height = body_area.height as usize;
    let mut content_width = body_area.width as usize;
    let mut lines = wrap_plain_lines(lines, content_width);
    if viewport_height > 0 && lines.len() > viewport_height && content_width > 0 {
        content_width = content_width.saturating_sub(1);
        lines = wrap_plain_lines(lines, content_width);
    }
    let show_scrollbar = viewport_height > 0 && lines.len() > viewport_height;
    let content_area = if show_scrollbar && body_area.width > 1 {
        Rect {
            x: body_area.x,
            y: body_area.y,
            width: body_area.width - 1,
            height: body_area.height,
        }
    } else {
        body_area
    };
    viewport_height = content_area.height as usize;
    let content_length = lines.len();
    let paragraph = Paragraph::new(lines)
        .style(Style::default().fg(PALETTE_TEXT))
        .scroll((0, 0));
    frame.render_widget(paragraph, content_area);
    if show_scrollbar && body_area.width > 1 {
        render_vertical_scrollbar(
            frame,
            vertical_scrollbar_area(body_area),
            viewport_height,
            content_length,
            0,
        );
    }
    if actions_area.height > 0 {
        frame.render_widget(
            Paragraph::new(action_line).style(Style::default().fg(PALETTE_TEXT)),
            actions_area,
        );
    }
}

pub(super) fn wrap_plain_lines(lines: Vec<Line<'static>>, width: usize) -> Vec<Line<'static>> {
    if width == 0 {
        return lines;
    }
    let mut wrapped = Vec::new();
    for line in lines {
        let raw = line.to_string();
        if raw.is_empty() {
            wrapped.push(Line::from(""));
            continue;
        }
        let chars = raw.chars().collect::<Vec<_>>();
        let mut index = 0usize;
        while index < chars.len() {
            let end = (index + width).min(chars.len());
            wrapped.push(Line::from(chars[index..end].iter().collect::<String>()));
            index = end;
        }
    }
    wrapped
}

fn sidebar_rows(language: crate::i18n::Language) -> Vec<(Option<ActiveView>, ListItem<'static>)> {
    let mut rows = Vec::new();
    for (section_index, section) in ActiveView::sections().iter().enumerate() {
        if section_index > 0 {
            rows.push((None, ListItem::new("")));
        }
        if let Some(heading) = section.heading {
            let heading = match heading {
                "Tools" => tr(language, TextKey::Tools),
                "Settings" => tr(language, TextKey::SettingsSection),
                _ => heading,
            };
            rows.push((
                None,
                ListItem::new(format!(" {heading}")).style(Style::default().fg(PALETTE_LINE)),
            ));
        }
        for view in section.items {
            let mut label = format!(" {}", view.title_for_language(language));
            if !view.is_implemented() {
                label.push_str(&format!(" ({})", tr(language, TextKey::Soon)));
            }
            let base_style = if view.is_implemented() {
                Style::default().fg(PALETTE_TEXT)
            } else {
                Style::default().fg(PALETTE_LINE)
            };
            rows.push((Some(*view), ListItem::new(label).style(base_style)));
        }
    }
    rows
}

fn localized(state: &AppState, en: &'static str, de: &'static str) -> &'static str {
    match state.effective_language() {
        Language::English => en,
        Language::German => de,
    }
}

fn sidebar_block(title: &'static str) -> Block<'static> {
    Block::default()
        .title(format!(" {title} "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(PALETTE_LINE))
}

fn render_vertical_scrollbar(
    frame: &mut Frame<'_>,
    area: Rect,
    viewport_height: usize,
    content_length: usize,
    scroll_offset: usize,
) {
    if viewport_height == 0 || content_length <= viewport_height {
        return;
    }
    let target = vertical_scrollbar_area(area);
    let Some((thumb_top, thumb_height)) = scrollbar_thumb(
        target.height as usize,
        viewport_height,
        content_length,
        scroll_offset,
    ) else {
        return;
    };
    let thumb_bottom = thumb_top.saturating_add(thumb_height);
    let lines = (0..target.height as usize)
        .map(|row| {
            let (symbol, color) = if row >= thumb_top && row < thumb_bottom {
                ("█", PALETTE_ACCENT)
            } else {
                ("│", PALETTE_LINE)
            };
            Line::from(Span::styled(symbol, Style::default().fg(color)))
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), target);
}

fn scrollbar_thumb(
    track_height: usize,
    viewport_height: usize,
    content_length: usize,
    scroll_offset: usize,
) -> Option<(usize, usize)> {
    if track_height == 0 || viewport_height == 0 || content_length <= viewport_height {
        return None;
    }

    // Keep this custom math: it makes the thumb height proportional and
    // guarantees the thumb reaches the bottom when the last page is visible.
    let thumb_height =
        ((viewport_height * track_height).div_ceil(content_length)).clamp(1, track_height);
    let max_scroll = content_length.saturating_sub(viewport_height);
    let max_thumb_top = track_height.saturating_sub(thumb_height);
    let thumb_top = if max_scroll == 0 {
        0
    } else {
        scroll_offset.min(max_scroll) * max_thumb_top / max_scroll
    };
    Some((thumb_top, thumb_height))
}

fn vertical_scrollbar_area(inner: Rect) -> Rect {
    Rect {
        x: inner.x.saturating_add(inner.width.saturating_sub(1)),
        y: inner.y,
        width: inner.width.min(1),
        height: inner.height,
    }
}

#[cfg(test)]
mod tests {
    use super::scrollbar_thumb;

    #[test]
    fn scrollbar_thumb_reaches_track_edges() {
        let track = 20;
        let viewport = 5;
        let content = 25;
        let top = scrollbar_thumb(track, viewport, content, 0).unwrap();
        let bottom = scrollbar_thumb(track, viewport, content, content - viewport).unwrap();

        assert_eq!(top.0, 0);
        assert_eq!(top.1, 4);
        assert_eq!(bottom.0 + bottom.1, track);
    }

    #[test]
    fn scrollbar_thumb_is_proportional_for_large_viewports() {
        let thumb = scrollbar_thumb(24, 18, 36, 0).unwrap();

        assert_eq!(thumb.1, 12);
    }
}
