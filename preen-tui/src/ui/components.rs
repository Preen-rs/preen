use crate::model::{ActiveView, AppState};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use super::{PALETTE_ACCENT, PALETTE_LINE, PALETTE_TEXT};
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
    let mut rows = Vec::new();
    for (section_index, section) in ActiveView::sections().iter().enumerate() {
        if section_index > 0 {
            rows.push((None, ListItem::new("")));
        }
        if let Some(heading) = section.heading {
            rows.push((
                None,
                ListItem::new(format!(" {heading}")).style(Style::default().fg(PALETTE_LINE)),
            ));
        }
        for view in section.items {
            let mut label = format!(" {}", view.title());
            if !view.is_implemented() {
                label.push_str(" (soon)");
            }
            let base_style = if view.is_implemented() {
                Style::default().fg(PALETTE_TEXT)
            } else {
                Style::default().fg(PALETTE_LINE)
            };
            rows.push((Some(*view), ListItem::new(label).style(base_style)));
        }
    }

    let items: Vec<ListItem<'_>> = rows.iter().map(|(_, item)| item.clone()).collect();
    let selected = rows
        .iter()
        .position(|(view, _)| view.is_some_and(|view| view == state.active_view))
        .unwrap_or(0);
    let mut list_state = ListState::default();
    list_state.select(Some(selected));
    let list = List::new(items)
        .block(
            Block::default()
                .title(" Menu ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PALETTE_LINE)),
        )
        .style(Style::default().fg(PALETTE_TEXT))
        .highlight_style(Style::default().bg(PALETTE_ACCENT).fg(Color::Black))
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, area, &mut list_state);
}

pub(super) fn render_main_container(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let (border_color, title_color) = theme::main_container_colors(state);
    let title = Line::from(vec![Span::styled(
        format!(" {} ", state.active_view.title()),
        Style::default()
            .fg(title_color)
            .add_modifier(Modifier::BOLD),
    )]);
    let content_width = area.width.saturating_sub(2) as usize;
    let lines = views::build_main_lines(state, content_width);
    let viewport_height = area.height.saturating_sub(2) as usize;
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
}
