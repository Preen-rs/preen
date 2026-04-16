use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use super::super::format::{pad_to_width, truncate_with_ellipsis};
use super::super::{PALETTE_ACCENT, PALETTE_TEXT};

#[derive(Clone)]
pub(super) struct DashboardCardLine {
    pub(super) text: String,
    pub(super) style: Style,
}

pub(super) struct DashboardCard {
    pub(super) title: &'static str,
    pub(super) lines: Vec<DashboardCardLine>,
}

pub(super) fn line_plain(text: impl Into<String>) -> DashboardCardLine {
    DashboardCardLine {
        text: text.into(),
        style: Style::default().fg(PALETTE_TEXT),
    }
}

pub(super) fn line_styled(text: impl Into<String>, style: Style) -> DashboardCardLine {
    DashboardCardLine {
        text: text.into(),
        style,
    }
}

pub(super) fn render_dashboard_cards(
    cards: &[DashboardCard],
    content_width: usize,
) -> Vec<Line<'static>> {
    if content_width >= 92 {
        render_two_columns(cards, content_width)
    } else {
        render_single_column(cards, content_width)
    }
}

fn render_two_columns(cards: &[DashboardCard], content_width: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let gap_width = 3usize;
    let column_width = content_width.saturating_sub(gap_width) / 2;
    let gap = " ".repeat(gap_width);

    for pair in cards.chunks(2) {
        let left = render_card_lines(&pair[0], column_width);
        let right = if pair.len() == 2 {
            render_card_lines(&pair[1], column_width)
        } else {
            Vec::new()
        };
        let row_count = left.len().max(right.len());
        for index in 0..row_count {
            let left_row = left.get(index).cloned().unwrap_or_else(empty_line);
            let right_row = right.get(index).cloned().unwrap_or_else(empty_line);
            out.push(Line::from(vec![
                Span::styled(pad_to_width(&left_row.text, column_width), left_row.style),
                Span::raw(gap.clone()),
                Span::styled(
                    truncate_with_ellipsis(&right_row.text, column_width),
                    right_row.style,
                ),
            ]));
        }
        out.push(Line::from(""));
    }
    if matches!(out.last(), Some(line) if line == &Line::from("")) {
        let _ = out.pop();
    }
    out
}

fn render_single_column(cards: &[DashboardCard], content_width: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    for card in cards {
        for line in render_card_lines(card, content_width) {
            out.push(Line::from(Span::styled(line.text, line.style)));
        }
        out.push(Line::from(""));
    }
    if matches!(out.last(), Some(line) if line == &Line::from("")) {
        let _ = out.pop();
    }
    out
}

fn render_card_lines(card: &DashboardCard, width: usize) -> Vec<DashboardCardLine> {
    let mut rows = Vec::with_capacity(card.lines.len() + 1);
    rows.push(card_header_line(card.title, width));
    for line in &card.lines {
        rows.push(DashboardCardLine {
            text: truncate_with_ellipsis(&format!("  {}", line.text), width),
            style: line.style,
        });
    }
    rows
}

fn empty_line() -> DashboardCardLine {
    line_plain("")
}

fn card_header_line(title: &str, width: usize) -> DashboardCardLine {
    let title_text = format!("{} {}", card_icon(title), title);
    let title_len = title_text.chars().count();
    let separator_len = width.saturating_sub(title_len + 2);
    let text = if separator_len == 0 {
        truncate_with_ellipsis(&title_text, width)
    } else {
        format!("{title_text}  {}", "╌".repeat(separator_len))
    };
    line_styled(
        text,
        Style::default()
            .fg(PALETTE_ACCENT)
            .add_modifier(Modifier::BOLD),
    )
}

fn card_icon(title: &str) -> &'static str {
    match title {
        "CPU" => "◉",
        "Memory" => "◍",
        "Disk" => "◧",
        "Power" => "◪",
        "Network" => "⇅",
        "Processes" => "*",
        _ => "•",
    }
}
