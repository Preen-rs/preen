use crate::model::DashboardSnapshot;
use preen_core::dashboard_view::DashboardViewModel;
use ratatui::text::Line;

mod build;
mod card;

pub(super) fn dashboard_lines(
    snapshot: &DashboardSnapshot,
    content_width: usize,
) -> Vec<Line<'static>> {
    let view = DashboardViewModel::from_snapshot(snapshot);
    let cards = build::build_dashboard_cards(&view);
    let mut lines = vec![
        build::dashboard_status_line(&view, content_width),
        Line::from(""),
    ];
    let mut body = card::render_dashboard_cards(&cards, content_width);
    lines.append(&mut body);
    lines
}
