use crate::model::{ActiveView, AppState};
use preen_core::dashboard_policy::{
    DashboardLevel, classify_battery_percent, classify_health_score, classify_network_rate_mbps,
    classify_usage_percent,
};
use ratatui::style::{Color, Modifier, Style};

use super::{PALETTE_DANGER, PALETTE_OK, PALETTE_TEXT, PALETTE_WARN};

pub(super) fn main_container_colors(state: &AppState) -> (Color, Color) {
    if state.active_view != ActiveView::Dashboard {
        return (Color::Rgb(120, 232, 140), Color::Rgb(120, 232, 140));
    }
    let Some(snapshot) = &state.snapshot else {
        return (Color::Rgb(120, 232, 140), Color::Rgb(120, 232, 140));
    };
    match classify_health_score(snapshot.health_score) {
        DashboardLevel::Good => (Color::Rgb(120, 232, 140), Color::Rgb(140, 250, 160)),
        DashboardLevel::Warn => (Color::Rgb(240, 203, 94), Color::Rgb(250, 222, 120)),
        DashboardLevel::Danger => (Color::Rgb(242, 110, 110), Color::Rgb(255, 140, 140)),
    }
}

pub(super) fn usage_style(percent: f64) -> Style {
    style_for_level(classify_usage_percent(percent))
}

pub(super) fn battery_style(percent: f64) -> Style {
    style_for_level(classify_battery_percent(percent))
}

pub(super) fn network_rate_style(rate_mbps: f64) -> Style {
    style_for_level(classify_network_rate_mbps(rate_mbps))
}

pub(super) fn battery_health_style(value: &str) -> Style {
    let lower = value.to_lowercase();
    if lower.contains("poor") || lower.contains("bad") {
        return Style::default()
            .fg(PALETTE_DANGER)
            .add_modifier(Modifier::BOLD);
    }
    if lower.contains("fair") {
        return Style::default()
            .fg(PALETTE_WARN)
            .add_modifier(Modifier::BOLD);
    }
    if lower.contains("good") || lower.contains("normal") {
        return Style::default().fg(PALETTE_OK).add_modifier(Modifier::BOLD);
    }
    Style::default().fg(PALETTE_TEXT)
}

pub(super) fn health_dot_color(score: u8) -> Color {
    match classify_health_score(score) {
        DashboardLevel::Good => Color::Rgb(134, 239, 172),
        DashboardLevel::Warn => Color::Rgb(250, 204, 97),
        DashboardLevel::Danger => Color::Rgb(248, 113, 113),
    }
}

fn style_for_level(level: DashboardLevel) -> Style {
    match level {
        DashboardLevel::Good => Style::default().fg(PALETTE_OK).add_modifier(Modifier::BOLD),
        DashboardLevel::Warn => Style::default()
            .fg(PALETTE_WARN)
            .add_modifier(Modifier::BOLD),
        DashboardLevel::Danger => Style::default()
            .fg(PALETTE_DANGER)
            .add_modifier(Modifier::BOLD),
    }
}
