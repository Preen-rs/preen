use ratatui::layout::{Constraint, Direction, Layout, Rect};

pub(super) const HEADER_HEIGHT: u16 = 3;
pub(super) const SIDEBAR_WIDTH: u16 = 30;
const SMART_CARE_REVIEW_POPUP_WIDTH: u16 = 84;
const SMART_CARE_REVIEW_POPUP_HEIGHT: u16 = 76;
const KEYBINDINGS_POPUP_WIDTH: u16 = 80;
const KEYBINDINGS_POPUP_HEIGHT: u16 = 72;

pub(super) struct AppLayout {
    pub(super) root: Rect,
    pub(super) footer: Rect,
    pub(super) sidebar_header: Rect,
    pub(super) sidebar_menu: Rect,
    pub(super) main_container: Rect,
}

pub(super) fn build(root: Rect, footer_height: u16) -> AppLayout {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(footer_height)])
        .split(root);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(SIDEBAR_WIDTH), Constraint::Min(20)])
        .split(vertical[0]);

    let sidebar = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(HEADER_HEIGHT), Constraint::Min(1)])
        .split(body[0]);

    AppLayout {
        root,
        footer: vertical[1],
        sidebar_header: sidebar[0],
        sidebar_menu: sidebar[1],
        main_container: body[1],
    }
}

pub(super) fn smart_care_review_popup_area(main_container: Rect) -> Rect {
    centered_rect(
        SMART_CARE_REVIEW_POPUP_WIDTH,
        SMART_CARE_REVIEW_POPUP_HEIGHT,
        main_container,
    )
}

pub(super) fn keybindings_popup_area(root: Rect) -> Rect {
    centered_rect(KEYBINDINGS_POPUP_WIDTH, KEYBINDINGS_POPUP_HEIGHT, root)
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
