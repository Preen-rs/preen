use ratatui::layout::{Constraint, Direction, Layout, Rect};

pub(super) const HEADER_HEIGHT: u16 = 3;
pub(super) const SIDEBAR_WIDTH: u16 = 30;

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
