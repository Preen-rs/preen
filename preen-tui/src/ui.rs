use crate::model::AppState;
use ratatui::Frame;
use ratatui::style::Color;

mod components;
mod dashboard;
mod footer;
mod format;
mod layout;
mod theme;
mod views;

pub use footer::{FooterLinkTarget, footer_link_at, repo_url_for_footer_link};

pub(super) const PALETTE_LINE: Color = Color::Rgb(118, 122, 146);
pub(super) const PALETTE_ACCENT: Color = Color::Rgb(191, 148, 255);
pub(super) const PALETTE_TEXT: Color = Color::Rgb(224, 227, 233);
pub(super) const PALETTE_OK: Color = Color::Rgb(162, 213, 159);
pub(super) const PALETTE_WARN: Color = Color::Rgb(246, 206, 117);
pub(super) const PALETTE_DANGER: Color = Color::Rgb(241, 123, 123);
pub(super) const BAR_WIDTH_UNIFIED: usize = 10;
pub(super) const PROCESS_NAME_WIDTH: usize = 10;

pub fn render(frame: &mut Frame<'_>, state: &AppState) {
    let layout = layout::build(frame.area(), footer::footer_height());

    components::render_header(frame, layout.sidebar_header);
    components::render_sidebar(frame, layout.sidebar_menu, state);
    components::render_main_container(frame, layout.main_container, state);

    footer::render_footer(frame, layout.footer, state);

    if state.show_keybindings_popup {
        footer::render_keybindings_popup(frame, layout.root, state);
    }
}
