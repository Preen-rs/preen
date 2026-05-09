use crate::i18n::{Language, TextKey};
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
    let language = state.effective_language();
    let block = Block::default()
        .title(format!(
            " {} ",
            l(language, "Keybindings", "Tastenbelegung")
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::LightGreen));
    frame.render_widget(block, popup_area);
    let inner = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });

    let mut viewport_height = inner.height as usize;
    let mut content_width = inner.width as usize;
    let mut lines = wrap_plain_lines(
        keybindings_popup_lines(state.active_view, language),
        content_width,
    );
    if viewport_height > 0 && lines.len() > viewport_height && content_width > 0 {
        content_width = content_width.saturating_sub(1);
        lines = wrap_plain_lines(
            keybindings_popup_lines(state.active_view, language),
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
    let language = state.effective_language();
    if state.show_keybindings_popup {
        return l(
            language,
            "Popup: j/k or Up/Down or wheel scroll | Close: ? / Esc",
            "Popup: j/k oder Hoch/Runter oder Mausrad | Schließen: ? / Esc",
        )
        .to_string();
    }
    if state.show_info_popup && state.active_view.supports_smart_care_controls() {
        return l(
            language,
            "Info: j/k or Up/Down or wheel scroll | Close: i / Esc",
            "Info: j/k oder Hoch/Runter oder Mausrad | Schließen: i / Esc",
        )
        .to_string();
    }
    if state.smart_care_action_running && state.active_view.supports_smart_care_controls() {
        let action = state
            .smart_care_action_label
            .as_deref()
            .unwrap_or(l(language, "action", "Aktion"));
        return match language {
            Language::English => {
                format!("Smart Care: {action} running... wait for completion | Keybinding: ?")
            }
            Language::German => {
                format!("Smart Care: {action} läuft... bitte warten | Tastenbelegung: ?")
            }
        };
    }
    if state.plugin_action_running && state.active_view.supports_smart_care_controls() {
        let capability = state
            .smart_care_selected_capability()
            .map(|capability| capability.title())
            .unwrap_or("Smart Care");
        let action = state
            .plugin_last_action
            .map(|action| action.label().to_string())
            .unwrap_or_else(|| l(language, "command", "Befehl").to_string());
        return match language {
            Language::English => {
                format!(
                    "{capability} plugin {action} running... wait for completion | Keybinding: ?"
                )
            }
            Language::German => {
                format!("{capability}-Plugin {action} läuft... bitte warten | Tastenbelegung: ?")
            }
        };
    }
    if state.smart_care_review_mode && state.active_view.supports_smart_care_controls() {
        return l(
            language,
            "Review: j/k | space | 1/2/3/4 | A all | N none | Shift+X arm | x run | u undo | close: b/v/Esc | ?: keys",
            "Review: j/k | Leertaste | 1/2/3/4 | A alle | N keine | Shift+X scharf | x ausführen | u rückgängig | schließen: b/v/Esc | ?: Tasten",
        )
        .to_string();
    }
    match state.active_view {
        ActiveView::Dashboard => l(
            language,
            "Dashboard: d | SmartCare: m | Plugins: p | Checks: c | Settings: o | Tab menu | q quit | ?: keys",
            "Dashboard: d | SmartCare: m | Plugins: p | Prüfungen: c | Einstellungen: o | Tab Menü | q Beenden | ?: Tasten",
        )
        .to_string(),
        ActiveView::Settings => state.tr(TextKey::SettingsFooter).to_string(),
        ActiveView::SmartCare => {
            let run_hint = match (language, state.smart_care_validate_run_request().is_ok()) {
                (Language::English, true) => "x run",
                (Language::English, false) => "x blocked",
                (Language::German, true) => "x ausführen",
                (Language::German, false) => "x blockiert",
            };
            match language {
                Language::English => format!(
                    "SmartCare: h/l select | space/1/2/3/4 toggle | a analyze | v review | n/f/t plugin | Shift+X arm | {run_hint} | u undo | i info | ?: keys"
                ),
                Language::German => format!(
                    "SmartCare: h/l wählen | Leertaste/1/2/3/4 umschalten | a Analyse | v Review | n/f/t Plugin | Shift+X scharf | {run_hint} | u rückgängig | i Info | ?: Tasten"
                ),
            }
        }
        ActiveView::Applications => l(
            language,
            "Applications: a analyze | r reanalyze | j/k move | space select | p paths | x update | u uninstall(selected) | z undo | i info | ?: keys",
            "Anwendungen: a analysieren | r erneut | j/k bewegen | Leertaste wählen | p Pfade | x aktualisieren | u deinstallieren | z rückgängig | i Info | ?: Tasten",
        )
        .to_string(),
        ActiveView::Cleanup | ActiveView::Protection | ActiveView::Performance => format!(
            "{}: {} | {} | a {} | v review | n/f/t plugin | Shift+X {} | {} | u {} | i info | ?: {}",
            state.active_view.title_for_language(state.effective_language()),
            l(language, "h/l select", "h/l wählen"),
            l(language, "space toggle", "Leertaste umschalten"),
            l(language, "analyze", "Analyse"),
            l(language, "arm", "scharf"),
            if state.smart_care_validate_run_request().is_ok() {
                l(language, "x run", "x ausführen")
            } else {
                l(language, "x blocked", "x blockiert")
            },
            l(language, "undo", "rückgängig"),
            l(language, "keys", "Tasten")
        ),
        ActiveView::Plugins => l(
            language,
            "Plugins: l/s/i/f/t/n | e edit spec | d/m/c switch | q quit | ?: keys",
            "Plugins: l/s/i/f/t/n | e Spec bearbeiten | d/m/c wechseln | q Beenden | ?: Tasten",
        )
        .to_string(),
        ActiveView::Checks => l(
            language,
            "Checks: j/k scroll | d/m/p switch | q quit | ?: keys",
            "Prüfungen: j/k scrollen | d/m/p wechseln | q Beenden | ?: Tasten",
        )
        .to_string(),
        _ => format!(
            "{} ({}) | {} | Tab {} | q {} | ?: {}",
            state.active_view.title_for_language(language),
            state.tr(TextKey::Soon),
            l(language, "d/m/p/c switch", "d/m/p/c wechseln"),
            l(language, "menu", "Menü"),
            l(language, "quit", "Beenden"),
            l(language, "keys", "Tasten")
        ),
    }
}

fn keybindings_popup_lines(view: ActiveView, language: Language) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(l(language, "Global", "Global")),
        Line::from(l(
            language,
            "  q / Esc      Quit app",
            "  q / Esc      App beenden",
        )),
        Line::from(l(
            language,
            "  r            Refresh snapshot now",
            "  r            Snapshot jetzt aktualisieren",
        )),
        Line::from(l(
            language,
            "  d / m / p / c Open Dashboard/Smart Care/Plugins/Checks",
            "  d / m / p / c Dashboard/Smart Care/Plugins/Prüfungen öffnen",
        )),
        Line::from(l(
            language,
            "  o            Open Settings",
            "  o            Einstellungen öffnen",
        )),
        Line::from(l(
            language,
            "  Tab          Next menu (full sidebar cycle)",
            "  Tab          Nächstes Menü (ganze Seitenleiste)",
        )),
        Line::from(l(
            language,
            "  Shift+Tab    Previous menu (full sidebar cycle)",
            "  Shift+Tab    Vorheriges Menü (ganze Seitenleiste)",
        )),
        Line::from(l(
            language,
            "  Left/Right   Switch menu",
            "  Links/Rechts Menü wechseln",
        )),
        Line::from(l(
            language,
            "  j/k          Scroll main container",
            "  j/k          Hauptbereich scrollen",
        )),
        Line::from(l(
            language,
            "  Up/Down      Scroll main container",
            "  Hoch/Runter  Hauptbereich scrollen",
        )),
        Line::from(l(
            language,
            "  Mouse wheel  Scroll active container/popup",
            "  Mausrad      Aktiven Bereich/Popup scrollen",
        )),
        Line::from(l(
            language,
            "  PgUp/PgDn    Fast scroll",
            "  Bild↑/Bild↓  Schnell scrollen",
        )),
        Line::from(l(
            language,
            "  g            Scroll to top",
            "  g            Nach oben scrollen",
        )),
        Line::from(l(
            language,
            "  ?            Open/close this popup",
            "  ?            Dieses Popup öffnen/schließen",
        )),
        Line::from(""),
        Line::from(l(language, "Popup Navigation", "Popup-Navigation")),
        Line::from(l(
            language,
            "  j/k or Up/Down  Scroll inside popup",
            "  j/k oder Hoch/Runter Im Popup scrollen",
        )),
        Line::from(l(
            language,
            "  PgUp/PgDn       Fast scroll inside popup",
            "  Bild↑/Bild↓      Schnell im Popup scrollen",
        )),
        Line::from(l(
            language,
            "  Esc or ?        Close popup",
            "  Esc oder ?       Popup schließen",
        )),
        Line::from(""),
    ];

    match view {
        ActiveView::Dashboard => {
            lines.push(Line::from(format!(
                "{}: {}",
                l(language, "Current menu", "Aktuelles Menü"),
                view.title_for_language(language)
            )));
            lines.push(Line::from(l(
                language,
                "  Realtime system status and health overview.",
                "  Echtzeit-Systemstatus und Zustandsübersicht.",
            )));
        }
        ActiveView::SmartCare => {
            lines.push(Line::from(format!(
                "{}: {}",
                l(language, "Current menu", "Aktuelles Menü"),
                view.title_for_language(language)
            )));
            lines.push(Line::from(l(
                language,
                "  Shows capability-pack readiness for Smart Care orchestration.",
                "  Zeigt die Bereitschaft der Capability-Packs für Smart Care.",
            )));
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
            lines.push(Line::from(format!(
                "{}: {}",
                l(language, "Current menu", "Aktuelles Menü"),
                view.title_for_language(language)
            )));
            lines.push(Line::from(l(
                language,
                "  Shows installed capability plugins and trust readiness.",
                "  Zeigt installierte Capability-Plugins und Trust-Bereitschaft.",
            )));
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
            lines.push(Line::from(format!(
                "{}: {}",
                l(language, "Current menu", "Aktuelles Menü"),
                view.title_for_language(language)
            )));
            lines.push(Line::from(l(
                language,
                "  e             Edit plugin spec",
                "  e             Plugin-Spec bearbeiten",
            )));
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
            lines.push(Line::from(format!(
                "{}: {}",
                l(language, "Current menu", "Aktuelles Menü"),
                view.title_for_language(language)
            )));
            lines.push(Line::from(l(
                language,
                "  Shows detailed checks with severity and messages.",
                "  Zeigt detaillierte Prüfungen mit Schweregrad und Meldungen.",
            )));
        }
        ActiveView::Settings => {
            lines.push(Line::from(format!(
                "{}: {}",
                l(language, "Current menu", "Aktuelles Menü"),
                view.title_for_language(language)
            )));
            lines.push(Line::from(l(
                language,
                "  l             Cycle language preference",
                "  l             Spracheinstellung wechseln",
            )));
        }
        _ => {
            lines.push(Line::from(format!(
                "{}: {} ({})",
                l(language, "Current menu", "Aktuelles Menü"),
                view.title_for_language(language),
                l(language, "planned", "geplant")
            )));
            lines.push(Line::from(l(
                language,
                "  This view is scaffolded; implementation is in roadmap.",
                "  Diese Ansicht ist vorbereitet; Umsetzung ist in der Roadmap.",
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(l(language, "Links", "Links")));
    lines.push(Line::from("  Donate: https://github.com/sponsors/Preen-rs"));
    lines.push(Line::from(
        "  Ask Question: https://github.com/Preen-rs/preen/issues",
    ));
    lines
}

fn l(language: Language, en: &'static str, de: &'static str) -> &'static str {
    match language {
        Language::English => en,
        Language::German => de,
    }
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

    #[test]
    fn footer_and_keybindings_use_german_language() {
        let state = AppState {
            active_view: ActiveView::Dashboard,
            language_preference: crate::i18n::LanguagePreference::German,
            ..AppState::default()
        };

        let footer = footer_context_text(&state);
        assert!(footer.contains("Einstellungen: o"));
        assert!(footer.contains("q Beenden"));

        let popup = keybindings_popup_lines(ActiveView::Settings, Language::German)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(popup.contains("Tastenbelegung") || popup.contains("Aktuelles Menü"));
        assert!(popup.contains("Spracheinstellung wechseln"));
    }
}
