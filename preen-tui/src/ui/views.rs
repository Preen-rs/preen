use crate::i18n::{Language, TextKey};
use crate::model::{ActiveView, AppState, DashboardSnapshot, PluginActionKind};
use preen_core::app_uninstall::{
    AppManagementSource, AppPackageDetectionConfidence, AppPackageManager, AppSource,
    AppUpdateAvailability, InstalledApplication,
};
use preen_core::check_list_view::CheckListView;
use preen_core::plugin_list_view::PluginListView;
use preen_core::smart_care::{
    SmartCareCapability, SmartCareCapabilityStatus, SmartCarePreview,
    classify_capability_descriptor_source, classify_descriptor_pack_source,
};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use std::collections::{BTreeMap, BTreeSet};

use super::dashboard;
use super::format::{pad_to_width, short_rev, truncate_with_ellipsis, yes_no};
use super::{PALETTE_ACCENT, PALETTE_DANGER, PALETTE_LINE, PALETTE_OK, PALETTE_TEXT, PALETTE_WARN};

pub(super) fn build_main_lines(state: &AppState, content_width: usize) -> Vec<Line<'static>> {
    let Some(snapshot) = &state.snapshot else {
        if matches!(state.active_view, ActiveView::Settings) {
            return settings_lines(state);
        }
        return vec![
            Line::from(state.tr(TextKey::CollectingSnapshot)),
            Line::from(""),
            Line::from(state.tr(TextKey::SnapshotWorkerRunning)),
        ];
    };

    match state.active_view {
        ActiveView::Dashboard => dashboard::dashboard_lines(snapshot, content_width),
        ActiveView::SmartCare => smart_care_lines(state, snapshot, content_width),
        ActiveView::Applications => applications_lines(state, snapshot, content_width),
        ActiveView::Cleanup | ActiveView::Protection | ActiveView::Performance => {
            capability_lines(state, snapshot, content_width)
        }
        ActiveView::Plugins => plugin_lines(state, snapshot, content_width),
        ActiveView::Checks => check_lines(state, snapshot),
        ActiveView::Settings => settings_lines(state),
        _ => coming_soon_lines(state),
    }
}

fn settings_lines(state: &AppState) -> Vec<Line<'static>> {
    let language = state.effective_language();
    let mut lines = vec![
        Line::from(state.tr(TextKey::SettingsTitle)),
        Line::from(state.tr(TextKey::SettingsSubtitle)),
        Line::from(""),
        Line::from(format!(
            "{}: {}",
            state.tr(TextKey::LanguageLabel),
            state.language_preference.label(state.system_language)
        )),
        Line::from(format!(
            "{}: {}",
            state.tr(TextKey::EffectiveLanguage),
            crate::i18n::locale(language)
        )),
        Line::from(state.tr(TextKey::LanguageHelp)),
        Line::from(""),
        Line::from(state.tr(TextKey::SensitiveFoldersTitle)),
    ];
    if state.sensitive_folders.is_empty() {
        lines.push(Line::from(state.tr(TextKey::SensitiveFoldersEmpty)));
    } else {
        lines.extend(
            state
                .sensitive_folders
                .iter()
                .map(|path| Line::from(format!("- {}", path.display()))),
        );
    }
    lines.push(Line::from(state.tr(TextKey::SensitiveFoldersHint)));
    if let Some(status) = &state.config_status {
        lines.push(Line::from(""));
        lines.push(Line::from(status.clone()));
    }
    lines
}

fn smart_care_lines(
    state: &AppState,
    _snapshot: &DashboardSnapshot,
    content_width: usize,
) -> Vec<Line<'static>> {
    let preview = state
        .smart_care_preview
        .clone()
        .unwrap_or_else(|| preview_from_state(state));
    let review_hint = if state.smart_care_has_analyze_result {
        "v"
    } else {
        "v (after a)"
    };
    let run_hint = if state.smart_care_has_review_result {
        "x"
    } else {
        "x (after v)"
    };
    let action_hint = if state.smart_care_action_running {
        format!(
            "Action: {} (running...)",
            state
                .smart_care_action_label
                .as_deref()
                .unwrap_or("background task")
        )
    } else {
        "Action: idle".to_string()
    };
    let workflow = summarize_review_workflow(state);
    let run_gate = smart_care_run_gate(state);
    let next_action = smart_care_next_action_hint(state);
    let run_summary = smart_care_last_run_summary(&state.smart_care_last_run_report);

    let mut lines = vec![
        Line::from("Smart Care"),
        Line::from("Orchestrates selected capability packs."),
        Line::from(format!(
            "Select: h/l | Toggle: space | Analyze: a | Review: {review_hint} | Run: {run_hint}"
        )),
        Line::from(format!(
            "Flow: analyze={} review={} arm={} run={}",
            workflow.analyze_stage, workflow.review_stage, workflow.apply_stage, workflow.run_stage
        )),
        Line::from(format!("Run gate: {run_gate} | Next: {next_action}")),
        Line::from(format!(
            "Arm: {} | Last run: {run_summary}",
            yes_no(state.smart_care_apply_armed)
        )),
        Line::from(format!("{action_hint} (details: i)")),
        Line::from(""),
    ];
    lines.extend(render_smart_care_cards(
        state,
        &preview,
        state.smart_care_selected_card,
        content_width,
        state.smart_care_has_analyze_result,
        state.smart_care_has_review_result,
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "Ready: {} | Selected trusted packs: {}",
        yes_no(preview.overall_ready),
        preview.selected_plugins.len()
    )));
    if !preview.blockers.is_empty() || !state.smart_care_skipped_pack_ids.is_empty() {
        lines.push(Line::from(format!(
            "Blockers: {} (press v for details)",
            preview.blockers.len() + state.smart_care_skipped_pack_ids.len()
        )));
    }
    if let Some(line) = smart_care_plugin_action_brief_line(state) {
        lines.push(Line::from(line));
    }
    if let Some(error) = &state.smart_care_error {
        lines.push(Line::from(""));
        lines.push(Line::from("Resolver warning"));
        for line in simplify_diagnostic_lines(vec![error.clone()]) {
            for wrapped in wrap_with_prefix("- ", &line, content_width) {
                lines.push(Line::from(wrapped));
            }
        }
    }
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from("Error"));
        for line in simplify_diagnostic_lines(vec![error.clone()]) {
            for wrapped in wrap_with_prefix("- ", &line, content_width) {
                lines.push(Line::from(wrapped));
            }
        }
    }
    lines
}

pub(super) fn build_smart_care_review_popup_lines(state: &AppState) -> Vec<Line<'static>> {
    let Some(snapshot) = &state.snapshot else {
        return vec![
            Line::from("Smart Care Review"),
            Line::from("Snapshot is not ready yet."),
            Line::from(""),
            Line::from("Run analyze after snapshot becomes available."),
        ];
    };
    let preview = state
        .smart_care_preview
        .clone()
        .unwrap_or_else(|| preview_from_state(state));
    smart_care_review_lines(state, &preview, snapshot)
}

pub(super) fn build_info_popup_lines(state: &AppState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    if matches!(state.active_view, ActiveView::Applications) {
        if state.applications_show_action_details {
            lines.push(Line::from(localized(
                state,
                "Application update result",
                "Anwendungsupdate-Ergebnis",
            )));
            lines.push(Line::from(""));
            if state.applications_last_action_lines.is_empty() {
                lines.push(Line::from(format!(
                    "- {}",
                    localized(state, "no result yet", "noch kein Ergebnis")
                )));
            } else {
                for item in &state.applications_last_action_lines {
                    lines.push(Line::from(format!("- {item}")));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(localized(
                state,
                "Supported update providers",
                "Unterstuetzte Update-Quellen",
            )));
            lines.push(Line::from("- Homebrew cask"));
            lines.push(Line::from("- Mac App Store detection"));
            lines.push(Line::from("- Sparkle detection"));
            lines.push(Line::from("- Flatpak"));
            lines.push(Line::from("- Snap"));
            lines.push(Line::from(""));
            lines.push(Line::from(localized(
                state,
                "Close: i / Esc | Scroll: j/k / PgUp/PgDn / mouse wheel",
                "Schliessen: i / Esc | Scroll: j/k / PgUp/PgDn / Mausrad",
            )));
            return lines;
        }

        let selected_app = state
            .applications_selected_app()
            .unwrap_or_else(|| "n/a".to_string());
        let app_name = state
            .applications_info_target
            .as_deref()
            .unwrap_or(&selected_app)
            .to_string();
        let selected_metadata = state
            .applications_inventory_metadata
            .iter()
            .find(|application| application.identity.display_name == app_name);

        push_application_detail_lines(state, &mut lines, selected_metadata, &app_name);

        if state.applications_show_paths_in_info {
            lines.push(Line::from(""));
            lines.push(Line::from(localized(
                state,
                "Related paths",
                "Zugehoerige Pfade",
            )));
            if state.applications_info_paths.is_empty() {
                lines.push(Line::from(format!(
                    "- {}",
                    localized(state, "no related path found", "keine zugehoerigen Pfade")
                )));
            } else {
                for path in &state.applications_info_paths {
                    lines.push(Line::from(format!("- {path}")));
                }
            }
            return lines;
        }

        let descriptors = state
            .smart_care_descriptors
            .iter()
            .filter(|descriptor| descriptor.capability == SmartCareCapability::Applications)
            .collect::<Vec<_>>();
        lines.push(Line::from(""));
        lines.push(Line::from(localized(state, "Plugins", "Plugins")));
        if descriptors.is_empty() {
            lines.push(Line::from(format!(
                "- {}",
                localized(state, "none", "keine")
            )));
        } else {
            for descriptor in descriptors {
                lines.push(Line::from(format!(
                    "- {}@{} | {} | trusted={}",
                    descriptor.pack_id,
                    descriptor.version.as_deref().unwrap_or("n/a"),
                    if descriptor.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    yes_no(descriptor.trusted_identity.is_some())
                )));
            }
        }
    } else if state.active_view.supports_smart_care_controls() {
        lines.push(Line::from("Info"));
        lines.push(Line::from(""));
        let preview = state
            .smart_care_preview
            .clone()
            .unwrap_or_else(|| preview_from_state(state));
        let selected_capability = state
            .smart_care_selected_capability()
            .or_else(|| state.active_view.smart_care_capability());
        let selected_label = selected_capability
            .map(capability_label)
            .unwrap_or("Smart Care");

        let selected_plugins = selected_capability
            .map(|capability| {
                state
                    .smart_care_descriptors
                    .iter()
                    .filter(|descriptor| descriptor.capability == capability && descriptor.enabled)
                    .count()
            })
            .unwrap_or(preview.selected_plugins.len());
        let selected_trusted = selected_capability
            .map(|capability| {
                state
                    .smart_care_descriptors
                    .iter()
                    .filter(|descriptor| {
                        descriptor.capability == capability
                            && descriptor.enabled
                            && descriptor.trusted_identity.is_some()
                    })
                    .count()
            })
            .unwrap_or(preview.selected_plugins.len());
        let selected_review_entries = selected_capability
            .map(|capability| {
                preview
                    .review_entries
                    .iter()
                    .filter(|entry| entry.capability == capability)
                    .count()
            })
            .unwrap_or(preview.review_entries.len());

        lines.push(Line::from(format!("View: {}", state.active_view.title())));
        lines.push(Line::from(format!("Selected capability: {selected_label}")));
        lines.push(Line::from(format!(
            "Capability plugins: matched={} trusted={} review_items={}",
            selected_plugins, selected_trusted, selected_review_entries
        )));
        lines.push(Line::from(format!(
            "Global installed plugins: {}",
            state
                .snapshot
                .as_ref()
                .map_or(0, |snapshot| snapshot.plugin_count)
        )));
        lines.push(Line::from(format!(
            "Analyze ready: {} | Review ready: {} | Run gate: {}",
            yes_no(state.smart_care_has_analyze_result),
            yes_no(state.smart_care_has_review_result),
            smart_care_run_gate(state)
        )));
        lines.push(Line::from(format!(
            "Apply arm: {} | Last run: {}",
            yes_no(state.smart_care_apply_armed),
            smart_care_last_run_summary(&state.smart_care_last_run_report)
        )));

        if !state.smart_care_skipped_pack_ids.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from("Skipped packs"));
            for pack_id in state.smart_care_skipped_pack_ids.iter().take(8) {
                lines.push(Line::from(format!("- {pack_id}")));
            }
            if state.smart_care_skipped_pack_ids.len() > 8 {
                lines.push(Line::from(format!(
                    "- ... and {} more",
                    state.smart_care_skipped_pack_ids.len() - 8
                )));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from("Shortcuts"));
        lines.push(Line::from("- Close: i / Esc"));
        lines.push(Line::from("- Scroll: j/k / PgUp/PgDn / mouse wheel"));
        lines.push(Line::from("- Review details: v"));
        lines.push(Line::from("- Analyze: a, Run: Shift+X then x"));
    } else {
        lines.push(Line::from("Info"));
        lines.push(Line::from(""));
        lines.push(Line::from("No extra info for this view."));
    }

    lines
}

fn push_application_detail_lines(
    state: &AppState,
    lines: &mut Vec<Line<'static>>,
    application: Option<&InstalledApplication>,
    fallback_name: &str,
) {
    lines.push(Line::from(localized(
        state,
        "Application details",
        "Anwendungsdetails",
    )));
    let Some(application) = application else {
        lines.push(Line::from(format!(
            "- {}: {}",
            localized(state, "Name", "Name"),
            fallback_name
        )));
        lines.push(Line::from(format!(
            "- {}: {}",
            localized(state, "Inventory data", "Inventardaten"),
            localized(state, "not available yet", "noch nicht verfuegbar")
        )));
        return;
    };

    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "Name", "Name"),
        application.identity.display_name
    )));
    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "Version", "Version"),
        application.version.as_deref().unwrap_or("n/a")
    )));
    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "Source", "Quelle"),
        application_source_label(state, &application.source)
    )));
    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "Estimated size", "Geschaetzte Groesse"),
        format_bytes(application.estimated_size)
    )));
    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "Protected", "Geschuetzt"),
        localized_bool(state, application.protected)
    )));
    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "App path", "App-Pfad"),
        application.path
    )));
    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "Last used", "Zuletzt verwendet"),
        application
            .last_used_at
            .as_ref()
            .map(|date| date.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| localized(state, "unknown", "unbekannt").to_string())
    )));
    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "Managed by", "Verwaltet von"),
        application_management_source_label(state, &application.management_source)
    )));
    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "Update availability", "Update-Verfuegbarkeit"),
        application_update_availability_label(state, &application.update_availability)
    )));
    if let Some(package) = &application.package_metadata {
        lines.push(Line::from(format!(
            "- {}: {}",
            localized(state, "Package manager", "Paketmanager"),
            application_package_manager_label(state, &package.manager)
        )));
        lines.push(Line::from(format!(
            "- {}: {}",
            localized(state, "Package id", "Paket-ID"),
            package.package_id
        )));
        if let Some(version) = &package.installed_version {
            lines.push(Line::from(format!(
                "- {}: {}",
                localized(state, "Package version", "Paketversion"),
                version
            )));
        }
        if let Some(command) = &package.update_command {
            lines.push(Line::from(format!(
                "- {}: {}",
                localized(state, "Update command", "Update-Befehl"),
                command
            )));
        }
        lines.push(Line::from(format!(
            "- {}: {}",
            localized(state, "Package match", "Paket-Zuordnung"),
            application_package_confidence_label(state, &package.detection_confidence)
        )));
    }
}

fn application_source_label(state: &AppState, source: &AppSource) -> &'static str {
    match source {
        AppSource::System => localized(state, "system", "System"),
        AppSource::User => localized(state, "user", "Benutzer"),
        AppSource::Local => localized(state, "local", "Lokal"),
        AppSource::Unknown => localized(state, "unknown", "unbekannt"),
    }
}

fn localized_bool(state: &AppState, value: bool) -> &'static str {
    if value {
        localized(state, "yes", "ja")
    } else {
        localized(state, "no", "nein")
    }
}

fn application_management_source_label(
    state: &AppState,
    source: &AppManagementSource,
) -> &'static str {
    match source {
        AppManagementSource::System => localized(state, "system", "System"),
        AppManagementSource::AppStore => localized(state, "App Store", "App Store"),
        AppManagementSource::PackageManager => localized(state, "package manager", "Paketmanager"),
        AppManagementSource::Manual => localized(state, "manual/local", "manuell/lokal"),
        AppManagementSource::Unknown => localized(state, "unknown", "unbekannt"),
    }
}

fn application_update_availability_label(
    state: &AppState,
    availability: &AppUpdateAvailability,
) -> &'static str {
    match availability {
        AppUpdateAvailability::UpdateAvailable => {
            localized(state, "update available", "Update verfuegbar")
        }
        AppUpdateAvailability::UpToDate => localized(state, "up to date", "aktuell"),
        AppUpdateAvailability::NotChecked => localized(state, "not checked", "nicht geprueft"),
        AppUpdateAvailability::Unsupported => {
            localized(state, "not supported", "nicht unterstuetzt")
        }
        AppUpdateAvailability::Unknown => localized(state, "unknown", "unbekannt"),
    }
}

fn application_package_manager_label(
    state: &AppState,
    manager: &AppPackageManager,
) -> &'static str {
    match manager {
        AppPackageManager::HomebrewCask => localized(state, "Homebrew cask", "Homebrew Cask"),
        AppPackageManager::MacAppStore => localized(state, "Mac App Store", "Mac App Store"),
        AppPackageManager::Sparkle => localized(state, "Sparkle", "Sparkle"),
        AppPackageManager::Apt => localized(state, "APT", "APT"),
        AppPackageManager::Dnf => localized(state, "DNF", "DNF"),
        AppPackageManager::Pacman => localized(state, "pacman", "pacman"),
        AppPackageManager::Flatpak => localized(state, "Flatpak", "Flatpak"),
        AppPackageManager::Snap => localized(state, "Snap", "Snap"),
        AppPackageManager::Unknown => localized(state, "unknown", "unbekannt"),
    }
}

fn application_package_confidence_label(
    state: &AppState,
    confidence: &AppPackageDetectionConfidence,
) -> &'static str {
    match confidence {
        AppPackageDetectionConfidence::Exact => localized(state, "exact", "exakt"),
        AppPackageDetectionConfidence::Strong => localized(state, "strong", "stark"),
        AppPackageDetectionConfidence::Fallback => localized(state, "fallback", "Fallback"),
    }
}

fn capability_label(capability: SmartCareCapability) -> &'static str {
    match capability {
        SmartCareCapability::Cleanup => "Cleanup",
        SmartCareCapability::Protection => "Protection",
        SmartCareCapability::Performance => "Performance",
        SmartCareCapability::Applications => "Applications",
    }
}

fn capability_shortcut_key(capability: SmartCareCapability) -> &'static str {
    match capability {
        SmartCareCapability::Cleanup => "1",
        SmartCareCapability::Performance => "2",
        SmartCareCapability::Applications => "3",
        SmartCareCapability::Protection => "4",
    }
}

fn applications_lines(
    state: &AppState,
    snapshot: &DashboardSnapshot,
    content_width: usize,
) -> Vec<Line<'static>> {
    let capability = SmartCareCapability::Applications;
    let enabled = state.smart_care_is_enabled(capability);
    let descriptors = state
        .smart_care_descriptors
        .iter()
        .filter(|descriptor| descriptor.capability == capability)
        .collect::<Vec<_>>();
    let trusted_count = descriptors
        .iter()
        .filter(|descriptor| descriptor.enabled && descriptor.trusted_identity.is_some())
        .count();

    let mut lines = vec![Line::from(state.tr(TextKey::Applications))];

    if !state.smart_care_has_analyze_result {
        lines.push(Line::from(""));
        lines.push(Line::from(localized(
            state,
            "[ Analyze Applications ]",
            "[ Anwendungen analysieren ]",
        )));
        lines.push(Line::from(localized(
            state,
            "Press 'a' to analyze and load the app list.",
            "Drücke 'a', um die App-Liste zu analysieren und zu laden.",
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "{}: {} | plugins={} | trusted={}",
            localized(state, "Capability", "Capability"),
            if enabled {
                localized(state, "ON", "AN")
            } else {
                localized(state, "OFF", "AUS")
            },
            descriptors.len(),
            trusted_count
        )));
        if descriptors.is_empty() {
            lines.push(Line::from(localized(
                state,
                "No Applications plugin installed.",
                "Kein Anwendungen-Plugin installiert.",
            )));
            lines.push(Line::from(localized(
                state,
                "Install flow: n install -> f preflight -> t test",
                "Installationsablauf: n installieren -> f Preflight -> t Test",
            )));
        }
        if let Some(error) = &state.last_error {
            lines.push(Line::from(""));
            lines.push(Line::from(localized(state, "Error", "Fehler")));
            for line in simplify_diagnostic_lines(vec![error.clone()]) {
                for wrapped in wrap_with_prefix("- ", &line, content_width) {
                    lines.push(Line::from(wrapped));
                }
            }
        }
        return lines;
    }

    lines.push(Line::from(localized(
        state,
        "Analyze done. App list is ready.",
        "Analyse abgeschlossen. App-Liste ist bereit.",
    )));
    lines.push(Line::from(localized(
        state,
        "Actions: j/k move | space select | p paths | r reanalyze | x update | u uninstall(selected)",
        "Aktionen: j/k bewegen | Leertaste wählen | p Pfade | r erneut | x aktualisieren | u deinstallieren",
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(localized(
        state,
        "Applications plugins",
        "Anwendungen-Plugins",
    )));

    if descriptors.is_empty() {
        lines.push(Line::from(localized(state, "- none", "- keine")));
        lines.push(Line::from(localized(
            state,
            "- start with: n install -> f preflight -> t test",
            "- beginne mit: n installieren -> f Preflight -> t Test",
        )));
    } else {
        for descriptor in descriptors.iter().take(6) {
            lines.push(Line::from(format!(
                "- {}@{} | {} | trusted={}",
                descriptor.pack_id,
                descriptor.version.as_deref().unwrap_or("n/a"),
                if descriptor.enabled {
                    localized(state, "enabled", "aktiviert")
                } else {
                    localized(state, "disabled", "deaktiviert")
                },
                yes_no(descriptor.trusted_identity.is_some())
            )));
        }
        if descriptors.len() > 6 {
            let more_count = descriptors.len().saturating_sub(6);
            lines.push(Line::from(match state.effective_language() {
                Language::English => format!("- ... and {more_count} more"),
                Language::German => format!("- ... und {more_count} weitere"),
            }));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(localized(
        state,
        "Installed applications",
        "Installierte Anwendungen",
    )));
    let app_items = state.applications_items();
    if app_items.is_empty() {
        lines.push(Line::from(localized(
            state,
            "- no application found",
            "- keine Anwendung gefunden",
        )));
    } else {
        lines.push(Line::from(match state.effective_language() {
            Language::English => format!(
                "- {} app(s) found | selected={}",
                app_items.len(),
                state.applications_selected_count()
            ),
            Language::German => format!(
                "- {} App(s) gefunden | ausgewählt={}",
                app_items.len(),
                state.applications_selected_count()
            ),
        }));
        for (index, app_name) in app_items.iter().enumerate() {
            let marker = if index == state.applications_selected_row {
                "▶"
            } else {
                " "
            };
            let selected = if state.applications_is_selected(app_name) {
                "[x]"
            } else {
                "[ ]"
            };
            let left = format!("  {marker} {selected} {app_name}");
            let line = state
                .applications_update_label(app_name)
                .map(|label| right_aligned_text(&left, &format!("[{label}]"), content_width))
                .unwrap_or(left);
            lines.push(Line::from(line));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(localized(state, "Environment", "Umgebung")));
    lines.push(Line::from(format!(
        "- {}: {}",
        localized(state, "Host", "Host"),
        snapshot.metrics.host_name.as_deref().unwrap_or("n/a")
    )));
    lines.push(Line::from(match state.effective_language() {
        Language::English => format!(
            "- Installed plugin dirs: {} | lockfile entries: {}",
            snapshot.installed_plugins_on_disk, snapshot.plugin_count
        ),
        Language::German => format!(
            "- Installierte Plugin-Ordner: {} | Lockfile-Einträge: {}",
            snapshot.installed_plugins_on_disk, snapshot.plugin_count
        ),
    }));
    if let Some(line) = smart_care_plugin_action_brief_line(state) {
        lines.push(Line::from(format!("- {line}")));
    }
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(localized(state, "Error", "Fehler")));
        for line in simplify_diagnostic_lines(vec![error.clone()]) {
            for wrapped in wrap_with_prefix("- ", &line, content_width) {
                lines.push(Line::from(wrapped));
            }
        }
    }

    lines
}

fn right_aligned_text(left: &str, right: &str, width: usize) -> String {
    let min_gap = 2;
    let left_len = left.chars().count();
    let right_len = right.chars().count();
    if width == 0 || left_len + min_gap + right_len >= width {
        return format!("{left} {right}");
    }
    format!(
        "{left}{:gap$}{right}",
        "",
        gap = width.saturating_sub(left_len + right_len)
    )
}

fn localized(state: &AppState, en: &'static str, de: &'static str) -> &'static str {
    match state.effective_language() {
        Language::English => en,
        Language::German => de,
    }
}

fn capability_lines(
    state: &AppState,
    snapshot: &DashboardSnapshot,
    content_width: usize,
) -> Vec<Line<'static>> {
    let Some(capability) = state.active_view.smart_care_capability() else {
        return vec![Line::from("Capability view is unavailable.")];
    };

    let selected = state.smart_care_is_enabled(capability);
    let _capability_source = classify_capability_descriptor_source(
        capability,
        &state.smart_care_descriptors,
        &state.smart_care_dev_fallback_pack_ids,
    );
    let mut candidates = state
        .smart_care_descriptors
        .iter()
        .filter(|descriptor| descriptor.capability == capability)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .trusted_identity
            .is_some()
            .cmp(&left.trusted_identity.is_some())
            .then_with(|| left.pack_id.cmp(&right.pack_id))
            .then_with(|| left.version.cmp(&right.version))
    });
    let enabled = candidates
        .iter()
        .filter(|descriptor| descriptor.enabled)
        .copied()
        .collect::<Vec<_>>();
    let skipped_for_capability = state
        .smart_care_skipped_pack_ids
        .iter()
        .filter(|pack_id| capability_from_pack_id(pack_id) == Some(capability))
        .cloned()
        .collect::<Vec<_>>();
    let trusted_enabled = enabled
        .iter()
        .filter(|descriptor| descriptor.trusted_identity.is_some())
        .count();
    let capability_status = if !selected {
        SmartCareCapabilityStatus::Disabled
    } else if enabled.is_empty() {
        SmartCareCapabilityStatus::MissingPlugin
    } else if trusted_enabled == 0 {
        SmartCareCapabilityStatus::UntrustedOnly
    } else {
        SmartCareCapabilityStatus::Ready
    };

    let mut lines = vec![
        Line::from(format!("{} capability", capability_label(capability))),
        Line::from(format!(
            "State: {} | Status: {} [{}]",
            if selected { "ON" } else { "OFF" },
            capability_status.as_str(),
            status_chip_label(capability_status)
        )),
        Line::from(format!(
            "Next action: {}",
            smart_care_next_action_hint(state)
        )),
        Line::from(format!(
            "Plugins: matched={} trusted={} skipped={} (i: details)",
            enabled.len(),
            trusted_enabled,
            skipped_for_capability.len()
        )),
    ];
    lines.extend(capability_domain_lines(capability, state, snapshot));
    if candidates.is_empty() {
        lines.push(Line::from(
            "- none detected in installed packs for this capability",
        ));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from("Active plugin targets"));
        for descriptor in candidates.iter().take(5) {
            let trusted = if descriptor.trusted_identity.is_some() {
                "yes"
            } else {
                "no"
            };
            lines.push(Line::from(format!(
                "- {}@{} | {} | trusted={}",
                descriptor.pack_id,
                descriptor.version.as_deref().unwrap_or("n/a"),
                if descriptor.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                trusted
            )));
        }
        if candidates.len() > 5 {
            lines.push(Line::from(format!(
                "- ... and {} more (i for full details)",
                candidates.len().saturating_sub(5)
            )));
        }
    }

    let mut blockers = Vec::new();
    if selected && enabled.is_empty() {
        blockers.push("no installed capability plugin".to_string());
    }
    if selected && !enabled.is_empty() && trusted_enabled == 0 {
        blockers.push("only untrusted capability plugins are installed".to_string());
    }
    if !skipped_for_capability.is_empty() {
        blockers.push(format!(
            "resolver skipped {} pack(s) for this capability",
            skipped_for_capability.len()
        ));
    }
    if !blockers.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Blockers"));
        for blocker in blockers {
            lines.push(Line::from(format!("- {blocker}")));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from("Actions: space toggle | n/f/t plugin | a analyze | v review | Shift+X arm | x run | u undo"));
    if let Some(error) = &state.smart_care_error {
        lines.push(Line::from(""));
        lines.push(Line::from("Resolver warning"));
        for line in simplify_diagnostic_lines(vec![error.clone()]) {
            for wrapped in wrap_with_prefix("- ", &line, content_width) {
                lines.push(Line::from(wrapped));
            }
        }
    }
    if !state.smart_care_last_analyze.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Latest analyze result"));
        for line in simplify_diagnostic_lines(state.smart_care_last_analyze.clone())
            .into_iter()
            .take(6)
        {
            for wrapped in wrap_with_prefix("- ", &line, content_width) {
                lines.push(Line::from(wrapped));
            }
        }
    }
    if let Some(line) = smart_care_plugin_action_brief_line(state) {
        lines.push(Line::from(format!("Plugin command: {line} (details: i)")));
    }
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from("Error"));
        for line in simplify_diagnostic_lines(vec![error.clone()]) {
            for wrapped in wrap_with_prefix("- ", &line, content_width) {
                lines.push(Line::from(wrapped));
            }
        }
    }
    lines
}

fn capability_domain_lines(
    capability: SmartCareCapability,
    state: &AppState,
    snapshot: &DashboardSnapshot,
) -> Vec<Line<'static>> {
    let metrics = &snapshot.metrics;
    let mut lines = vec![Line::from(""), Line::from("Domain summary")];

    match capability {
        SmartCareCapability::Cleanup => {
            lines.push(Line::from(format!(
                "- Disk used: {:.1}% | free: {}",
                disk_used_pct(snapshot).unwrap_or(0.0),
                format_bytes(metrics.disk_available_bytes.unwrap_or(0))
            )));
            lines.push(Line::from(format!(
                "- IO read/write: {:.2} / {:.2} MB/s",
                metrics.disk_read_rate_mbps.unwrap_or(0.0),
                metrics.disk_write_rate_mbps.unwrap_or(0.0)
            )));
            lines.push(Line::from(format!(
                "- Warnings: {} | Suggested actions: {}",
                snapshot.warnings.len(),
                snapshot.suggested_actions.len()
            )));
        }
        SmartCareCapability::Performance => {
            lines.push(Line::from(format!(
                "- CPU total: {:.1}% | cores: {}",
                metrics.cpu_usage_pct.unwrap_or(0.0),
                metrics.cpu_cores.unwrap_or(0)
            )));
            lines.push(Line::from(format!(
                "- Load avg: {:.2} / {:.2} / {:.2}",
                metrics.load_avg_1m.unwrap_or(0.0),
                metrics.load_avg_5m.unwrap_or(0.0),
                metrics.load_avg_15m.unwrap_or(0.0)
            )));
            lines.push(Line::from(format!(
                "- Memory used: {:.1}% | processes: {}",
                metrics.memory_used_pct.unwrap_or(0.0),
                metrics.process_count.unwrap_or(0)
            )));
        }
        SmartCareCapability::Applications => {
            lines.push(Line::from(format!(
                "- Installed plugin dirs: {} | lockfile plugins: {}",
                snapshot.installed_plugins_on_disk, snapshot.plugin_count
            )));
            lines.push(Line::from(format!(
                "- Trusted installed plugins: {}",
                snapshot
                    .plugins
                    .iter()
                    .filter(|plugin| !plugin.trusted_identity.is_empty())
                    .count()
            )));
            lines.push(Line::from(format!(
                "- Registry entries: {} | present: {}",
                snapshot.registry.entry_count.unwrap_or(0),
                yes_no(snapshot.registry.present)
            )));
        }
        SmartCareCapability::Protection => {
            let critical_total = snapshot
                .checks
                .iter()
                .filter(|check| check.severity == preen_core::dashboard::CheckSeverity::Critical)
                .count();
            let critical_passed = snapshot
                .checks
                .iter()
                .filter(|check| {
                    check.severity == preen_core::dashboard::CheckSeverity::Critical && check.passed
                })
                .count();
            let warning_total = snapshot
                .checks
                .iter()
                .filter(|check| check.severity == preen_core::dashboard::CheckSeverity::Warning)
                .count();
            let warning_passed = snapshot
                .checks
                .iter()
                .filter(|check| {
                    check.severity == preen_core::dashboard::CheckSeverity::Warning && check.passed
                })
                .count();
            lines.push(Line::from(format!(
                "- Critical checks: {critical_passed}/{critical_total} passed"
            )));
            lines.push(Line::from(format!(
                "- Warning checks: {warning_passed}/{warning_total} passed"
            )));
            lines.push(Line::from(format!(
                "- Warning messages: {}",
                snapshot.warnings.len()
            )));
        }
    }

    if state.smart_care_last_run_report.is_empty() {
        lines.push(Line::from("- Last run: n/a"));
    } else {
        lines.push(Line::from(format!(
            "- Last run report lines: {}",
            state.smart_care_last_run_report.len()
        )));
    }
    lines
}

fn disk_used_pct(snapshot: &DashboardSnapshot) -> Option<f64> {
    snapshot
        .metrics
        .disk_free_pct
        .map(|free_pct| (100.0 - free_pct).clamp(0.0, 100.0))
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let value = bytes as f64;
    if value >= GB {
        format!("{:.1}GB", value / GB)
    } else if value >= MB {
        format!("{:.1}MB", value / MB)
    } else if value >= KB {
        format!("{:.1}KB", value / KB)
    } else {
        format!("{bytes}B")
    }
}

#[derive(Clone)]
struct SmartCareCardLine {
    line: Line<'static>,
}

fn preview_from_state(state: &AppState) -> SmartCarePreview {
    preen_core::smart_care::build_preview_from_descriptors(
        &state.smart_care_profile,
        &state.smart_care_descriptors,
    )
}

fn render_smart_care_cards(
    state: &AppState,
    preview: &SmartCarePreview,
    selected_index: usize,
    content_width: usize,
    can_review: bool,
    can_run: bool,
) -> Vec<Line<'static>> {
    let skipped_counts = skipped_pack_counts_by_capability(&state.smart_care_skipped_pack_ids);
    let cards = preview
        .cards
        .iter()
        .enumerate()
        .map(|(index, card)| {
            let selected = index == selected_index;
            let source_label = card_source_label(state, card.capability);
            let skipped_count = skipped_counts.get(&card.capability).copied().unwrap_or(0);
            render_smart_care_card(
                card,
                source_label,
                skipped_count,
                if selected { "selected" } else { "normal" },
                content_width,
                can_review,
                can_run,
            )
        })
        .collect::<Vec<_>>();
    render_card_grid(&cards, content_width)
}

fn card_source_label(state: &AppState, capability: SmartCareCapability) -> &'static str {
    classify_capability_descriptor_source(
        capability,
        &state.smart_care_descriptors,
        &state.smart_care_dev_fallback_pack_ids,
    )
    .as_str()
}

fn render_smart_care_card(
    card: &preen_core::smart_care::SmartCareCapabilityCard,
    source_label: &'static str,
    skipped_count: usize,
    mode: &str,
    content_width: usize,
    can_review: bool,
    can_run: bool,
) -> Vec<SmartCareCardLine> {
    let card_width = if content_width >= 92 {
        content_width.saturating_sub(3) / 2
    } else {
        content_width
    }
    .clamp(30, 60);
    let inner_width = card_width.saturating_sub(2);
    let selected = mode == "selected";
    let border_color = if skipped_count > 0 {
        PALETTE_DANGER
    } else if card.enabled {
        PALETTE_OK
    } else {
        PALETTE_WARN
    };
    let border_style = if selected {
        Style::default()
            .fg(PALETTE_ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(border_color)
    };
    let title = format!(
        "{} [{}]",
        capability_label(card.capability),
        if card.enabled { "ON" } else { "OFF" }
    );
    let top = top_border_with_title(&title, inner_width);
    let status_line = card_status_line(
        card.status,
        selected,
        border_style,
        inner_width,
        skipped_count,
    );
    let headline_line = card_content_line(
        &format!("  {}", card.headline),
        Style::default().fg(PALETTE_TEXT),
        border_style,
        inner_width,
    );
    let subline_line = card_content_line(
        &format!("  {}", card.subline),
        Style::default().fg(PALETTE_TEXT),
        border_style,
        inner_width,
    );
    let meta_line = card_content_line(
        &format!(
            "  source={} trusted={} skipped={} review_items={}",
            source_label, card.trusted_plugin_count, skipped_count, card.review_count
        ),
        Style::default().fg(PALETTE_TEXT),
        border_style,
        inner_width,
    );
    let bottom_hint = if selected {
        if !can_review {
            "  <space> toggle | n/f/t plugin | review after analyze"
        } else if can_run {
            "  <space> toggle | n/f/t plugin | v review | x run"
        } else {
            "  <space> toggle | n/f/t plugin | v review to enable run"
        }
    } else {
        "  h next | l prev"
    };
    let hint_line = card_content_line(
        bottom_hint,
        Style::default().fg(PALETTE_ACCENT),
        border_style,
        inner_width,
    );
    let bottom = format!("╰{}╯", "─".repeat(inner_width));

    vec![
        SmartCareCardLine {
            line: Line::from(Span::styled(top, border_style)),
        },
        status_line,
        headline_line,
        subline_line,
        meta_line,
        hint_line,
        SmartCareCardLine {
            line: Line::from(Span::styled(bottom, border_style)),
        },
    ]
}

fn card_content_line(
    raw: &str,
    content_style: Style,
    border_style: Style,
    inner_width: usize,
) -> SmartCareCardLine {
    let content = pad_to_width(&truncate_with_ellipsis(raw, inner_width), inner_width);
    SmartCareCardLine {
        line: Line::from(vec![
            Span::styled("│", border_style),
            Span::styled(content, content_style),
            Span::styled("│", border_style),
        ]),
    }
}

fn card_status_line(
    status: SmartCareCapabilityStatus,
    selected: bool,
    border_style: Style,
    inner_width: usize,
    skipped_count: usize,
) -> SmartCareCardLine {
    let marker = if selected { "▶" } else { " " };
    let marker_style = if selected {
        Style::default()
            .fg(PALETTE_ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(PALETTE_LINE)
    };
    let rest = pad_to_width(
        &truncate_with_ellipsis(
            &format!(
                " status: {} [{}]{}",
                status.as_str(),
                status_chip_label(status),
                if skipped_count > 0 {
                    format!(" | skipped={skipped_count}")
                } else {
                    String::new()
                }
            ),
            inner_width.saturating_sub(1),
        ),
        inner_width.saturating_sub(1),
    );
    SmartCareCardLine {
        line: Line::from(vec![
            Span::styled("│", border_style),
            Span::styled(marker.to_string(), marker_style),
            Span::styled(rest, status_style(status)),
            Span::styled("│", border_style),
        ]),
    }
}

fn skipped_pack_counts_by_capability(
    skipped_pack_ids: &BTreeSet<String>,
) -> BTreeMap<SmartCareCapability, usize> {
    let mut counts = BTreeMap::new();
    for pack_id in skipped_pack_ids {
        if let Some(capability) = capability_from_pack_id(pack_id) {
            *counts.entry(capability).or_insert(0) += 1;
        }
    }
    counts
}

fn skipped_pack_blockers(state: &AppState) -> Vec<String> {
    let mut blockers = Vec::new();
    for pack_id in &state.smart_care_skipped_pack_ids {
        if let Some(capability) = capability_from_pack_id(pack_id) {
            blockers.push(format!(
                "{} skipped plugin pack: {pack_id}",
                capability.title()
            ));
        } else {
            blockers.push(format!("Skipped plugin pack: {pack_id}"));
        }
    }
    blockers
}

fn capability_from_pack_id(pack_id: &str) -> Option<SmartCareCapability> {
    let normalized = pack_id.to_ascii_lowercase();
    if normalized.contains(".cleanup") {
        Some(SmartCareCapability::Cleanup)
    } else if normalized.contains(".performance") {
        Some(SmartCareCapability::Performance)
    } else if normalized.contains(".applications") || normalized.contains(".apps") {
        Some(SmartCareCapability::Applications)
    } else if normalized.contains(".protection") {
        Some(SmartCareCapability::Protection)
    } else {
        None
    }
}

fn status_chip_label(status: SmartCareCapabilityStatus) -> &'static str {
    match status {
        SmartCareCapabilityStatus::Ready => "READY",
        SmartCareCapabilityStatus::UntrustedOnly => "UNTRUSTED",
        SmartCareCapabilityStatus::MissingPlugin => "MISSING",
        SmartCareCapabilityStatus::Disabled => "DISABLED",
    }
}

fn top_border_with_title(title: &str, inner_width: usize) -> String {
    let label = truncate_with_ellipsis(&format!(" {} ", title), inner_width);
    let fill_len = inner_width.saturating_sub(label.chars().count());
    format!("╭{}{}╮", label, "─".repeat(fill_len))
}

fn status_style(status: SmartCareCapabilityStatus) -> Style {
    match status {
        SmartCareCapabilityStatus::Ready => Style::default().fg(PALETTE_OK),
        SmartCareCapabilityStatus::UntrustedOnly => Style::default().fg(PALETTE_WARN),
        SmartCareCapabilityStatus::MissingPlugin => Style::default().fg(PALETTE_DANGER),
        SmartCareCapabilityStatus::Disabled => Style::default().fg(PALETTE_LINE),
    }
}

fn render_card_grid(cards: &[Vec<SmartCareCardLine>], content_width: usize) -> Vec<Line<'static>> {
    if cards.is_empty() {
        return vec![Line::from("No smart care card available.")];
    }
    if content_width < 92 {
        let mut out = Vec::new();
        for card in cards {
            for row in card {
                out.push(row.line.clone());
            }
            out.push(Line::from(""));
        }
        if !out.is_empty() {
            let _ = out.pop();
        }
        return out;
    }

    let mut out = Vec::new();
    let gap = "   ".to_string();
    for pair in cards.chunks(2) {
        let left = &pair[0];
        let right = pair.get(1);
        let row_count = left
            .len()
            .max(right.map(|item| item.len()).unwrap_or_default());
        for idx in 0..row_count {
            let left_row = left.get(idx).cloned().unwrap_or(SmartCareCardLine {
                line: Line::from(""),
            });
            if let Some(right) = right {
                let right_row = right.get(idx).cloned().unwrap_or(SmartCareCardLine {
                    line: Line::from(""),
                });
                let mut spans = left_row.line.spans;
                spans.push(Span::raw(gap.clone()));
                spans.extend(right_row.line.spans);
                out.push(Line::from(spans));
            } else {
                out.push(left_row.line);
            }
        }
        out.push(Line::from(""));
    }
    if !out.is_empty() {
        let _ = out.pop();
    }
    out
}

fn smart_care_review_lines(
    state: &AppState,
    preview: &SmartCarePreview,
    snapshot: &DashboardSnapshot,
) -> Vec<Line<'static>> {
    let total_entries = preview.review_entries.len();
    let selected_entries = preview
        .review_entries
        .iter()
        .filter(|entry| !state.smart_care_review_disabled_entries.contains(&entry.id))
        .count();
    let capability_review =
        review_entries_by_capability(preview, &state.smart_care_review_disabled_entries);
    let skipped_counts = skipped_pack_counts_by_capability(&state.smart_care_skipped_pack_ids);
    let workflow = summarize_review_workflow(state);
    let run_gate = smart_care_run_gate(state);
    let next_action = smart_care_next_action_hint(state);
    let run_summary = smart_care_last_run_summary(&state.smart_care_last_run_report);
    let mut lines = vec![
        Line::from("Smart Care Review"),
        Line::from("Review what Smart Care will run before apply."),
        Line::from(format!(
            "Flow: analyze={} review={} arm={} run={}",
            workflow.analyze_stage, workflow.review_stage, workflow.apply_stage, workflow.run_stage
        )),
        Line::from(format!("Run gate: {run_gate} | Next: {next_action}")),
        Line::from(format!(
            "Apply arm: {} | Last run: {run_summary}",
            yes_no(state.smart_care_apply_armed)
        )),
        Line::from(format!(
            "Selected items: {selected_entries}/{total_entries}"
        )),
        Line::from(format!("Overall ready: {}", yes_no(preview.overall_ready))),
        Line::from(format!(
            "Descriptor source: {} | Installed plugins: {}",
            state
                .smart_care_source_summary
                .as_deref()
                .unwrap_or("unknown"),
            snapshot.plugin_count
        )),
        Line::from(""),
        Line::from("Controls"),
        Line::from("j/k scroll | h/l select entry | space toggle | 1/2/3/4 toggle capability"),
        Line::from("A all | N none | a re-analyze | Shift+X arm | x run | u undo | b/v/Esc close"),
        Line::from(format!(
            "Action: {}",
            if state.smart_care_action_running {
                state
                    .smart_care_action_label
                    .as_deref()
                    .unwrap_or("background task")
            } else {
                "idle"
            }
        )),
        Line::from(""),
        Line::from("Capability cards"),
    ];
    for capability in [
        SmartCareCapability::Cleanup,
        SmartCareCapability::Performance,
        SmartCareCapability::Applications,
        SmartCareCapability::Protection,
    ] {
        let card = capability_card(preview, capability);
        let (selected_count, total_count) = capability_review.counts_for(capability);
        lines.push(Line::from(format!(
            "- [{}] {} [{}] status={} plugins={} trusted={} selected={}/{}{}",
            capability_shortcut_key(capability),
            capability.title(),
            if card.map(|entry| entry.enabled).unwrap_or(false) {
                "ON"
            } else {
                "OFF"
            },
            card.map(|entry| entry.status.as_str()).unwrap_or("unknown"),
            card.map(|entry| entry.plugin_count).unwrap_or(0),
            card.map(|entry| entry.trusted_plugin_count).unwrap_or(0),
            selected_count,
            total_count,
            skipped_suffix_for_capability(capability, &skipped_counts)
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Review entries"));

    if preview.review_entries.is_empty() {
        lines.push(Line::from(
            "- none (blocked by missing or untrusted capability plugin)",
        ));
    } else {
        for capability in [
            SmartCareCapability::Cleanup,
            SmartCareCapability::Performance,
            SmartCareCapability::Applications,
            SmartCareCapability::Protection,
        ] {
            lines.push(Line::from(format!(
                "- [{}] {}",
                capability_shortcut_key(capability),
                capability.title(),
            )));
            for (index, entry) in preview
                .review_entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.capability == capability)
            {
                let active = index == state.smart_care_review_selected_entry;
                let enabled = !state.smart_care_review_disabled_entries.contains(&entry.id);
                let marker = if active { ">" } else { " " };
                let checkbox = if enabled { "[x]" } else { "[ ]" };
                let source = classify_descriptor_pack_source(
                    entry.pack_id.as_str(),
                    &state.smart_care_dev_fallback_pack_ids,
                )
                .as_str();
                let review_label = entry
                    .rule_label
                    .as_deref()
                    .or(entry.rule_id.as_deref())
                    .unwrap_or("plugin review");
                lines.push(Line::from(format!("  {marker} {checkbox} {review_label}")));
                lines.push(Line::from(format!(
                    "    plugin={}@{} | trusted={} | source={}",
                    entry.pack_id,
                    entry.version.as_deref().unwrap_or("n/a"),
                    yes_no(entry.trusted_identity.is_some()),
                    source
                )));
            }
        }
    }
    let mut blockers = preview.blockers.clone();
    blockers.extend(skipped_pack_blockers(state));
    if !blockers.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Blockers"));
        for blocker in blockers.iter().take(8) {
            lines.push(Line::from(format!("- {blocker}")));
        }
        if blockers.len() > 8 {
            lines.push(Line::from(format!(
                "- ... and {} more",
                blockers.len().saturating_sub(8)
            )));
        }
    }
    if !state.smart_care_skipped_pack_ids.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Skipped plugin packs"));
        for pack_id in &state.smart_care_skipped_pack_ids {
            let (capability_label, spec) = match capability_from_pack_id(pack_id) {
                Some(capability) => (
                    capability.title().to_string(),
                    state.preferred_plugin_spec_for_capability(capability),
                ),
                None => ("Unknown".to_string(), pack_id.to_string()),
            };
            lines.push(Line::from(format!(
                "- {capability_label}: {pack_id} | hint: n install / f preflight / t test ({spec})"
            )));
        }
    }
    if !state.smart_care_last_analyze.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Analyze diagnostics (latest)"));
        for line in simplify_diagnostic_lines(state.smart_care_last_analyze.clone())
            .into_iter()
            .take(4)
        {
            lines.push(Line::from(format!("- {line}")));
        }
    }
    if !state.smart_care_last_run_report.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Execution report (latest)"));
        for line in simplify_diagnostic_lines(state.smart_care_last_run_report.clone())
            .into_iter()
            .take(4)
        {
            lines.push(Line::from(format!("- {line}")));
        }
    }
    if let Some(error) = &state.smart_care_error {
        lines.push(Line::from(""));
        lines.push(Line::from("Resolver warning"));
        for line in simplify_diagnostic_lines(vec![error.clone()]) {
            lines.push(Line::from(format!("- {line}")));
        }
    }
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from("Error"));
        for line in simplify_diagnostic_lines(vec![error.clone()]) {
            lines.push(Line::from(format!("- {line}")));
        }
    }
    lines
}

fn skipped_suffix_for_capability(
    capability: SmartCareCapability,
    skipped_counts: &BTreeMap<SmartCareCapability, usize>,
) -> String {
    let skipped = skipped_counts.get(&capability).copied().unwrap_or(0);
    if skipped == 0 {
        String::new()
    } else {
        format!(" | skipped={skipped}")
    }
}

fn capability_card(
    preview: &SmartCarePreview,
    capability: SmartCareCapability,
) -> Option<&preen_core::smart_care::SmartCareCapabilityCard> {
    preview
        .cards
        .iter()
        .find(|card| card.capability == capability)
}

#[derive(Default)]
struct CapabilityReviewSelection {
    cleanup_selected: usize,
    cleanup_total: usize,
    performance_selected: usize,
    performance_total: usize,
    applications_selected: usize,
    applications_total: usize,
    protection_selected: usize,
    protection_total: usize,
}

impl CapabilityReviewSelection {
    fn counts_for(&self, capability: SmartCareCapability) -> (usize, usize) {
        match capability {
            SmartCareCapability::Cleanup => (self.cleanup_selected, self.cleanup_total),
            SmartCareCapability::Performance => (self.performance_selected, self.performance_total),
            SmartCareCapability::Applications => {
                (self.applications_selected, self.applications_total)
            }
            SmartCareCapability::Protection => (self.protection_selected, self.protection_total),
        }
    }
}

#[derive(Default)]
struct ReviewWorkflowSummary {
    analyze_stage: String,
    review_stage: String,
    apply_stage: String,
    run_stage: String,
}

fn summarize_review_workflow(state: &AppState) -> ReviewWorkflowSummary {
    let mut summary = ReviewWorkflowSummary {
        analyze_stage: if state.smart_care_has_analyze_result {
            "ready".to_string()
        } else {
            "missing".to_string()
        },
        review_stage: if state.smart_care_has_review_result {
            if state.smart_care_review_mode {
                "open".to_string()
            } else {
                "ready".to_string()
            }
        } else {
            "locked".to_string()
        },
        apply_stage: if state.smart_care_apply_armed {
            "armed".to_string()
        } else {
            "not-armed".to_string()
        },
        run_stage: "idle".to_string(),
        ..ReviewWorkflowSummary::default()
    };
    let mut run_state_raw = None::<String>;

    if state.smart_care_action_running {
        match state.smart_care_action_label.as_deref() {
            Some("run") => summary.run_stage = "running".to_string(),
            _ => {}
        }
    }

    for line in &state.smart_care_last_run_report {
        if let Some(raw) = line.strip_prefix("run:") {
            run_state_raw = Some(raw.trim().to_string());
        }
    }

    if let Some(run_state) = run_state_raw.as_deref() {
        summary.run_stage = if run_state == "blocked" {
            "blocked".to_string()
        } else {
            "completed".to_string()
        };
    }

    summary
}

fn smart_care_run_gate(state: &AppState) -> String {
    state
        .smart_care_validate_run_request()
        .map(|_| "ready".to_string())
        .unwrap_or_else(|error| format!("blocked ({error})"))
}

fn smart_care_next_action_hint(state: &AppState) -> &'static str {
    if !state.smart_care_has_analyze_result {
        "press a (analyze)"
    } else if !state.smart_care_has_review_result {
        "press v (open review)"
    } else if !state.smart_care_apply_armed {
        "press Shift+X (arm apply)"
    } else {
        "press x (run)"
    }
}

fn smart_care_last_run_summary(lines: &[String]) -> String {
    if lines.is_empty() {
        return "n/a".to_string();
    }

    let mut run_state = None::<String>;
    let mut reason = None::<String>;
    let mut hint = None::<String>;
    let mut selected_entries = None::<String>;
    let mut success_rules = None::<String>;
    let mut failed_rules = None::<String>;

    for line in lines {
        let trimmed = line.trim();
        if run_state.is_none() && (trimmed.starts_with("run:") || trimmed.starts_with("undo:")) {
            run_state = Some(trimmed.to_string());
        }
        if reason.is_none() && trimmed.starts_with("reason:") {
            reason = Some(trimmed.trim_start_matches("reason:").trim().to_string());
        }
        if hint.is_none() && trimmed.starts_with("hint:") {
            hint = Some(trimmed.trim_start_matches("hint:").trim().to_string());
        }
        if selected_entries.is_none() && trimmed.starts_with("selected_entries:") {
            selected_entries = Some(
                trimmed
                    .trim_start_matches("selected_entries:")
                    .trim()
                    .to_string(),
            );
        }
        if success_rules.is_none() && trimmed.starts_with("success_rules:") {
            success_rules = Some(
                trimmed
                    .trim_start_matches("success_rules:")
                    .trim()
                    .to_string(),
            );
        }
        if failed_rules.is_none() && trimmed.starts_with("failed_rules:") {
            failed_rules = Some(
                trimmed
                    .trim_start_matches("failed_rules:")
                    .trim()
                    .to_string(),
            );
        }
    }

    let mut parts = Vec::new();
    if let Some(state) = run_state {
        parts.push(state);
    }
    if let Some(entries) = selected_entries {
        parts.push(format!("selected_entries={entries}"));
    }
    if let Some(success) = success_rules {
        parts.push(format!("success_rules={success}"));
    }
    if let Some(failed) = failed_rules {
        parts.push(format!("failed_rules={failed}"));
    }
    if let Some(reason) = reason {
        parts.push(format!("reason={reason}"));
    } else if let Some(hint) = hint {
        parts.push(format!("hint={hint}"));
    }

    if parts.is_empty() {
        "completed (details below)".to_string()
    } else {
        parts.join(" | ")
    }
}

fn review_entries_by_capability(
    preview: &SmartCarePreview,
    disabled_ids: &BTreeSet<String>,
) -> CapabilityReviewSelection {
    let mut summary = CapabilityReviewSelection::default();
    for entry in &preview.review_entries {
        let enabled = !disabled_ids.contains(&entry.id);
        match entry.capability {
            SmartCareCapability::Cleanup => {
                summary.cleanup_total += 1;
                if enabled {
                    summary.cleanup_selected += 1;
                }
            }
            SmartCareCapability::Performance => {
                summary.performance_total += 1;
                if enabled {
                    summary.performance_selected += 1;
                }
            }
            SmartCareCapability::Applications => {
                summary.applications_total += 1;
                if enabled {
                    summary.applications_selected += 1;
                }
            }
            SmartCareCapability::Protection => {
                summary.protection_total += 1;
                if enabled {
                    summary.protection_selected += 1;
                }
            }
        }
    }
    summary
}

fn is_capability_plugin_action(action: PluginActionKind) -> bool {
    matches!(
        action,
        PluginActionKind::Install | PluginActionKind::Preflight | PluginActionKind::Test
    )
}

fn smart_care_plugin_action_brief_line(state: &AppState) -> Option<String> {
    let action = state.plugin_last_action?;
    if !is_capability_plugin_action(action) {
        return None;
    }
    if state.plugin_action_running {
        return Some(format!("plugin {}: running", action.label()));
    }
    let raw_lines = if !state.plugin_last_diagnostics.is_empty() {
        state.plugin_last_diagnostics.clone()
    } else {
        state.plugin_last_output.clone()
    };
    let status = summarize_plugin_action_status(&raw_lines).unwrap_or("unknown");
    Some(format!("plugin {}: {}", action.label(), status))
}

fn summarize_plugin_action_status(lines: &[String]) -> Option<&'static str> {
    for line in lines {
        let compact = line.trim();
        if compact.contains("overall_passed: true")
            || compact.contains("overall_passed=true")
            || compact.contains("\"overall_passed\":true")
        {
            return Some("ok");
        }
        if compact.contains("overall_passed: false")
            || compact.contains("overall_passed=false")
            || compact.contains("\"overall_passed\":false")
            || compact.contains("\"kind\":\"error\"")
            || compact.contains("error during command execution")
        {
            return Some("failed");
        }
    }
    None
}

fn simplify_diagnostic_lines(lines: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for line in lines {
        let compact = line.trim();
        if compact.is_empty() {
            continue;
        }
        if compact.starts_with("{\"schema_version\":") {
            if let Some(error_kind) = extract_json_string_field(compact, "error_kind")
                && seen.insert(format!("error_kind:{error_kind}"))
            {
                out.push(format!("error_kind: {error_kind}"));
            }
            if let Some(detail_code) = extract_json_string_field(compact, "detail_code")
                && seen.insert(format!("detail_code:{detail_code}"))
            {
                out.push(format!("detail_code: {detail_code}"));
            }
            if let Some(hint_code) = extract_json_string_field(compact, "hint_code")
                && seen.insert(format!("hint_code:{hint_code}"))
            {
                out.push(format!("hint_code: {hint_code}"));
            }
            if let Some(hint_message) = extract_json_string_field(compact, "hint_message")
                && seen.insert(format!("hint_message:{hint_message}"))
            {
                out.push(format!("hint: {hint_message}"));
            }
            if let Some(message) = extract_json_string_field(compact, "message")
                && seen.insert(format!("message:{message}"))
            {
                out.push(format!("message: {message}"));
            }
            continue;
        }
        if let Some(detail_code) = extract_json_string_field(compact, "detail_code") {
            if seen.insert(format!("detail_code:{detail_code}")) {
                out.push(format!("detail_code: {detail_code}"));
            }
        }
        if let Some(hint_code) = extract_json_string_field(compact, "hint_code") {
            if seen.insert(format!("hint_code:{hint_code}")) {
                out.push(format!("hint_code: {hint_code}"));
            }
        }
        if let Some(hint_action) = extract_json_string_field(compact, "hint_action") {
            if seen.insert(format!("hint_action:{hint_action}")) {
                out.push(format!("hint_action: {hint_action}"));
            }
        }
        if compact.contains("preflight_trust_policy_invalid") {
            if seen.insert("mapped:trust_policy_invalid".to_string()) {
                out.push("trust policy is invalid for this plugin/cert identity".to_string());
                out.push("next: refresh registry policy and rerun preflight/test".to_string());
            }
            continue;
        }
        if compact.contains("Signature or trust chain verification failed") {
            if seen.insert("mapped:signature_or_trust_failed".to_string()) {
                out.push("signature/trust verification failed".to_string());
                out.push(
                    "next: run preflight (f) then test (t), check trusted identity".to_string(),
                );
            }
            continue;
        }
        if seen.insert(format!("line:{compact}")) {
            if compact.len() > 220 {
                out.push(format!("{}...", &compact[..220]));
            } else {
                out.push(compact.to_string());
            }
        }
    }
    if out.len() > 8 {
        out.truncate(8);
        out.push("... more lines omitted".to_string());
    }
    out
}

fn extract_json_string_field(line: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":\"");
    let start = line.find(&needle)?;
    let value_start = start + needle.len();
    let value_tail = &line[value_start..];
    let value_end = value_tail.find('"')?;
    Some(value_tail[..value_end].to_string())
}

pub(super) fn plugin_lines(
    state: &AppState,
    snapshot: &DashboardSnapshot,
    content_width: usize,
) -> Vec<Line<'static>> {
    let view = PluginListView::from_snapshot(snapshot);
    let mut lines = vec![
        Line::from("Plugin actions"),
        Line::from("  list(l) search(s) info(i) preflight(f) test(t) install(n)"),
        Line::from(format!(
            "  spec: {}{}",
            if state.plugin_spec.trim().is_empty() {
                "<empty>"
            } else {
                state.plugin_spec.trim()
            },
            if state.plugin_spec_editing {
                "  [editing]"
            } else {
                "  (press e to edit)"
            }
        )),
        Line::from(""),
        Line::from("Installed plugins snapshot"),
        Line::from(format!("Installed plugins: {}", view.total_plugins)),
        Line::from(""),
    ];
    if view.items.is_empty() {
        lines.push(Line::from("No plugin found in lockfile."));
        lines.push(Line::from("Run `preen plugin install <pack>@<version>`."));
        return lines;
    }

    for plugin in &view.items {
        lines.push(Line::from(format!(
            "- {}  v{}  [{}]  installed={}",
            plugin.pack_id,
            plugin.version,
            plugin.source,
            yes_no(plugin.installed)
        )));
        lines.push(Line::from(format!("  rev: {}", short_rev(&plugin.rev))));
        lines.push(Line::from(format!(
            "  identity: {}",
            plugin.trusted_identity
        )));
        lines.push(Line::from(""));
    }

    lines.push(Line::from("Command output"));
    if state.plugin_action_running {
        lines.push(Line::from("  running..."));
    } else if let Some(action) = state.plugin_last_action {
        lines.push(Line::from(format!("  last action: {}", action.label())));
    } else {
        lines.push(Line::from("  no command executed yet"));
    }
    if !state.plugin_last_output.is_empty() {
        for line in &state.plugin_last_output {
            for wrapped in wrap_with_prefix("  ", line, content_width) {
                lines.push(Line::from(wrapped));
            }
        }
    }
    if !state.plugin_last_diagnostics.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Structured diagnostics"));
        for line in &state.plugin_last_diagnostics {
            for wrapped in wrap_with_prefix("  ", line, content_width) {
                lines.push(Line::from(wrapped));
            }
        }
    }
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Error: {error}")));
    }
    lines
}

fn wrap_with_prefix(prefix: &str, text: &str, width: usize) -> Vec<String> {
    let usable = width.saturating_sub(prefix.chars().count()).max(8);
    let mut out = Vec::new();
    let chars = text.chars().collect::<Vec<_>>();
    if chars.is_empty() {
        out.push(prefix.to_string());
        return out;
    }
    let mut index = 0usize;
    while index < chars.len() {
        let end = (index + usable).min(chars.len());
        let chunk = chars[index..end].iter().collect::<String>();
        out.push(format!("{prefix}{chunk}"));
        index = end;
    }
    out
}

pub(super) fn check_lines(state: &AppState, snapshot: &DashboardSnapshot) -> Vec<Line<'static>> {
    let view = CheckListView::from_snapshot(snapshot);
    let mut lines = vec![
        Line::from(format!("Checks: {}", view.total_checks)),
        Line::from(""),
    ];
    for check in &view.items {
        lines.push(Line::from(format!(
            "- [{}] {}  ({})",
            if check.passed { "OK" } else { "NO" },
            check.label,
            check.severity_label
        )));
        lines.push(Line::from(format!("  {}", check.message)));
    }
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Error: {error}")));
    }
    lines
}

fn coming_soon_lines(state: &AppState) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("{} view is scaffolded.", state.active_view.title())),
        Line::from(""),
        Line::from("This menu is planned but not implemented yet."),
        Line::from("Architecture target:"),
        Line::from("- UI stays thin (render/input only)"),
        Line::from("- data and business logic come from preen-core/preen-os"),
        Line::from(""),
        Line::from(
            "Current ready menus: Dashboard, Smart Care, Cleanup, Protection, Performance, Applications, Plugins, Checks.",
        ),
    ];
    if let Some(error) = &state.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Error: {error}")));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::{
        applications_lines, build_info_popup_lines, build_smart_care_review_popup_lines,
        capability_lines, check_lines, plugin_lines, smart_care_lines,
    };
    use crate::i18n::LanguagePreference;
    use crate::model::{ActiveView, AppState, PluginActionKind};
    use preen_core::app_uninstall::{
        AppIdentity, AppManagementSource, AppPackageDetectionConfidence, AppPackageManager,
        AppPackageMetadata, AppSource, AppUpdateAvailability, InstalledApplication,
    };
    use preen_core::dashboard::{
        CheckSeverity, DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
        DashboardMetrics, DashboardSnapshot, PluginRow, RegistrySummary, StatusCheck,
    };
    use preen_core::smart_care::{SmartCareCapability, SmartCarePluginDescriptor};
    use std::path::PathBuf;

    fn base_snapshot() -> DashboardSnapshot {
        DashboardSnapshot {
            schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
            contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
            collected_at: std::time::SystemTime::now().into(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            state_dir: PathBuf::from("/tmp/preen"),
            health_score: 90,
            overall_passed: true,
            plugin_count: 1,
            installed_plugins_on_disk: 1,
            checks: vec![StatusCheck {
                id: "state_dir_exists".to_string(),
                label: "State directory exists".to_string(),
                severity: CheckSeverity::Critical,
                passed: true,
                message: "ok".to_string(),
            }],
            warnings: Vec::new(),
            suggested_actions: Vec::new(),
            registry: RegistrySummary::default(),
            metrics: DashboardMetrics::default(),
            plugins: vec![PluginRow {
                pack_id: "preen-rs.homebrew".to_string(),
                version: "1.0.7".to_string(),
                source: "registry".to_string(),
                rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
                installed: true,
                trusted_identity:
                    "https://github.com/Preen-rs/preen-rulepack-homebrew/.github/workflows/release-manual.yml@refs/heads/main"
                        .to_string(),
            }],
        }
    }

    #[test]
    fn plugin_lines_show_structured_diagnostics_when_present() {
        let snapshot = base_snapshot();
        let mut state = AppState {
            active_view: ActiveView::Plugins,
            plugin_spec: "preen-rs.homebrew@1.0.7".to_string(),
            ..AppState::default()
        };
        state.apply_plugin_command_result(
            crate::model::PluginActionKind::Test,
            true,
            vec![r#"{"schema_version":1,"kind":"plugin.test_spec","data":{"overall_passed":true,"duration_ms":42,"checks":[{"check":"signature_verified","passed":true}]}}"#.to_string()],
        );

        let lines = plugin_lines(&state, &snapshot, 120);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Structured diagnostics"));
        assert!(text.contains("overall_passed: true"));
        assert!(text.contains("Signature verified=true"));
    }

    #[test]
    fn applications_lines_use_german_language() {
        let snapshot = base_snapshot();
        let state = AppState {
            active_view: ActiveView::Applications,
            language_preference: LanguagePreference::German,
            ..AppState::default()
        };

        let lines = applications_lines(&state, &snapshot, 120);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("[ Anwendungen analysieren ]"));
        assert!(text.contains("Kein Anwendungen-Plugin installiert."));
        assert!(text.contains("Installationsablauf"));
    }

    #[test]
    fn applications_paths_info_prioritizes_app_details() {
        let state = AppState {
            active_view: ActiveView::Applications,
            applications_inventory: vec!["Affinity".to_string()],
            applications_inventory_metadata: vec![InstalledApplication {
                identity: AppIdentity::macos("Affinity"),
                path: "/Applications/Affinity.app".to_string(),
                version: Some("2.6.0".to_string()),
                source: AppSource::User,
                estimated_size: 1_073_741_824,
                last_used_at: None,
                management_source: AppManagementSource::Manual,
                update_availability: AppUpdateAvailability::Unsupported,
                package_metadata: Some(AppPackageMetadata {
                    manager: AppPackageManager::HomebrewCask,
                    package_id: "affinity-designer".to_string(),
                    installed_version: Some("2.6.0".to_string()),
                    latest_version: None,
                    update_command: Some("brew upgrade --cask affinity-designer".to_string()),
                    detection_confidence: AppPackageDetectionConfidence::Strong,
                }),
                protected: false,
            }],
            applications_info_target: Some("Affinity".to_string()),
            applications_show_paths_in_info: true,
            applications_info_paths: vec![
                "/Applications/Affinity.app".to_string(),
                "/Users/test/Library/Application Support/Affinity".to_string(),
            ],
            ..AppState::default()
        };

        let text = build_info_popup_lines(&state)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.starts_with("Application details"));
        assert!(!text.starts_with("Affinity\n"));
        assert!(text.contains("- Version: 2.6.0"));
        assert!(text.contains("- Estimated size: 1.0GB"));
        assert!(text.contains("- Last used: unknown"));
        assert!(text.contains("- Managed by: manual/local"));
        assert!(text.contains("- Update availability: not supported"));
        assert!(text.contains("- Package manager: Homebrew cask"));
        assert!(text.contains("- Package id: affinity-designer"));
        assert!(text.contains("- Package version: 2.6.0"));
        assert!(text.contains("- Update command: brew upgrade --cask affinity-designer"));
        assert!(text.contains("- Package match: strong"));
        assert!(text.contains("Related paths"));
        assert!(!text.contains("Info target"));
        assert!(!text.contains("Shortcuts"));
    }

    #[test]
    fn applications_action_details_use_scrollable_info_popup_content() {
        let state = AppState {
            active_view: ActiveView::Applications,
            applications_show_action_details: true,
            applications_last_action_lines: vec![
                "Affinity: no supported executable updater detected; executable now: Homebrew cask, Flatpak, Snap; Mac App Store and Sparkle detection are native"
                    .to_string(),
                "Anaconda Navigator: update available".to_string(),
            ],
            ..AppState::default()
        };

        let text = build_info_popup_lines(&state)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.starts_with("Application update result"));
        assert!(text.contains("Anaconda Navigator: update available"));
        assert!(text.contains("Supported update providers"));
        assert!(text.contains("Homebrew cask"));
    }

    #[test]
    fn check_lines_show_severity_and_message() {
        let mut snapshot = base_snapshot();
        snapshot.checks = vec![StatusCheck {
            id: "registry_readable".to_string(),
            label: "Registry index readable".to_string(),
            severity: CheckSeverity::Warning,
            passed: false,
            message: "registry missing".to_string(),
        }];
        let state = AppState::default();

        let lines = check_lines(&state, &snapshot);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Checks: 1"));
        assert!(text.contains("Registry index readable"));
        assert!(text.contains("(warning)"));
        assert!(text.contains("registry missing"));
    }

    #[test]
    fn smart_care_lines_show_capability_status() {
        let snapshot = base_snapshot();
        let mut state = AppState {
            active_view: ActiveView::SmartCare,
            ..AppState::default()
        };
        state.smart_care_descriptors = vec![
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.cleanup.base".to_string(),
                capability: SmartCareCapability::Cleanup,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.apps.base".to_string(),
                capability: SmartCareCapability::Applications,
                enabled: true,
                trusted_identity: None,
                version: Some("1.2.0".to_string()),
            },
        ];
        state.smart_care_source_summary =
            Some("state=1 | dev-fallback=1 [preen-rs.apps.base]".to_string());
        state
            .smart_care_dev_fallback_pack_ids
            .insert("preen-rs.apps.base".to_string());
        state.plugin_last_action = Some(PluginActionKind::Preflight);
        state.plugin_spec = "preen-rs.cleanup.base@1.0.0".to_string();
        state.plugin_last_diagnostics = vec![
            "overall_passed: true".to_string(),
            "check [critical] Signature verified=true".to_string(),
        ];

        let lines = smart_care_lines(&state, &snapshot, 120);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Smart Care"));
        assert!(text.contains("Cleanup [ON]"));
        assert!(text.contains("Applications [ON]"));
        assert!(text.contains("status: ready"));
        assert!(text.contains("[READY]"));
        assert!(text.contains("Ready: "));
        assert!(text.contains("source=state"));
        assert!(text.contains("source=dev-fallback"));
        assert!(text.contains("Blockers:"));
        assert!(text.contains("plugin preflight: ok"));
    }

    #[test]
    fn smart_care_lines_surface_skipped_pack_blockers_and_card_meta() {
        let snapshot = base_snapshot();
        let mut state = AppState {
            active_view: ActiveView::SmartCare,
            ..AppState::default()
        };
        state
            .smart_care_skipped_pack_ids
            .insert("preen-rs.cleanup.base".to_string());
        state.smart_care_error = Some("skipped plugin packs: preen-rs.cleanup.base".to_string());
        state.smart_care_source_summary = Some("state-only (packs=0) | skipped=1".to_string());

        let lines = smart_care_lines(&state, &snapshot, 120);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Blockers:"));
        assert!(text.contains("status: missing_plugin [MISSING] | skipped=1"));
        assert!(text.contains("source=none trusted=0 skipped=1 review_items=0"));
    }

    #[test]
    fn capability_lines_show_profile_and_trust_status() {
        let snapshot = base_snapshot();
        let mut state = AppState {
            active_view: ActiveView::Cleanup,
            ..AppState::default()
        };
        state.smart_care_descriptors = vec![SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        }];
        state.smart_care_source_summary = Some("state-only (packs=1)".to_string());
        state.plugin_last_action = Some(PluginActionKind::Install);
        state.plugin_spec = "preen-rs.cleanup.base@1.0.0".to_string();
        state.plugin_last_output = vec!["install completed".to_string()];

        let lines = capability_lines(&state, &snapshot, 120);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Cleanup capability"));
        assert!(text.contains("State: ON | Status: ready [READY]"));
        assert!(text.contains("preen-rs.cleanup.base@1.0.0"));
        assert!(text.contains("Plugins: matched=1 trusted=1 skipped=0"));
        assert!(text.contains("Plugin command: plugin install: unknown (details: i)"));
    }

    #[test]
    fn capability_lines_show_skipped_pack_diagnostics_for_selected_capability() {
        let snapshot = base_snapshot();
        let mut state = AppState {
            active_view: ActiveView::Cleanup,
            ..AppState::default()
        };
        state
            .smart_care_skipped_pack_ids
            .insert("preen-rs.cleanup.base".to_string());
        state.smart_care_source_summary = Some("state-only (packs=0) | skipped=1".to_string());

        let lines = capability_lines(&state, &snapshot, 120);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Plugins: matched=0 trusted=0 skipped=1"));
        assert!(text.contains("Blockers"));
        assert!(text.contains("resolver skipped 1 pack(s) for this capability"));
    }

    #[test]
    fn smart_care_review_popup_shows_compact_workflow_and_capability_summary() {
        let snapshot = base_snapshot();
        let mut state = AppState {
            active_view: ActiveView::SmartCare,
            snapshot: Some(snapshot),
            ..AppState::default()
        };
        state.smart_care_descriptors = vec![
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.cleanup.base".to_string(),
                capability: SmartCareCapability::Cleanup,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.performance.base".to_string(),
                capability: SmartCareCapability::Performance,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.applications.base".to_string(),
                capability: SmartCareCapability::Applications,
                enabled: false,
                trusted_identity: None,
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.protection.base".to_string(),
                capability: SmartCareCapability::Protection,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
        ];
        state.smart_care_source_summary = Some("state-only (packs=4)".to_string());
        state.smart_care_run_local_analyze();
        state.smart_care_open_review();
        state.smart_care_apply_armed = true;
        state.smart_care_last_run_report = vec![
            "run: blocked".to_string(),
            "reason: review is required before run".to_string(),
            "hint: open review with 'v' and confirm selected entries".to_string(),
            "capability=cleanup entries=1".to_string(),
            "capability=performance entries=2".to_string(),
            "capability=applications entries=0".to_string(),
            "capability=protection entries=1".to_string(),
        ];

        let lines = build_smart_care_review_popup_lines(&state);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Flow: analyze=ready review=open arm=armed"));
        assert!(text.contains("Run gate: blocked"));
        assert!(text.contains("Selected items: 3/3"));
        assert!(text.contains("Controls"));
        assert!(text.contains("Capability cards"));
        assert!(text.contains("- [1] Cleanup [ON] status=ready plugins=1 trusted=1 selected=1/1"));
        assert!(text.contains(
            "- [3] Applications [ON] status=missing_plugin plugins=0 trusted=0 selected=0/0"
        ));
        assert!(text.contains("Review entries"));
        assert!(text.contains("- [2] Performance"));
        assert!(text.contains("Execution report (latest)"));
    }

    #[test]
    fn smart_care_review_popup_shows_selected_entry_counts_before_first_run() {
        let snapshot = base_snapshot();
        let mut state = AppState {
            active_view: ActiveView::SmartCare,
            snapshot: Some(snapshot),
            ..AppState::default()
        };
        state.smart_care_descriptors = vec![
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.cleanup.base".to_string(),
                capability: SmartCareCapability::Cleanup,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
            SmartCarePluginDescriptor {
                pack_id: "preen-rs.performance.base".to_string(),
                capability: SmartCareCapability::Performance,
                enabled: true,
                trusted_identity: Some("https://github.com/Preen-rs".to_string()),
                version: Some("1.0.0".to_string()),
            },
        ];
        state.smart_care_run_local_analyze();
        state.smart_care_open_review();

        let lines = build_smart_care_review_popup_lines(&state);
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Run gate: blocked"));
        assert!(text.contains("Selected items: 2/2"));
        assert!(text.contains("- [1] Cleanup [ON] status=ready plugins=1 trusted=1 selected=1/1"));
        assert!(
            text.contains("- [2] Performance [ON] status=ready plugins=1 trusted=1 selected=1/1")
        );
    }
}
