#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    German,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguagePreference {
    System,
    English,
    German,
}

impl LanguagePreference {
    pub fn next(self) -> Self {
        match self {
            Self::System => Self::English,
            Self::English => Self::German,
            Self::German => Self::System,
        }
    }

    pub fn as_config_value(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::English => "en-US",
            Self::German => "de-DE",
        }
    }

    pub fn from_config_value(value: &str) -> Self {
        match value.trim() {
            "en" | "en-US" => Self::English,
            "de" | "de-DE" => Self::German,
            _ => Self::System,
        }
    }

    pub fn label(self, system_language: Language) -> &'static str {
        match self {
            Self::System => match system_language {
                Language::English => "System (English)",
                Language::German => "System (Deutsch)",
            },
            Self::English => "English",
            Self::German => "Deutsch",
        }
    }
}

pub fn detect_system_language() -> Language {
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(value) = std::env::var(key)
            && value.to_ascii_lowercase().starts_with("de")
        {
            return Language::German;
        }
    }
    Language::English
}

pub fn locale(language: Language) -> &'static str {
    match language {
        Language::English => "en-US",
        Language::German => "de-DE",
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TextKey {
    Menu,
    Tools,
    SettingsSection,
    Dashboard,
    SmartCare,
    Cleanup,
    Protection,
    Performance,
    Applications,
    Plugins,
    Checks,
    MyTools,
    MyActivity,
    Settings,
    Soon,
    LoadingDashboardTitle,
    LoadingDashboardDetail,
    RunningPluginDetail,
    RunningSmartCareTitlePrefix,
    RunningSmartCareDetail,
    AnalyzingApplicationsTitle,
    AnalyzingApplicationsDetail,
    LoadingApplicationPathsTitle,
    LoadingApplicationPathsDetail,
    UninstallingApplicationsTitle,
    UninstallingApplicationsDetail,
    UpdatingApplicationsTitle,
    UpdatingApplicationsDetail,
    UndoingApplicationsTitle,
    UndoingApplicationsDetail,
    CollectingSnapshot,
    SnapshotWorkerRunning,
    SettingsTitle,
    SettingsSubtitle,
    LanguageLabel,
    LanguageHelp,
    EffectiveLanguage,
    SensitiveFoldersTitle,
    SensitiveFoldersEmpty,
    SensitiveFoldersHint,
    SettingsFooter,
}

pub fn tr(language: Language, key: TextKey) -> &'static str {
    match language {
        Language::English => match key {
            TextKey::Menu => "Menu",
            TextKey::Tools => "Tools",
            TextKey::SettingsSection => "Settings",
            TextKey::Dashboard => "Dashboard",
            TextKey::SmartCare => "Smart Care",
            TextKey::Cleanup => "Cleanup",
            TextKey::Protection => "Protection",
            TextKey::Performance => "Performance",
            TextKey::Applications => "Applications",
            TextKey::Plugins => "Plugins",
            TextKey::Checks => "Checks",
            TextKey::MyTools => "My Tools",
            TextKey::MyActivity => "My Activity",
            TextKey::Settings => "Settings",
            TextKey::Soon => "soon",
            TextKey::LoadingDashboardTitle => "Loading dashboard",
            TextKey::LoadingDashboardDetail => {
                "Collecting system health, plugins, checks, and runtime metrics"
            }
            TextKey::RunningPluginDetail => "Executing plugin command and collecting diagnostics",
            TextKey::RunningSmartCareTitlePrefix => "Running Smart Care",
            TextKey::RunningSmartCareDetail => {
                "Preparing recommendations and applying selected workflow checks"
            }
            TextKey::AnalyzingApplicationsTitle => "Analyzing applications",
            TextKey::AnalyzingApplicationsDetail => {
                "Scanning installed apps and reading uninstall metadata"
            }
            TextKey::LoadingApplicationPathsTitle => "Loading application paths",
            TextKey::LoadingApplicationPathsDetail => {
                "Finding related files before opening the paths view"
            }
            TextKey::UninstallingApplicationsTitle => "Uninstalling applications",
            TextKey::UninstallingApplicationsDetail => {
                "Moving selected app files to Trash and writing undo metadata"
            }
            TextKey::UpdatingApplicationsTitle => "Updating applications",
            TextKey::UpdatingApplicationsDetail => {
                "Running supported package manager updates for selected apps"
            }
            TextKey::UndoingApplicationsTitle => "Restoring applications",
            TextKey::UndoingApplicationsDetail => {
                "Restoring files from the last application uninstall journal"
            }
            TextKey::CollectingSnapshot => "Collecting realtime snapshot...",
            TextKey::SnapshotWorkerRunning => "State worker is running in background.",
            TextKey::SettingsTitle => "Settings",
            TextKey::SettingsSubtitle => "Configure the TUI experience.",
            TextKey::LanguageLabel => "Language",
            TextKey::LanguageHelp => "Press l to cycle System, English, and Deutsch.",
            TextKey::EffectiveLanguage => "Effective language",
            TextKey::SensitiveFoldersTitle => "Sensitive folders",
            TextKey::SensitiveFoldersEmpty => "No custom sensitive folders configured yet.",
            TextKey::SensitiveFoldersHint => {
                "Reserved for cleanup: Preen will skip these paths when cleanup ships."
            }
            TextKey::SettingsFooter => "Settings: l language | Tab menu | q quit | ?: keys",
        },
        Language::German => match key {
            TextKey::Menu => "Menü",
            TextKey::Tools => "Werkzeuge",
            TextKey::SettingsSection => "Einstellungen",
            TextKey::Dashboard => "Dashboard",
            TextKey::SmartCare => "Smart Care",
            TextKey::Cleanup => "Bereinigung",
            TextKey::Protection => "Schutz",
            TextKey::Performance => "Leistung",
            TextKey::Applications => "Anwendungen",
            TextKey::Plugins => "Plugins",
            TextKey::Checks => "Prüfungen",
            TextKey::MyTools => "Meine Werkzeuge",
            TextKey::MyActivity => "Meine Aktivität",
            TextKey::Settings => "Einstellungen",
            TextKey::Soon => "bald",
            TextKey::LoadingDashboardTitle => "Dashboard wird geladen",
            TextKey::LoadingDashboardDetail => {
                "Systemzustand, Plugins, Prüfungen und Laufzeitmetriken werden gesammelt"
            }
            TextKey::RunningPluginDetail => {
                "Plugin-Befehl wird ausgeführt und Diagnosen werden gesammelt"
            }
            TextKey::RunningSmartCareTitlePrefix => "Smart Care läuft",
            TextKey::RunningSmartCareDetail => {
                "Empfehlungen und ausgewählte Workflow-Prüfungen werden vorbereitet"
            }
            TextKey::AnalyzingApplicationsTitle => "Anwendungen werden analysiert",
            TextKey::AnalyzingApplicationsDetail => {
                "Installierte Apps und Deinstallations-Metadaten werden gelesen"
            }
            TextKey::LoadingApplicationPathsTitle => "Anwendungspfade werden geladen",
            TextKey::LoadingApplicationPathsDetail => {
                "Zugehörige Dateien werden gesucht, bevor die Pfadansicht geöffnet wird"
            }
            TextKey::UninstallingApplicationsTitle => "Anwendungen werden deinstalliert",
            TextKey::UninstallingApplicationsDetail => {
                "Ausgewählte App-Dateien werden in den Papierkorb bewegt und Undo-Metadaten werden geschrieben"
            }
            TextKey::UpdatingApplicationsTitle => "Anwendungen werden aktualisiert",
            TextKey::UpdatingApplicationsDetail => {
                "Unterstützte Paketmanager-Updates für ausgewählte Apps werden ausgeführt"
            }
            TextKey::UndoingApplicationsTitle => "Anwendungen werden wiederhergestellt",
            TextKey::UndoingApplicationsDetail => {
                "Dateien aus dem letzten Deinstallations-Journal werden wiederhergestellt"
            }
            TextKey::CollectingSnapshot => "Echtzeit-Snapshot wird gesammelt...",
            TextKey::SnapshotWorkerRunning => "Status-Worker läuft im Hintergrund.",
            TextKey::SettingsTitle => "Einstellungen",
            TextKey::SettingsSubtitle => "TUI-Erlebnis konfigurieren.",
            TextKey::LanguageLabel => "Sprache",
            TextKey::LanguageHelp => "Drücke l für System, English und Deutsch.",
            TextKey::EffectiveLanguage => "Aktive Sprache",
            TextKey::SensitiveFoldersTitle => "Geschützte Ordner",
            TextKey::SensitiveFoldersEmpty => "Noch keine eigenen geschützten Ordner konfiguriert.",
            TextKey::SensitiveFoldersHint => {
                "Reserviert für Cleanup: Preen überspringt diese Pfade, sobald Cleanup aktiv ist."
            }
            TextKey::SettingsFooter => {
                "Einstellungen: l Sprache | Tab Menü | q Beenden | ?: Tasten"
            }
        },
    }
}
