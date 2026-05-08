use async_trait::async_trait;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::time::{self, Duration};
use uuid::Uuid;

use crate::error::CoreError;
rust_i18n::i18n!("locales", fallback = "en-US");

pub mod action_runtime;
pub mod app_uninstall;
pub mod check_list_view;
pub mod dashboard;
pub mod dashboard_facade;
pub mod dashboard_policy;
pub mod dashboard_provider;
pub mod dashboard_service;
pub mod dashboard_view;
pub mod error;
pub mod metrics;
pub mod plugin;
pub mod plugin_list_view;
pub mod plugin_loader;
pub mod plugin_lock;
pub mod plugin_registry;
pub mod smart_care;
pub mod store;

pub const UNDO_CODE_AMBIGUOUS: &str = "undo_ambiguous";
pub const UNDO_CODE_NOT_FOUND: &str = "undo_not_found";
pub const UNDO_CODE_RESTORE_FAILED: &str = "undo_restore_failed";
pub const UNDO_CODE_INFO_MISSING: &str = "undo_info_missing";
pub const UNDO_CODE_GENERIC: &str = "undo_failed";
pub const SYSTEM_CODE_COMMAND_NOT_IMPLEMENTED: &str = "command_not_implemented";

fn normalize_supported_locale(language: &str) -> &'static str {
    let lower = language.to_lowercase();
    if lower.starts_with("de") {
        "de-DE"
    } else {
        "en-US"
    }
}

pub fn classify_undo_error_code(message: &str) -> &'static str {
    if message.contains("ambiguous trash candidates") {
        return UNDO_CODE_AMBIGUOUS;
    }
    if message.contains("trash item not found") {
        return UNDO_CODE_NOT_FOUND;
    }
    if message.contains("trash restore failed") || message.contains("target path exists") {
        return UNDO_CODE_RESTORE_FAILED;
    }
    if message.contains("no undo_info") {
        return UNDO_CODE_INFO_MISSING;
    }
    UNDO_CODE_GENERIC
}

pub fn undo_failed_user_message_with_language(code: &str, language: &str) -> String {
    let locale = normalize_supported_locale(language);
    match code {
        UNDO_CODE_AMBIGUOUS => rust_i18n::t!("undo.ambiguous", locale = locale).to_string(),
        UNDO_CODE_NOT_FOUND => rust_i18n::t!("undo.not_found", locale = locale).to_string(),
        UNDO_CODE_RESTORE_FAILED => {
            rust_i18n::t!("undo.restore_failed", locale = locale).to_string()
        }
        UNDO_CODE_INFO_MISSING => rust_i18n::t!("undo.info_missing", locale = locale).to_string(),
        _ => rust_i18n::t!("undo.generic", locale = locale).to_string(),
    }
}

pub fn undo_failed_user_message(code: &str) -> String {
    undo_failed_user_message_with_language(code, "en-US")
}

pub fn system_error_kind_label(kind: &str, language: &str) -> String {
    let locale = normalize_supported_locale(language);
    match kind {
        "validation" => rust_i18n::t!("system.errors.kind_labels.validation", locale = locale),
        "not_found" => rust_i18n::t!("system.errors.kind_labels.not_found", locale = locale),
        "trust" => rust_i18n::t!("system.errors.kind_labels.trust", locale = locale),
        "verification" => rust_i18n::t!("system.errors.kind_labels.verification", locale = locale),
        "io" => rust_i18n::t!("system.errors.kind_labels.io", locale = locale),
        "network" => rust_i18n::t!("system.errors.kind_labels.network", locale = locale),
        "unsupported" => rust_i18n::t!("system.errors.kind_labels.unsupported", locale = locale),
        "internal" => rust_i18n::t!("system.errors.kind_labels.internal", locale = locale),
        _ => rust_i18n::t!("system.errors.kind_labels.internal", locale = locale),
    }
    .to_string()
}

fn system_command_names(prefix: &str) -> Option<(&'static str, &'static str)> {
    match prefix {
        "clean" => Some(("clean", "Clean")),
        "purge" => Some(("purge", "Purge")),
        "installer" => Some(("installer", "Installer")),
        "uninstall" => Some(("uninstall", "Uninstall")),
        "optimize" => Some(("optimize", "Optimize")),
        "analyze" => Some(("analyze", "Analyze")),
        "status" => Some(("status", "Status")),
        "check" => Some(("check", "Check")),
        "touchid" => Some(("touchid", "Touch ID")),
        "completion" => Some(("completion", "Completion")),
        "update" => Some(("update", "Update")),
        "remove" => Some(("remove", "Remove")),
        _ => None,
    }
}

fn system_prefixed_detail_message(code: &str, locale: &str) -> Option<String> {
    let (prefix, suffix) = code.split_once('_')?;
    let (command_en, command_de) = system_command_names(prefix)?;
    let command = if locale == "de-DE" {
        command_de
    } else {
        command_en
    };

    let rendered = match suffix {
        "confirmation_required" => {
            if locale == "de-DE" {
                format!("{command}-Anwenden benoetigt --confirm.")
            } else {
                format!("{command} apply mode requires --confirm.")
            }
        }
        "no_roots" => {
            if locale == "de-DE" {
                format!("{command} hat keine konfigurierten Scan-Wurzeln.")
            } else {
                format!("{command} has no configured scan roots.")
            }
        }
        "target_required" => {
            if locale == "de-DE" {
                format!("{command} benoetigt ein Target-Argument.")
            } else {
                format!("{command} requires a target argument.")
            }
        }
        "rule_not_in_manifest" => {
            if locale == "de-DE" {
                format!("{command}-Regel fehlt im Manifest.")
            } else {
                format!("{command} rule is not present in manifest.")
            }
        }
        "relative_path" => {
            if locale == "de-DE" {
                format!("Ausgewaehlter {command} Pfad muss absolut sein.")
            } else {
                format!("selected {command} path must be absolute.")
            }
        }
        "path_scope_violation" => {
            if locale == "de-DE" {
                format!("Ausgewaehlter {command} Pfad liegt ausserhalb der konfigurierten Wurzeln.")
            } else {
                format!("selected {command} path is outside configured roots.")
            }
        }
        "symlink_not_allowed" => {
            if locale == "de-DE" {
                format!("Ausgewaehlter {command} Pfad darf kein Symlink sein.")
            } else {
                format!("selected {command} path cannot be a symlink.")
            }
        }
        "blocked_path" => {
            if locale == "de-DE" {
                format!("Ausgewaehlter {command} Pfad ist durch Sicherheitsrichtlinie blockiert.")
            } else {
                format!("selected {command} path is blocked by safety policy.")
            }
        }
        "unsupported_action" => {
            if locale == "de-DE" {
                format!("{command}-Aktion wird vom Executor nicht unterstuetzt.")
            } else {
                format!("{command} action is unsupported by executor.")
            }
        }
        "execution_failed" => {
            if locale == "de-DE" {
                format!("{command}-Ausfuehrung ist fehlgeschlagen.")
            } else {
                format!("{command} execution failed.")
            }
        }
        "command_denied" => {
            if locale == "de-DE" {
                format!("{command}-Befehl wurde durch Allowlist abgelehnt.")
            } else {
                format!("{command} command was denied by allowlist.")
            }
        }
        "command_timeout" => {
            if locale == "de-DE" {
                format!("{command}-Befehl hat das Zeitlimit ueberschritten.")
            } else {
                format!("{command} command timed out.")
            }
        }
        "command_non_zero" => {
            if locale == "de-DE" {
                format!("{command}-Befehl endete mit einem Fehlerstatus.")
            } else {
                format!("{command} command exited with a non-zero status.")
            }
        }
        "no_tasks" => {
            if locale == "de-DE" {
                format!("{command} hat auf diesem Betriebssystem keine unterstuetzten Aufgaben.")
            } else {
                format!("{command} has no supported tasks on this operating system.")
            }
        }
        "dry_run_unsupported_os" => {
            if locale == "de-DE" {
                format!("{command} wird auf diesem Betriebssystem nicht unterstuetzt.")
            } else {
                format!("{command} is not supported on this operating system.")
            }
        }
        "root_not_found" => {
            if locale == "de-DE" {
                format!("{command}-Wurzel wurde nicht gefunden.")
            } else {
                format!("{command} root not found.")
            }
        }
        "root_not_directory" => {
            if locale == "de-DE" {
                format!("{command}-Wurzel ist kein Verzeichnis.")
            } else {
                format!("{command} root is not a directory.")
            }
        }
        "target_not_readable" => {
            if locale == "de-DE" {
                format!("{command}-Ziel ist nicht lesbar.")
            } else {
                format!("{command} target is not readable.")
            }
        }
        "cwd_unavailable" => {
            if locale == "de-DE" {
                format!("Aktuelles Arbeitsverzeichnis fuer {command} ist nicht verfuegbar.")
            } else {
                format!("current working directory is unavailable for {command}.")
            }
        }
        "home_missing" => {
            if locale == "de-DE" {
                format!("Home-Verzeichnis wird fuer {command} benoetigt.")
            } else {
                format!("home directory is required for {command}.")
            }
        }
        "state_dir_unavailable" => {
            if locale == "de-DE" {
                format!("State-Verzeichnis fuer {command} ist nicht verfuegbar.")
            } else {
                format!("state directory is unavailable for {command}.")
            }
        }
        "path_resolve_failed" => {
            if locale == "de-DE" {
                format!("{command}-Pfadauflosung ist fehlgeschlagen.")
            } else {
                format!("{command} path resolution failed.")
            }
        }
        "shell_unknown" => {
            if locale == "de-DE" {
                format!("Shell fuer {command} konnte nicht erkannt werden.")
            } else {
                format!("shell for {command} could not be detected.")
            }
        }
        "nightly_unsupported_source" => {
            if locale == "de-DE" {
                format!(
                    "{command} Nightly-Update wird nur fuer Script-Installationen unterstuetzt."
                )
            } else {
                format!("{command} nightly update is supported only for script installs.")
            }
        }
        "read_failed" => {
            if locale == "de-DE" {
                format!("{command}-Konfiguration konnte nicht gelesen werden.")
            } else {
                format!("{command} configuration read failed.")
            }
        }
        "write_failed" => {
            if locale == "de-DE" {
                format!("{command}-Konfiguration konnte nicht geschrieben werden.")
            } else {
                format!("{command} configuration write failed.")
            }
        }
        "executable_unknown" => {
            if locale == "de-DE" {
                format!("Ausfuehrbare Datei fuer {command} konnte nicht ermittelt werden.")
            } else {
                format!("failed to resolve executable path for {command}.")
            }
        }
        _ => return None,
    };

    Some(rendered)
}

pub fn system_localized_error_message(
    detail_code: Option<&str>,
    message: &str,
    language: &str,
) -> String {
    let locale = normalize_supported_locale(language);
    if let Some(code) = detail_code {
        if code == SYSTEM_CODE_COMMAND_NOT_IMPLEMENTED {
            let suffix = " command is not implemented yet";
            if let Some(command) = message.strip_suffix(suffix) {
                if locale == "de-DE" {
                    return format!("{command} Befehl ist noch nicht implementiert.");
                }
                return format!("{command}{suffix}");
            }
        }
        let key = format!("system.errors.detail.{code}");
        let localized = rust_i18n::t!(&key, locale = locale).to_string();
        if localized != key {
            return localized;
        }
        if let Some(fallback) = system_prefixed_detail_message(code, locale) {
            return fallback;
        }
    }
    message.to_string()
}

// --- 1. Domain Models ---

// New: Configuration Structures
pub mod config {
    /// Global configuration for the Preen application.
    #[derive(Debug, Clone, PartialEq)]
    pub struct AppConfig {
        /// List of paths or patterns to ignore during scanning.
        pub ignore_list: Vec<String>,
        /// Whether to follow symlinks during scans.
        pub follow_symlinks: bool,
        /// Maximum directory depth for scans. None means unlimited.
        pub max_scan_depth: Option<usize>,
        /// Explicit allowlist for scanning paths.
        pub allowlist: Vec<String>,
        /// Maximum age (in days) for files to be considered cleanable (e.g., for downloads).
        pub max_file_age_days: u32,
        /// Whether to scan system-critical directories (e.g., /usr, /var).
        pub scan_system_dirs: bool,
        /// Language for UI messages.
        pub language: String,
    }

    impl Default for AppConfig {
        fn default() -> Self {
            AppConfig {
                ignore_list: vec![
                    "~/.config/preen/ignore".to_string(),
                    "~/Documents".to_string(),
                ],
                follow_symlinks: false,
                max_scan_depth: None,
                allowlist: vec![],
                max_file_age_days: 30,
                scan_system_dirs: false,
                language: "en-US".to_string(),
            }
        }
    }
}

use config::AppConfig;

// New: Rule Engine Structures
pub mod rules {
    use super::*;

    /// Defines a single rule for identifying cleanable items.
    #[derive(Debug, Clone, PartialEq)]
    pub struct ScanRule {
        pub id: String,
        pub name: String,
        pub category: ItemCategory,
        /// The path pattern to search (e.g., "~/.cache/telegram").
        pub path_pattern: String,
        /// The strategy to use for finding files within the path.
        pub strategy: ScanStrategy,
        /// A description of what this rule cleans.
        pub description: String,
    }

    /// Defines the strategy for scanning a path.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum ScanStrategy {
        /// Scan all files and folders recursively.
        Recursive,
        /// Scan only the immediate contents of the directory.
        Shallow,
        /// Look for files matching a specific regex pattern.
        Regex(String),
        /// Look for files older than a certain duration (e.g., 30 days).
        OlderThanDays(u32),
    }

    /// A collection of rules to be executed by the Core.
    #[derive(Debug, Clone, PartialEq)]
    pub struct RuleEngine {
        rules: Vec<ScanRule>,
    }

    impl RuleEngine {
        pub fn new(rules: Vec<ScanRule>) -> Self {
            RuleEngine { rules }
        }

        /// Returns all rules that should be executed.
        pub fn get_active_rules(&self) -> &[ScanRule] {
            &self.rules
        }
    }
}

/// Represents a single item that can be cleaned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanableItem {
    /// The rule that identified this item.
    pub rule_id: String,
    /// Unique identifier for the item (e.g., a hash or a combination of category and path).
    pub id: String,
    /// The category of the item (e.g., "Cache", "Logs", "Broken Symlinks").
    pub category: ItemCategory,
    /// The path to the file or directory.
    pub path: PathBuf,
    /// The size of the item in bytes.
    pub size: u64,
    /// A brief description of the item.
    pub description: String,
    /// Whether this item can be undone (e.g., moved to trash).
    pub can_undo: bool,
    /// Information needed to undo the clean operation (e.g., original path, trash path).
    pub undo_info: Option<String>,
}

/// Defines the type of junk data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemCategory {
    Cache,
    Logs,
    TemporaryFiles,
    BrokenSymlinks,
    OldDownloads,
    Other(String),
}

/// Represents the result of a scan operation.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    /// The list of rules that were executed during the scan.
    pub executed_rules: Vec<rules::ScanRule>,
    /// Total size of all cleanable items found.
    pub total_size: u64,
    /// List of all cleanable items found.
    pub items: Vec<CleanableItem>,
}

// New: Statistics and History Structures
#[derive(Debug, Clone, PartialEq)]
pub struct CleanHistoryEntry {
    pub id: String,
    pub timestamp: DateTime<Local>,
    pub cleaned_items: Vec<CleanableItem>,
    pub freed_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Statistics {
    pub total_scans: u64,
    pub total_cleaned_items: u64,
    pub total_freed_bytes: u64,
    pub last_clean_date: Option<DateTime<Local>>,
}

// New: Scheduler Structures
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduledTask {
    pub id: String,
    pub name: String,
    pub interval: Duration,
    pub rules: Vec<rules::ScanRule>,
    pub last_run: Option<DateTime<Local>>,
    pub next_run: Option<DateTime<Local>>,
}

// --- 2. Application Communication (Commands & Events) ---

/// Commands sent from the UI (TUI/GUI) to the Core.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Starts the system scan for junk files.
    StartScan(Vec<rules::ScanRule>),
    /// Updates the application configuration.
    UpdateConfig(AppConfig),
    /// Starts the cleaning process for selected items.
    CleanSelected(Vec<String>), // Vector of item IDs to clean
    /// Undoes a previous cleaning operation for selected items.
    UndoClean(Vec<String>),
    /// Stops any ongoing operation (scan or clean).
    StopOperation,
    /// Requests the core to shut down gracefully.
    Quit,
    /// Requests the cleaning history.
    RequestHistory,
    /// Requests the current statistics.
    RequestStatistics,
    /// Schedules a scan to run at a specific interval.
    ScheduleScan(String, Duration, Vec<rules::ScanRule>),
    /// Cancels a scheduled scan by its ID.
    CancelScheduledScan(String),
    /// Requests a list of currently scheduled tasks.
    RequestScheduledTasks,
}

/// Events sent from the Core back to the UI (TUI/GUI).
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Indicates the progress of an ongoing operation (0.0 to 1.0).
    Progress(f32, String),
    /// Indicates the progress of an ongoing operation using a message key.
    ProgressKey(f32, String),
    /// Reports a list of found items during or after a scan.
    ScanCompleted(ScanResult),
    /// Reports the result of a cleaning operation.
    CleanCompleted(u64), // Total bytes freed
    /// Reports an error that occurred in the core.
    Error(String),
    /// Reports a structured undo failure that UI can map to friendly messages.
    UndoFailed {
        code: String,
        user_message: String,
        message: String,
    },
    /// Indicates the core has shut down.
    Shutdown,
    /// Reports the cleaning history.
    History(Vec<CleanHistoryEntry>),
    /// Reports the current statistics.
    Statistics(Statistics),
    /// Reports a list of currently scheduled tasks.
    ScheduledTasks(Vec<ScheduledTask>),
}

// --- 3. Ports (Interfaces for Hexagonal Architecture) ---

/// Defines the interface for interacting with the file system and OS-specific locations.
/// This is the "Port" that the Core uses to talk to the outside world.
#[async_trait]
pub trait FileSystemPort: Send + Sync {
    /// Scans the system for cleanable items based on the provided rules and configuration.
    /// Returns a list of found items or an error.
    async fn scan_cleanable_items(
        &self,
        rules: &[rules::ScanRule],
        config: &AppConfig,
    ) -> Result<ScanResult, CoreError>;

    /// Prepares items for cleaning, potentially moving them to a temporary location or trash.
    /// Returns a list of items with updated undo_info or an error.
    async fn prepare_clean(&self, items: &[CleanableItem])
    -> Result<Vec<CleanableItem>, CoreError>;

    /// Deletes the files/directories associated with the given item IDs.
    /// Returns the total size of freed space or an error.
    async fn clean_items(&self, item_ids: &[String]) -> Result<u64, CoreError>;

    /// Undoes the last cleaning operation for specific items.
    async fn undo_clean(&self, items: &[CleanableItem]) -> Result<(), CoreError>;
}

// --- 4. Core Logic (Application Service) ---

/// A handle to the CoreService that the UI can use to send Commands.
pub struct CoreHandle {
    command_sender: Sender<Command>,
}

impl CoreHandle {
    pub fn send_command(&self, command: Command) {
        let _ = self.command_sender.send(command);
    }
}

/// Internal commands for the scheduler.
enum SchedulerCommand {
    Schedule(ScheduledTask),
    Cancel(String),
}

/// The scheduler runs in its own Tokio task and manages scheduled scans.
pub struct Scheduler {
    command_receiver: tokio_mpsc::Receiver<SchedulerCommand>,
    event_sender: Sender<Event>,
    core_command_sender: Sender<Command>, // To send StartScan commands back to CoreService
    tasks: HashMap<String, ScheduledTask>,
}

impl Scheduler {
    pub(crate) fn new(
        command_receiver: tokio_mpsc::Receiver<SchedulerCommand>,
        event_sender: Sender<Event>,
        core_command_sender: Sender<Command>,
    ) -> Self {
        Scheduler {
            command_receiver,
            event_sender,
            core_command_sender,
            tasks: HashMap::new(),
        }
    }

    pub async fn run(&mut self) {
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                cmd = self.command_receiver.recv() => {
                    match cmd {
                        Some(SchedulerCommand::Schedule(task)) => {
                            self.tasks.insert(task.id.clone(), task.clone());
                            self.send_event(Event::ProgressKey(0.0, "schedule.task_added".to_string()));
                        },
                        Some(SchedulerCommand::Cancel(id)) => {
                            self.tasks.remove(&id);
                            self.send_event(Event::ProgressKey(0.0, "schedule.task_cancelled".to_string()));
                        },
                        None => break, // Sender dropped
                    }
                }
                _ = interval.tick() => {
                    self.check_and_run_tasks().await;
                }
            }
        }
    }

    async fn check_and_run_tasks(&mut self) {
        let now = Local::now();
        let mut tasks_to_run = Vec::new();

        for (id, task) in self.tasks.iter_mut() {
            if let Some(next_run) = task.next_run {
                // Convert Instant to DateTime<Local> for comparison
                // This is a simplification; a real scheduler would use tokio::time::sleep_until
                // and more robust time management.
                if now >= next_run {
                    tasks_to_run.push((id.clone(), task.rules.clone()));
                    task.last_run = Some(now);
                    task.next_run = Some(now + task.interval);
                }
            }
        }

        for (_id, rules) in tasks_to_run {
            // Send a command back to the CoreService to start the scan
            let _ = self.core_command_sender.send(Command::StartScan(rules));
            self.send_event(Event::ProgressKey(0.0, "schedule.triggered".to_string()));
        }
    }

    fn send_event(&self, event: Event) {
        let _ = self.event_sender.send(event);
    }
}

/// The main application service that orchestrates the business logic.
/// It runs in its own thread and communicates via channels.
pub struct CoreService<T: FileSystemPort> {
    fs_port: T,
    config: AppConfig,
    state: Option<ScanResult>, // Current scan result
    command_receiver: Receiver<Command>,
    event_sender: Sender<Event>,
    history: Vec<CleanHistoryEntry>,
    statistics: Statistics,
    scheduled_tasks: HashMap<String, ScheduledTask>,
    scheduler_command_sender: tokio_mpsc::Sender<SchedulerCommand>,
}

impl<T: FileSystemPort + Send + Sync + 'static> CoreService<T> {
    /// Creates the CoreService and its communication channels.
    /// Returns a tuple of (CoreHandle, EventReceiver).
    pub fn start(fs_port: T) -> (CoreHandle, Receiver<Event>) {
        let (command_sender, command_receiver) = std::sync::mpsc::channel();
        let (event_sender, event_receiver) = std::sync::mpsc::channel();
        let (scheduler_command_sender, scheduler_command_receiver) = tokio_mpsc::channel(100);

        let mut core = CoreService {
            fs_port,
            config: AppConfig::default(),
            state: None,
            command_receiver,
            event_sender: event_sender.clone(), // Clone for scheduler
            history: Vec::new(),
            statistics: Statistics::default(),
            scheduled_tasks: HashMap::new(),
            scheduler_command_sender: scheduler_command_sender.clone(),
        };

        // Clone the command_sender for the scheduler to send commands back to the core
        let core_command_sender_for_scheduler = command_sender.clone();

        // Start the core loop in a new thread
        std::thread::spawn(move || {
            // Create a new Tokio runtime for the scheduler and async operations
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build();

            let Ok(runtime) = runtime else {
                let _ = event_sender.send(Event::Error("runtime init failed".to_string()));
                return;
            };

            runtime.block_on(async move {
                let mut scheduler = Scheduler::new(
                    scheduler_command_receiver,
                    event_sender.clone(),
                    core_command_sender_for_scheduler,
                );
                tokio::spawn(async move {
                    scheduler.run().await;
                });
                core.run_loop().await;
            });
        });

        (CoreHandle { command_sender }, event_receiver)
    }

    /// The main loop where the Core listens for commands.
    async fn run_loop(&mut self) {
        loop {
            // Blocking wait for a command
            match self.command_receiver.recv() {
                Ok(command) => {
                    if let Command::Quit = command {
                        self.send_event(Event::Shutdown);
                        break;
                    }
                    self.process_command(command).await;
                }
                Err(_) => {
                    // Sender disconnected (UI closed unexpectedly)
                    self.send_event(Event::Error("UI disconnected unexpectedly.".to_string()));
                    break;
                }
            }
        }
    }

    /// Sends an event back to the UI.
    fn send_event(&self, event: Event) {
        let _ = self.event_sender.send(event);
    }

    /// Processes a command from the UI.
    async fn process_command(&mut self, command: Command) {
        match command {
            Command::StartScan(rules) => self.handle_start_scan(rules).await,
            Command::UpdateConfig(new_config) => {
                self.config = new_config;
                self.send_event(Event::ProgressKey(0.0, "config.updated".to_string()));
            }
            Command::CleanSelected(item_ids) => self.handle_clean_selected(item_ids).await,
            Command::UndoClean(item_ids) => self.handle_undo_clean(item_ids).await,
            Command::StopOperation => {
                // In a real async implementation, this would signal a stop.
                self.send_event(Event::ProgressKey(1.0, "operation.stopped".to_string()));
            }
            Command::Quit => { /* Handled in run_loop */ }
            Command::RequestHistory => self.send_event(Event::History(self.history.clone())),
            Command::RequestStatistics => {
                self.send_event(Event::Statistics(self.statistics.clone()))
            }
            Command::ScheduleScan(name, interval, rules) => {
                self.handle_schedule_scan(name, interval, rules).await
            }
            Command::CancelScheduledScan(id) => self.handle_cancel_scheduled_scan(id).await,
            Command::RequestScheduledTasks => self.send_event(Event::ScheduledTasks(
                self.scheduled_tasks.values().cloned().collect(),
            )),
        }
    }

    /// Handles the StartScan command.
    async fn handle_start_scan(&mut self, rules: Vec<rules::ScanRule>) {
        self.send_event(Event::ProgressKey(0.0, "scan.starting".to_string()));

        match self
            .fs_port
            .scan_cleanable_items(&rules, &self.config)
            .await
        {
            Ok(result) => {
                self.state = Some(result.clone());
                self.statistics.total_scans += 1;
                self.send_event(Event::ScanCompleted(result));
            }
            Err(e) => self.send_event(Event::Error(format!("Scan failed: {}", e))),
        }
    }

    /// Handles the CleanSelected command.
    async fn handle_clean_selected(&mut self, item_ids: Vec<String>) {
        self.send_event(Event::ProgressKey(0.0, "clean.preparing".to_string()));

        let items_to_clean: Vec<CleanableItem> = if let Some(ref scan_result) = self.state {
            scan_result
                .items
                .iter()
                .filter(|item| item_ids.contains(&item.id))
                .cloned()
                .collect()
        } else {
            vec![]
        };

        match self.fs_port.prepare_clean(&items_to_clean).await {
            Ok(prepared_items) => {
                self.send_event(Event::ProgressKey(0.5, "clean.performing".to_string()));
                let actual_item_ids: Vec<String> =
                    prepared_items.iter().map(|item| item.id.clone()).collect();
                match self.fs_port.clean_items(&actual_item_ids).await {
                    Ok(freed_bytes) => {
                        self.state = None;
                        self.statistics.total_freed_bytes += freed_bytes;
                        self.statistics.total_cleaned_items += prepared_items.len() as u64;
                        self.statistics.last_clean_date = Some(Local::now());

                        self.history.push(CleanHistoryEntry {
                            id: Uuid::new_v4().to_string(),
                            timestamp: Local::now(),
                            cleaned_items: prepared_items,
                            freed_bytes,
                        });
                        self.send_event(Event::CleanCompleted(freed_bytes));
                    }
                    Err(e) => self.send_event(Event::Error(format!("Cleaning failed: {}", e))),
                }
            }
            Err(e) => self.send_event(Event::Error(format!(
                "Preparation for cleaning failed: {}",
                e
            ))),
        }
    }

    /// Handles the UndoClean command.
    async fn handle_undo_clean(&mut self, item_ids: Vec<String>) {
        self.send_event(Event::ProgressKey(0.0, "clean.undo.start".to_string()));

        let mut items_to_undo: Vec<CleanableItem> = Vec::new();
        // Find the items in history that match the IDs and can be undone
        for entry in self.history.iter().rev() {
            // Search history in reverse for most recent clean
            for item in &entry.cleaned_items {
                if item_ids.contains(&item.id) && item.can_undo && item.undo_info.is_some() {
                    items_to_undo.push(item.clone());
                }
            }
            if items_to_undo.len() == item_ids.len() {
                break;
            } // Found all items
        }

        if items_to_undo.is_empty() {
            self.send_event(Event::Error(
                "No cleanable items found in history for undo.".to_string(),
            ));
            return;
        }

        match self.fs_port.undo_clean(&items_to_undo).await {
            Ok(_) => {
                // Update statistics and history (remove undone items)
                // This part can be more sophisticated to truly revert history
                self.send_event(Event::ProgressKey(1.0, "clean.undo.done".to_string()));
            }
            Err(e) => {
                let message = e.to_string();
                let code = classify_undo_error_code(&message).to_string();
                let user_message =
                    undo_failed_user_message_with_language(&code, &self.config.language);
                self.send_event(Event::UndoFailed {
                    code,
                    user_message,
                    message: message.clone(),
                });
                self.send_event(Event::Error(format!("Undo failed: {}", message)));
            }
        }
    }

    /// Handles scheduling a scan.
    async fn handle_schedule_scan(
        &mut self,
        name: String,
        interval: Duration,
        rules: Vec<rules::ScanRule>,
    ) {
        let task_id = Uuid::new_v4().to_string();
        let scheduled_task = ScheduledTask {
            id: task_id.clone(),
            name,
            interval,
            rules: rules.clone(),
            last_run: None,
            next_run: Some(Local::now() + interval),
        };
        self.scheduled_tasks
            .insert(task_id.clone(), scheduled_task.clone());
        self.send_event(Event::ProgressKey(0.0, "schedule.added".to_string()));
        let _ = self
            .scheduler_command_sender
            .send(SchedulerCommand::Schedule(scheduled_task))
            .await;
    }

    /// Handles canceling a scheduled scan.
    async fn handle_cancel_scheduled_scan(&mut self, id: String) {
        if self.scheduled_tasks.remove(&id).is_some() {
            self.send_event(Event::ProgressKey(0.0, "schedule.cancelled".to_string()));
            let _ = self
                .scheduler_command_sender
                .send(SchedulerCommand::Cancel(id))
                .await;
        } else {
            self.send_event(Event::Error(format!(
                "Scheduled task with ID {} not found.",
                id
            )));
        }
    }
}
