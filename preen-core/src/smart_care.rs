use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

use crate::ItemCategory;
use crate::action_runtime::{ActionRisk, ExecutionMode};
use crate::plugin::{ActionType, Capability, RuleFile};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SmartCareCapability {
    Cleanup,
    Performance,
    Applications,
    Protection,
}

impl SmartCareCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cleanup => "cleanup",
            Self::Performance => "performance",
            Self::Applications => "applications",
            Self::Protection => "protection",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::Cleanup => "Cleanup",
            Self::Performance => "Performance",
            Self::Applications => "Applications",
            Self::Protection => "Protection",
        }
    }
}

impl fmt::Display for SmartCareCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareCapabilitySelection {
    pub capability: SmartCareCapability,
    pub enabled: bool,
}

impl SmartCareCapabilitySelection {
    pub fn enabled(capability: SmartCareCapability) -> Self {
        Self {
            capability,
            enabled: true,
        }
    }

    pub fn disabled(capability: SmartCareCapability) -> Self {
        Self {
            capability,
            enabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareProfile {
    pub id: String,
    pub name: String,
    pub capabilities: Vec<SmartCareCapabilitySelection>,
}

impl SmartCareProfile {
    pub fn default_profile() -> Self {
        Self {
            id: "smart-care.default".to_string(),
            name: "Smart Care".to_string(),
            capabilities: vec![
                SmartCareCapabilitySelection::enabled(SmartCareCapability::Cleanup),
                SmartCareCapabilitySelection::enabled(SmartCareCapability::Performance),
                SmartCareCapabilitySelection::enabled(SmartCareCapability::Applications),
                SmartCareCapabilitySelection::enabled(SmartCareCapability::Protection),
            ],
        }
    }

    pub fn enabled_capabilities(&self) -> Vec<SmartCareCapability> {
        self.capabilities
            .iter()
            .filter(|selection| selection.enabled)
            .map(|selection| selection.capability)
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmartCareCheckStatus {
    Passed,
    Warning,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareCheckResult {
    pub id: String,
    pub label: String,
    pub capability: SmartCareCapability,
    pub plugin_pack_id: String,
    pub status: SmartCareCheckStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareTask {
    pub id: String,
    pub label: String,
    pub capability: SmartCareCapability,
    pub plugin_pack_id: String,
    pub rule_id: Option<String>,
    pub risk: ActionRisk,
    pub estimated_freed_bytes: Option<u64>,
    pub metadata: BTreeMap<String, String>,
}

impl SmartCareTask {
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        capability: SmartCareCapability,
        plugin_pack_id: impl Into<String>,
        risk: ActionRisk,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            capability,
            plugin_pack_id: plugin_pack_id.into(),
            rule_id: None,
            risk,
            estimated_freed_bytes: None,
            metadata: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareAnalyzeRequest {
    pub profile: SmartCareProfile,
    pub locale: String,
    pub require_trusted_identity: bool,
}

impl SmartCareAnalyzeRequest {
    pub fn with_profile(profile: SmartCareProfile) -> Self {
        Self {
            profile,
            locale: "en-US".to_string(),
            require_trusted_identity: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCarePluginDescriptor {
    pub pack_id: String,
    pub capability: SmartCareCapability,
    pub enabled: bool,
    pub trusted_identity: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmartCareDescriptorSource {
    None,
    State,
    DevFallback,
    Mixed,
}

impl SmartCareDescriptorSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::State => "state",
            Self::DevFallback => "dev-fallback",
            Self::Mixed => "mixed",
        }
    }
}

pub fn classify_capability_descriptor_source(
    capability: SmartCareCapability,
    descriptors: &[SmartCarePluginDescriptor],
    dev_fallback_pack_ids: &BTreeSet<String>,
) -> SmartCareDescriptorSource {
    let matching = descriptors
        .iter()
        .filter(|descriptor| descriptor.enabled && descriptor.capability == capability)
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return SmartCareDescriptorSource::None;
    }

    let fallback_count = matching
        .iter()
        .filter(|descriptor| dev_fallback_pack_ids.contains(descriptor.pack_id.as_str()))
        .count();
    if fallback_count == 0 {
        SmartCareDescriptorSource::State
    } else if fallback_count == matching.len() {
        SmartCareDescriptorSource::DevFallback
    } else {
        SmartCareDescriptorSource::Mixed
    }
}

pub fn classify_descriptor_pack_source(
    pack_id: &str,
    dev_fallback_pack_ids: &BTreeSet<String>,
) -> SmartCareDescriptorSource {
    if dev_fallback_pack_ids.contains(pack_id) {
        SmartCareDescriptorSource::DevFallback
    } else {
        SmartCareDescriptorSource::State
    }
}

pub const fn default_pack_id_for_capability(capability: SmartCareCapability) -> &'static str {
    match capability {
        SmartCareCapability::Cleanup => "preen-rs.cleanup.base",
        SmartCareCapability::Performance => "preen-rs.performance.base",
        SmartCareCapability::Applications => "preen-rs.applications.base",
        SmartCareCapability::Protection => "preen-rs.protection.base",
    }
}

pub fn preferred_plugin_spec_for_capability(
    capability: SmartCareCapability,
    descriptors: &[SmartCarePluginDescriptor],
) -> String {
    let mut matching = descriptors
        .iter()
        .filter(|descriptor| descriptor.enabled && descriptor.capability == capability)
        .collect::<Vec<_>>();
    matching.sort_by(|left, right| {
        right
            .trusted_identity
            .is_some()
            .cmp(&left.trusted_identity.is_some())
            .then_with(|| left.pack_id.cmp(&right.pack_id))
            .then_with(|| left.version.cmp(&right.version))
    });

    matching
        .first()
        .map(|descriptor| plugin_spec_from_descriptor(descriptor))
        .unwrap_or_else(|| default_pack_id_for_capability(capability).to_string())
}

pub fn plugin_spec_from_descriptor(descriptor: &SmartCarePluginDescriptor) -> String {
    match descriptor.version.as_deref() {
        Some(version) if !version.trim().is_empty() => {
            format!("{}@{version}", descriptor.pack_id)
        }
        _ => descriptor.pack_id.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmartCareCapabilityStatus {
    Disabled,
    MissingPlugin,
    UntrustedOnly,
    Ready,
}

impl SmartCareCapabilityStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::MissingPlugin => "missing_plugin",
            Self::UntrustedOnly => "untrusted_only",
            Self::Ready => "ready",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareReviewEntry {
    pub id: String,
    pub capability: SmartCareCapability,
    pub pack_id: String,
    pub version: Option<String>,
    pub trusted_identity: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub rule_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareCapabilityCard {
    pub capability: SmartCareCapability,
    pub enabled: bool,
    pub status: SmartCareCapabilityStatus,
    pub plugin_count: usize,
    pub trusted_plugin_count: usize,
    pub headline: String,
    pub subline: String,
    pub review_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCarePreview {
    pub profile_id: String,
    pub cards: Vec<SmartCareCapabilityCard>,
    pub review_entries: Vec<SmartCareReviewEntry>,
    pub selected_plugins: Vec<String>,
    pub blockers: Vec<String>,
    pub overall_ready: bool,
}

pub fn descriptors_from_plugin_rules(
    pack_id: &str,
    enabled: bool,
    trusted_identity: Option<String>,
    version: Option<String>,
    plugin_capabilities: &[Capability],
    rules: &[RuleFile],
) -> Vec<SmartCarePluginDescriptor> {
    let mut capabilities = HashSet::new();
    let manifest_capabilities = infer_capabilities_from_manifest(plugin_capabilities);
    if !manifest_capabilities.is_empty() {
        capabilities.extend(manifest_capabilities);
    } else {
        for rule in rules {
            if let Some(capability) = infer_capability_from_rule(rule) {
                capabilities.insert(capability);
            }
        }
    }
    if capabilities.is_empty() {
        capabilities.extend(infer_capabilities_from_pack_id(pack_id));
    }

    let mut sorted = capabilities.into_iter().collect::<Vec<_>>();
    sorted.sort();
    sorted
        .into_iter()
        .map(|capability| SmartCarePluginDescriptor {
            pack_id: pack_id.to_string(),
            capability,
            enabled,
            trusted_identity: trusted_identity.clone(),
            version: version.clone(),
        })
        .collect()
}

pub fn infer_capability_from_rule(rule: &RuleFile) -> Option<SmartCareCapability> {
    if let Some(value) = rule.action.params.get("smart_care_capability")
        && let Some(capability) = parse_capability_tag(value)
    {
        return Some(capability);
    }

    if let Some(value) = rule.action.params.get("domain")
        && let Some(capability) = parse_capability_tag(value)
    {
        return Some(capability);
    }

    infer_capability_from_action_type(&rule.action.action_type)
        .or_else(|| infer_capability_from_item_category(&rule.category))
}

fn infer_capability_from_action_type(action: &ActionType) -> Option<SmartCareCapability> {
    match action {
        ActionType::TrashPaths
        | ActionType::DeletePaths
        | ActionType::PruneEmptyDirs
        | ActionType::RemoveOrphans
        | ActionType::ProjectCleanup
        | ActionType::FindInstallers
        | ActionType::DiskUsageSnapshot => Some(SmartCareCapability::Cleanup),
        ActionType::AppUninstall => Some(SmartCareCapability::Applications),
        ActionType::OptimizeSystem | ActionType::SystemStatus => {
            Some(SmartCareCapability::Performance)
        }
        ActionType::RunCommand => None,
        _ => None,
    }
}

fn infer_capability_from_item_category(category: &ItemCategory) -> Option<SmartCareCapability> {
    match category {
        ItemCategory::Cache
        | ItemCategory::Logs
        | ItemCategory::TemporaryFiles
        | ItemCategory::BrokenSymlinks
        | ItemCategory::OldDownloads => Some(SmartCareCapability::Cleanup),
        ItemCategory::Other(_) => None,
    }
}

fn infer_capabilities_from_manifest(capabilities: &[Capability]) -> HashSet<SmartCareCapability> {
    let mut out = HashSet::new();
    for capability in capabilities {
        let mapped = match capability {
            Capability::SystemOptimize => Some(SmartCareCapability::Performance),
            Capability::Other(value) => parse_capability_tag(value),
            _ => None,
        };
        if let Some(capability) = mapped {
            out.insert(capability);
        }
    }
    out
}

fn infer_capabilities_from_pack_id(pack_id: &str) -> HashSet<SmartCareCapability> {
    let mut out = HashSet::new();
    for token in pack_id
        .trim()
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
    {
        let mapped = match token {
            "cleanup" => Some(SmartCareCapability::Cleanup),
            "performance" | "optimize" | "optimization" => Some(SmartCareCapability::Performance),
            "applications" | "application" | "apps" | "app" => {
                Some(SmartCareCapability::Applications)
            }
            "protection" | "security" => Some(SmartCareCapability::Protection),
            _ => None,
        };
        if let Some(capability) = mapped {
            out.insert(capability);
        }
    }
    out
}

fn parse_capability_tag(raw: &str) -> Option<SmartCareCapability> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "cleanup" => Some(SmartCareCapability::Cleanup),
        "performance" => Some(SmartCareCapability::Performance),
        "applications" | "apps" => Some(SmartCareCapability::Applications),
        "protection" | "security" => Some(SmartCareCapability::Protection),
        _ => None,
    }
}

pub fn build_preview_from_descriptors(
    profile: &SmartCareProfile,
    descriptors: &[SmartCarePluginDescriptor],
) -> SmartCarePreview {
    let mut cards = Vec::new();
    let mut selected_plugins = BTreeSet::new();
    let mut review_entries = Vec::new();
    let mut blockers = Vec::new();

    for selection in &profile.capabilities {
        let matching = dedup_descriptors_by_pack(
            descriptors
                .iter()
                .filter(|descriptor| {
                    descriptor.enabled && descriptor.capability == selection.capability
                })
                .collect::<Vec<_>>(),
        );
        let trusted = matching
            .iter()
            .filter(|descriptor| descriptor.trusted_identity.is_some())
            .count();

        let status = if !selection.enabled {
            SmartCareCapabilityStatus::Disabled
        } else if matching.is_empty() {
            SmartCareCapabilityStatus::MissingPlugin
        } else if trusted == 0 {
            SmartCareCapabilityStatus::UntrustedOnly
        } else {
            SmartCareCapabilityStatus::Ready
        };

        if selection.enabled {
            match status {
                SmartCareCapabilityStatus::MissingPlugin => blockers.push(format!(
                    "{}: no installed capability plugin",
                    selection.capability.as_str()
                )),
                SmartCareCapabilityStatus::UntrustedOnly => blockers.push(format!(
                    "{}: plugins are installed but none is trusted",
                    selection.capability.as_str()
                )),
                _ => {}
            }
        }

        let plugin_count = matching.len();
        let mut review_count = 0usize;
        for descriptor in &matching {
            if selection.enabled && descriptor.trusted_identity.is_some() {
                selected_plugins.insert(format!(
                    "{}@{}",
                    descriptor.pack_id,
                    descriptor.version.as_deref().unwrap_or("n/a")
                ));
                review_entries.push(SmartCareReviewEntry {
                    id: format!("{}:{}", descriptor.pack_id, selection.capability.as_str()),
                    capability: selection.capability,
                    pack_id: descriptor.pack_id.clone(),
                    version: descriptor.version.clone(),
                    trusted_identity: descriptor.trusted_identity.clone(),
                    rule_id: None,
                    rule_label: None,
                });
                review_count = review_count.saturating_add(1);
            }
        }

        let (headline, subline) = card_copy(selection.capability, status, plugin_count, trusted);
        cards.push(SmartCareCapabilityCard {
            capability: selection.capability,
            enabled: selection.enabled,
            status,
            plugin_count,
            trusted_plugin_count: trusted,
            headline,
            subline,
            review_count,
        });
    }

    SmartCarePreview {
        profile_id: profile.id.clone(),
        cards,
        review_entries,
        selected_plugins: selected_plugins.into_iter().collect(),
        blockers: blockers.clone(),
        overall_ready: blockers.is_empty(),
    }
}

fn card_copy(
    capability: SmartCareCapability,
    status: SmartCareCapabilityStatus,
    plugin_count: usize,
    trusted_count: usize,
) -> (String, String) {
    let title = capability.title();
    match status {
        SmartCareCapabilityStatus::Disabled => (
            format!("{title} disabled"),
            "Enable this capability to include it in Smart Care run".to_string(),
        ),
        SmartCareCapabilityStatus::MissingPlugin => (
            format!("No {title} plugin installed"),
            "Install an official trusted plugin to continue".to_string(),
        ),
        SmartCareCapabilityStatus::UntrustedOnly => (
            format!("{title} plugin not trusted"),
            "Trust policy blocked available plugins".to_string(),
        ),
        SmartCareCapabilityStatus::Ready => (
            format!("{trusted_count} trusted plugin(s) ready"),
            format!("{plugin_count} capability plugin(s) detected"),
        ),
    }
}

fn dedup_descriptors_by_pack(
    descriptors: Vec<&SmartCarePluginDescriptor>,
) -> Vec<&SmartCarePluginDescriptor> {
    let mut deduped = BTreeMap::<String, &SmartCarePluginDescriptor>::new();
    for descriptor in descriptors {
        match deduped.get(&descriptor.pack_id) {
            Some(existing)
                if existing.trusted_identity.is_some() || descriptor.trusted_identity.is_none() => {
            }
            _ => {
                deduped.insert(descriptor.pack_id.clone(), descriptor);
            }
        }
    }
    deduped.into_values().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSmartCareAnalysis {
    pub checks: Vec<SmartCareCheckResult>,
    pub tasks: Vec<SmartCareTask>,
    pub warnings: Vec<String>,
    pub estimated_freed_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCarePlan {
    pub profile_id: String,
    pub generated_at: DateTime<Utc>,
    pub checks: Vec<SmartCareCheckResult>,
    pub tasks: Vec<SmartCareTask>,
    pub warnings: Vec<String>,
    pub estimated_freed_bytes: u64,
    pub selected_plugin_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareExecuteRequest {
    pub plan: SmartCarePlan,
    pub mode: ExecutionMode,
    pub selected_task_ids: Vec<String>,
    pub confirmation_token: Option<String>,
}

impl SmartCareExecuteRequest {
    pub fn selected_task_id_set(&self) -> HashSet<&str> {
        self.selected_task_ids
            .iter()
            .map(std::string::String::as_str)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSmartCareExecuteRequest {
    pub mode: ExecutionMode,
    pub confirmation_token: Option<String>,
    pub tasks: Vec<SmartCareTask>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareTaskExecutionResult {
    pub task_id: String,
    pub capability: SmartCareCapability,
    pub plugin_pack_id: String,
    pub succeeded: bool,
    pub affected_items: u64,
    pub freed_bytes: u64,
    pub message: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSmartCareExecutionResult {
    pub task_results: Vec<SmartCareTaskExecutionResult>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareExecutionResult {
    pub run_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub task_results: Vec<SmartCareTaskExecutionResult>,
    pub warnings: Vec<String>,
    pub total_affected_items: u64,
    pub total_freed_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareUndoRequest {
    pub run_id: Uuid,
    pub capabilities: Vec<SmartCareCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSmartCareUndoResult {
    pub restored_items: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartCareUndoResult {
    pub run_id: Uuid,
    pub restored_items: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SmartCareError {
    #[error("profile has no enabled capabilities")]
    EmptyProfile,
    #[error("duplicate plugin engine registration: {pack_id} ({capability})")]
    DuplicatePluginEngine {
        pack_id: String,
        capability: SmartCareCapability,
    },
    #[error("no active plugins resolved for selected profile")]
    NoActivePluginsForProfile,
    #[error("no trusted plugins resolved for selected profile")]
    NoTrustedPluginsForProfile,
    #[error("plugin engine is missing: {pack_id}")]
    MissingPluginEngine { pack_id: String },
    #[error("plugin analyze failed ({pack_id}): {message}")]
    AnalyzeFailed { pack_id: String, message: String },
    #[error("plugin execute failed ({pack_id}): {message}")]
    ExecuteFailed { pack_id: String, message: String },
    #[error("plugin undo failed ({pack_id}): {message}")]
    UndoFailed { pack_id: String, message: String },
}

#[async_trait]
pub trait SmartCarePluginPort: Send + Sync {
    fn descriptor(&self) -> SmartCarePluginDescriptor;

    async fn analyze(
        &self,
        request: SmartCareAnalyzeRequest,
    ) -> Result<PluginSmartCareAnalysis, String>;

    async fn execute(
        &self,
        request: PluginSmartCareExecuteRequest,
    ) -> Result<PluginSmartCareExecutionResult, String>;

    async fn undo(
        &self,
        request: SmartCareUndoRequest,
    ) -> Result<PluginSmartCareUndoResult, String>;
}

pub struct SmartCareOrchestrator {
    plugins: HashMap<String, Box<dyn SmartCarePluginPort>>,
    descriptors: HashMap<String, SmartCarePluginDescriptor>,
}

impl SmartCareOrchestrator {
    pub fn new(plugins: Vec<Box<dyn SmartCarePluginPort>>) -> Result<Self, SmartCareError> {
        let mut by_pack_id = HashMap::new();
        let mut descriptors = HashMap::new();
        let mut seen = HashSet::new();

        for plugin in plugins {
            let descriptor = plugin.descriptor();
            let unique = (descriptor.pack_id.clone(), descriptor.capability);
            if !seen.insert(unique.clone()) {
                return Err(SmartCareError::DuplicatePluginEngine {
                    pack_id: unique.0,
                    capability: unique.1,
                });
            }
            descriptors.insert(descriptor.pack_id.clone(), descriptor);
            by_pack_id.insert(unique.0, plugin);
        }

        Ok(Self {
            plugins: by_pack_id,
            descriptors,
        })
    }

    pub async fn analyze(
        &self,
        request: SmartCareAnalyzeRequest,
    ) -> Result<SmartCarePlan, SmartCareError> {
        let enabled_capabilities = request.profile.enabled_capabilities();
        if enabled_capabilities.is_empty() {
            return Err(SmartCareError::EmptyProfile);
        }
        let enabled_capability_set = enabled_capabilities.into_iter().collect::<HashSet<_>>();

        let candidate_plugins = self
            .descriptors
            .values()
            .filter(|descriptor| descriptor.enabled)
            .filter(|descriptor| enabled_capability_set.contains(&descriptor.capability))
            .map(|descriptor| descriptor.pack_id.clone())
            .collect::<Vec<_>>();

        if candidate_plugins.is_empty() {
            return Err(SmartCareError::NoActivePluginsForProfile);
        }

        let selected_plugins = candidate_plugins
            .iter()
            .filter_map(|pack_id| self.descriptors.get(pack_id))
            .filter(|descriptor| {
                !request.require_trusted_identity || descriptor.trusted_identity.is_some()
            })
            .map(|descriptor| descriptor.pack_id.clone())
            .collect::<Vec<_>>();

        if selected_plugins.is_empty() {
            return Err(SmartCareError::NoTrustedPluginsForProfile);
        }

        let mut checks = Vec::new();
        let mut tasks = Vec::new();
        let mut warnings = Vec::new();
        let mut estimated_freed_bytes = 0u64;

        for pack_id in &selected_plugins {
            let Some(plugin) = self.plugins.get(pack_id) else {
                return Err(SmartCareError::MissingPluginEngine {
                    pack_id: pack_id.clone(),
                });
            };
            let descriptor = plugin.descriptor();
            let mut analysis = plugin.analyze(request.clone()).await.map_err(|message| {
                SmartCareError::AnalyzeFailed {
                    pack_id: descriptor.pack_id.clone(),
                    message,
                }
            })?;

            estimated_freed_bytes =
                estimated_freed_bytes.saturating_add(analysis.estimated_freed_bytes);
            checks.extend(
                analysis
                    .checks
                    .drain(..)
                    .map(|check| normalize_check(check, &descriptor)),
            );
            warnings.append(&mut analysis.warnings);
            tasks.extend(
                analysis
                    .tasks
                    .drain(..)
                    .map(|task| normalize_task(task, &descriptor)),
            );
        }

        Ok(SmartCarePlan {
            profile_id: request.profile.id,
            generated_at: Utc::now(),
            checks,
            tasks,
            warnings,
            estimated_freed_bytes,
            selected_plugin_count: selected_plugins.len(),
        })
    }

    pub async fn execute(
        &self,
        request: SmartCareExecuteRequest,
    ) -> Result<SmartCareExecutionResult, SmartCareError> {
        let started_at = Utc::now();
        let run_id = Uuid::new_v4();
        let selected_set = request.selected_task_id_set();
        let mut by_plugin = HashMap::<String, Vec<SmartCareTask>>::new();

        for task in &request.plan.tasks {
            let include_task = selected_set.is_empty() || selected_set.contains(task.id.as_str());
            if include_task {
                by_plugin
                    .entry(task.plugin_pack_id.clone())
                    .or_default()
                    .push(task.clone());
            }
        }

        let mut task_results = Vec::new();
        let mut warnings = Vec::new();

        for (pack_id, plugin_tasks) in by_plugin {
            let Some(plugin) = self.plugins.get(&pack_id) else {
                return Err(SmartCareError::MissingPluginEngine { pack_id });
            };

            let mut result = plugin
                .execute(PluginSmartCareExecuteRequest {
                    mode: request.mode,
                    confirmation_token: request.confirmation_token.clone(),
                    tasks: plugin_tasks,
                })
                .await
                .map_err(|message| SmartCareError::ExecuteFailed {
                    pack_id: plugin.descriptor().pack_id,
                    message,
                })?;
            warnings.append(&mut result.warnings);
            task_results.append(&mut result.task_results);
        }

        let total_affected_items = task_results
            .iter()
            .map(|result| result.affected_items)
            .sum();
        let total_freed_bytes = task_results.iter().map(|result| result.freed_bytes).sum();

        Ok(SmartCareExecutionResult {
            run_id,
            started_at,
            finished_at: Utc::now(),
            task_results,
            warnings,
            total_affected_items,
            total_freed_bytes,
        })
    }

    pub async fn undo(
        &self,
        request: SmartCareUndoRequest,
    ) -> Result<SmartCareUndoResult, SmartCareError> {
        let capability_filter = request.capabilities.iter().copied().collect::<HashSet<_>>();
        let use_filter = !capability_filter.is_empty();

        let selected_plugins = self
            .descriptors
            .values()
            .filter(|descriptor| descriptor.enabled)
            .filter(|descriptor| !use_filter || capability_filter.contains(&descriptor.capability))
            .map(|descriptor| descriptor.pack_id.clone())
            .collect::<Vec<_>>();

        let mut restored_items = 0u64;
        let mut warnings = Vec::new();

        for pack_id in selected_plugins {
            let Some(plugin) = self.plugins.get(&pack_id) else {
                return Err(SmartCareError::MissingPluginEngine { pack_id });
            };
            let mut result = plugin
                .undo(SmartCareUndoRequest {
                    run_id: request.run_id,
                    capabilities: request.capabilities.clone(),
                })
                .await
                .map_err(|message| SmartCareError::UndoFailed {
                    pack_id: plugin.descriptor().pack_id,
                    message,
                })?;
            restored_items = restored_items.saturating_add(result.restored_items);
            warnings.append(&mut result.warnings);
        }

        Ok(SmartCareUndoResult {
            run_id: request.run_id,
            restored_items,
            warnings,
        })
    }
}

fn normalize_task(
    mut task: SmartCareTask,
    descriptor: &SmartCarePluginDescriptor,
) -> SmartCareTask {
    task.capability = descriptor.capability;
    task.plugin_pack_id = descriptor.pack_id.clone();
    if !task.id.starts_with(&format!("{}:", descriptor.pack_id)) {
        task.id = format!("{}:{}", descriptor.pack_id, task.id);
    }
    task
}

fn normalize_check(
    mut check: SmartCareCheckResult,
    descriptor: &SmartCarePluginDescriptor,
) -> SmartCareCheckResult {
    check.capability = descriptor.capability;
    check.plugin_pack_id = descriptor.pack_id.clone();
    check
}
