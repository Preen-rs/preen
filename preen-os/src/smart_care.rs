use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use preen_core::plugin_loader::load_rule_pack_from_dir;
use preen_core::plugin_lock::PluginLockfile;
use preen_core::smart_care::{SmartCarePluginDescriptor, descriptors_from_plugin_rules};

pub(crate) const DEFAULT_PLUGIN_LOCKFILE_NAME: &str = "plugins.lock";
pub(crate) const LEGACY_PLUGIN_LOCKFILE_NAME: &str = "preen-plugins.lock";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorResolutionReport {
    pub descriptors: Vec<SmartCarePluginDescriptor>,
    pub loaded_from_state: usize,
    pub loaded_from_dev_fallback: usize,
    pub loaded_from_plugins_scan: usize,
    pub skipped_plugins: Vec<String>,
    pub dev_fallback_pack_ids: Vec<String>,
    pub source: DescriptorSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorSource {
    Lockfile,
    PluginsDirScan,
}

impl DescriptorResolutionReport {
    pub fn source_summary(&self) -> String {
        let mut summary = if matches!(self.source, DescriptorSource::PluginsDirScan) {
            format!("plugins-scan (packs={})", self.loaded_from_state)
        } else {
            let base = if self.loaded_from_dev_fallback == 0 {
                format!("state-only (packs={})", self.loaded_from_state)
            } else {
                let fallback_ids = if self.dev_fallback_pack_ids.is_empty() {
                    "unknown".to_string()
                } else {
                    self.dev_fallback_pack_ids.join(", ")
                };
                format!(
                    "state={} | dev-fallback={} [{fallback_ids}]",
                    self.loaded_from_state, self.loaded_from_dev_fallback
                )
            };
            if self.loaded_from_plugins_scan == 0 {
                base
            } else {
                format!(
                    "{base} | plugins-scan-extra={}",
                    self.loaded_from_plugins_scan
                )
            }
        };
        if !self.skipped_plugins.is_empty() {
            summary.push_str(&format!(" | skipped={}", self.skipped_plugins.len()));
        }
        summary
    }

    pub fn skipped_summary(&self, limit: usize) -> Option<String> {
        if self.skipped_plugins.is_empty() {
            return None;
        }
        let shown = self
            .skipped_plugins
            .iter()
            .take(limit.max(1))
            .cloned()
            .collect::<Vec<_>>();
        let mut detail = format!("skipped plugin packs: {}", shown.join(", "));
        let remaining = self.skipped_plugins.len().saturating_sub(shown.len());
        if remaining > 0 {
            detail.push_str(&format!(" (+{remaining} more)"));
        }
        Some(detail)
    }
}

fn dedup_skipped_plugins(skipped_plugins: &mut Vec<String>) {
    skipped_plugins.sort();
    skipped_plugins.dedup();
}

pub fn resolve_descriptors_from_state_dir(
    state_dir: &Path,
) -> Result<Vec<SmartCarePluginDescriptor>, String> {
    Ok(resolve_descriptors_with_report_from_state_dir(state_dir)?.descriptors)
}

pub fn resolve_descriptors_with_report_from_state_dir(
    state_dir: &Path,
) -> Result<DescriptorResolutionReport, String> {
    match read_plugin_lockfile_from_state_dir_internal(state_dir) {
        Ok(lockfile) => {
            let mut report = resolve_descriptors_from_lockfile_with_report(state_dir, &lockfile)?;
            supplement_report_from_plugins_dir_scan(state_dir, &mut report);
            Ok(report)
        }
        Err(LockfileReadError::NotFound(_)) => resolve_descriptors_from_plugins_dir_scan(state_dir),
        Err(error) => Err(error.to_display_message()),
    }
}

pub(crate) fn resolve_lockfile_read_path(state_dir: &Path) -> PathBuf {
    let default_path = state_dir.join(DEFAULT_PLUGIN_LOCKFILE_NAME);
    if default_path.exists() {
        return default_path;
    }
    let legacy_path = state_dir.join(LEGACY_PLUGIN_LOCKFILE_NAME);
    if legacy_path.exists() {
        return legacy_path;
    }
    default_path
}

pub(crate) fn read_plugin_lockfile_from_state_dir(
    state_dir: &Path,
) -> Result<PluginLockfile, String> {
    read_plugin_lockfile_from_state_dir_internal(state_dir)
        .map_err(|error| error.to_display_message())
}

fn read_plugin_lockfile_from_state_dir_internal(
    state_dir: &Path,
) -> Result<PluginLockfile, LockfileReadError> {
    let lockfile_path = resolve_lockfile_read_path(state_dir);
    let lockfile_content = std::fs::read_to_string(&lockfile_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            LockfileReadError::NotFound(lockfile_path.clone())
        } else {
            LockfileReadError::Read {
                path: lockfile_path.clone(),
                message: error.to_string(),
            }
        }
    })?;
    lockfile_content
        .parse::<PluginLockfile>()
        .map_err(|error| LockfileReadError::Parse {
            path: lockfile_path,
            message: format!("{error:?}"),
        })
}

pub fn resolve_descriptors_from_lockfile(
    state_dir: &Path,
    lockfile: &PluginLockfile,
) -> Result<Vec<SmartCarePluginDescriptor>, String> {
    Ok(resolve_descriptors_from_lockfile_with_report(state_dir, lockfile)?.descriptors)
}

pub fn resolve_descriptors_from_lockfile_with_report(
    state_dir: &Path,
    lockfile: &PluginLockfile,
) -> Result<DescriptorResolutionReport, String> {
    let dev_plugin_roots = default_dev_plugin_roots();
    resolve_descriptors_from_lockfile_with_roots(state_dir, lockfile, &dev_plugin_roots)
}

fn resolve_descriptors_from_lockfile_with_roots(
    state_dir: &Path,
    lockfile: &PluginLockfile,
    dev_plugin_roots: &[PathBuf],
) -> Result<DescriptorResolutionReport, String> {
    let plugins_dir = state_dir.join("plugins");
    let mut descriptors = Vec::new();
    let mut loaded_from_state = 0usize;
    let mut loaded_from_dev_fallback = 0usize;
    let mut skipped_plugins = Vec::new();
    let mut dev_fallback_pack_ids = Vec::new();

    for plugin in &lockfile.plugins {
        let pack_dir = plugins_dir.join(&plugin.pack_id);
        let (loaded, origin) = match load_pack_with_fallback(
            &pack_dir,
            &plugin.pack_id,
            state_dir,
            dev_plugin_roots,
        ) {
            Ok(value) => value,
            Err(_) => {
                skipped_plugins.push(plugin.pack_id.clone());
                continue;
            }
        };
        match origin {
            LoadPackOrigin::StateInstalled => loaded_from_state += 1,
            LoadPackOrigin::DevFallback => {
                loaded_from_dev_fallback += 1;
                dev_fallback_pack_ids.push(plugin.pack_id.clone());
            }
        }
        let mut plugin_descriptors = descriptors_from_plugin_rules(
            &plugin.pack_id,
            true,
            normalize_optional_field(&plugin.trusted_identity),
            Some(plugin.version.clone()),
            &loaded.manifest.capabilities,
            &loaded.rules,
        );
        descriptors.append(&mut plugin_descriptors);
    }

    dedup_descriptors(&mut descriptors);
    dedup_skipped_plugins(&mut skipped_plugins);
    dev_fallback_pack_ids.sort();
    dev_fallback_pack_ids.dedup();
    Ok(DescriptorResolutionReport {
        descriptors,
        loaded_from_state,
        loaded_from_dev_fallback,
        loaded_from_plugins_scan: 0,
        skipped_plugins,
        dev_fallback_pack_ids,
        source: DescriptorSource::Lockfile,
    })
}

fn resolve_descriptors_from_plugins_dir_scan(
    state_dir: &Path,
) -> Result<DescriptorResolutionReport, String> {
    let plugins_dir = state_dir.join("plugins");
    if !plugins_dir.is_dir() {
        return Ok(DescriptorResolutionReport {
            descriptors: Vec::new(),
            loaded_from_state: 0,
            loaded_from_dev_fallback: 0,
            loaded_from_plugins_scan: 0,
            skipped_plugins: Vec::new(),
            dev_fallback_pack_ids: Vec::new(),
            source: DescriptorSource::PluginsDirScan,
        });
    }

    let mut pack_dirs = std::fs::read_dir(&plugins_dir)
        .map_err(|error| {
            format!(
                "failed to list plugins dir {}: {error}",
                plugins_dir.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    pack_dirs.sort();

    let mut descriptors = Vec::new();
    let mut loaded_pack_ids = BTreeSet::new();
    let mut skipped_plugins = Vec::new();

    for pack_dir in pack_dirs {
        let loaded = match load_rule_pack_from_dir(&pack_dir) {
            Ok(loaded) => loaded,
            Err(_) => {
                if let Some(name) = pack_dir.file_name().and_then(|name| name.to_str()) {
                    skipped_plugins.push(name.to_string());
                }
                continue;
            }
        };
        let pack_id = loaded.manifest.pack_id.clone();
        loaded_pack_ids.insert(pack_id.clone());
        let mut plugin_descriptors = descriptors_from_plugin_rules(
            &pack_id,
            true,
            None,
            Some(loaded.manifest.version.clone()),
            &loaded.manifest.capabilities,
            &loaded.rules,
        );
        descriptors.append(&mut plugin_descriptors);
    }

    dedup_descriptors(&mut descriptors);
    dedup_skipped_plugins(&mut skipped_plugins);
    Ok(DescriptorResolutionReport {
        descriptors,
        loaded_from_state: loaded_pack_ids.len(),
        loaded_from_dev_fallback: 0,
        loaded_from_plugins_scan: 0,
        skipped_plugins,
        dev_fallback_pack_ids: Vec::new(),
        source: DescriptorSource::PluginsDirScan,
    })
}

fn supplement_report_from_plugins_dir_scan(
    state_dir: &Path,
    report: &mut DescriptorResolutionReport,
) {
    let scan_report = match resolve_descriptors_from_plugins_dir_scan(state_dir) {
        Ok(scan_report) => scan_report,
        Err(_) => return,
    };
    report
        .skipped_plugins
        .extend(scan_report.skipped_plugins.iter().cloned());
    dedup_skipped_plugins(&mut report.skipped_plugins);
    if scan_report.descriptors.is_empty() {
        return;
    }

    let mut seen = report
        .descriptors
        .iter()
        .map(|descriptor| (descriptor.pack_id.clone(), descriptor.capability))
        .collect::<HashSet<_>>();
    let mut added_pack_ids = BTreeSet::new();
    for descriptor in scan_report.descriptors {
        let key = (descriptor.pack_id.clone(), descriptor.capability);
        if seen.insert(key.clone()) {
            added_pack_ids.insert(key.0);
            report.descriptors.push(descriptor);
        }
    }
    if added_pack_ids.is_empty() {
        return;
    }

    report.loaded_from_plugins_scan = report
        .loaded_from_plugins_scan
        .saturating_add(added_pack_ids.len());
    dedup_descriptors(&mut report.descriptors);
}

#[derive(Debug)]
enum LockfileReadError {
    NotFound(PathBuf),
    Read { path: PathBuf, message: String },
    Parse { path: PathBuf, message: String },
}

impl LockfileReadError {
    fn to_display_message(&self) -> String {
        match self {
            Self::NotFound(path) => {
                format!(
                    "failed to read plugin lockfile at {}: not found",
                    path.display()
                )
            }
            Self::Read { path, message } => {
                format!(
                    "failed to read plugin lockfile at {}: {message}",
                    path.display()
                )
            }
            Self::Parse { path, message } => {
                format!(
                    "failed to parse plugin lockfile at {}: {message}",
                    path.display()
                )
            }
        }
    }
}

fn load_pack(
    pack_dir: &Path,
    pack_id: &str,
) -> Result<preen_core::plugin_loader::LoadedRulePack, String> {
    load_rule_pack_from_dir(pack_dir).map_err(|error| {
        format!(
            "failed to load plugin pack {pack_id} from {}: {error:?}",
            pack_dir.display()
        )
    })
}

fn load_pack_with_fallback(
    state_pack_dir: &Path,
    pack_id: &str,
    state_dir: &Path,
    dev_plugin_roots: &[PathBuf],
) -> Result<(preen_core::plugin_loader::LoadedRulePack, LoadPackOrigin), String> {
    match load_pack(state_pack_dir, pack_id) {
        Ok(loaded) => Ok((loaded, LoadPackOrigin::StateInstalled)),
        Err(primary_error) => {
            if !state_pack_missing_for_fallback(state_pack_dir) {
                return Err(primary_error);
            }
            if let Some(dev_pack_dir) = find_dev_pack_dir(pack_id, state_dir, dev_plugin_roots) {
                return load_pack(&dev_pack_dir, pack_id)
                    .map(|loaded| (loaded, LoadPackOrigin::DevFallback));
            }
            Err(primary_error)
        }
    }
}

fn state_pack_missing_for_fallback(state_pack_dir: &Path) -> bool {
    !state_pack_dir.is_dir() || !state_pack_dir.join("manifest.toml").is_file()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadPackOrigin {
    StateInstalled,
    DevFallback,
}

fn default_dev_plugin_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(raw) = std::env::var_os("PREEN_DEV_PLUGIN_ROOTS") {
        roots.extend(std::env::split_paths(&raw).filter(|path| path.is_dir()));
    }
    if cfg!(debug_assertions)
        && let Ok(cwd) = std::env::current_dir()
    {
        let template_root = cwd.join(".template-worktrees");
        if template_root.is_dir() {
            roots.push(template_root);
        }
    }
    roots
}

fn find_dev_pack_dir(
    pack_id: &str,
    state_dir: &Path,
    dev_plugin_roots: &[PathBuf],
) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    for root in dev_plugin_roots {
        if !root.is_dir() {
            continue;
        }
        if seen.insert(root.clone()) {
            candidates.push(root.clone());
        }
        let nested = root.join(pack_id);
        if seen.insert(nested.clone()) {
            candidates.push(nested);
        }
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && seen.insert(path.clone()) {
                    candidates.push(path);
                }
            }
        }
    }

    candidates.into_iter().find(|candidate| {
        if candidate.starts_with(state_dir.join("plugins")) {
            return false;
        }
        let manifest_path = candidate.join("manifest.toml");
        if !manifest_path.is_file() {
            return false;
        }
        load_rule_pack_from_dir(candidate)
            .map(|loaded| loaded.manifest.pack_id == pack_id)
            .unwrap_or(false)
    })
}

fn normalize_optional_field(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn dedup_descriptors(descriptors: &mut Vec<SmartCarePluginDescriptor>) {
    let mut seen = HashSet::new();
    descriptors
        .retain(|descriptor| seen.insert((descriptor.pack_id.clone(), descriptor.capability)));
    descriptors.sort_by(|left, right| {
        left.pack_id
            .cmp(&right.pack_id)
            .then_with(|| left.capability.as_str().cmp(right.capability.as_str()))
    });
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PLUGIN_LOCKFILE_NAME, DescriptorSource, LEGACY_PLUGIN_LOCKFILE_NAME,
        resolve_descriptors_from_lockfile, resolve_descriptors_from_lockfile_with_report,
        resolve_descriptors_from_lockfile_with_roots, resolve_descriptors_from_state_dir,
        resolve_descriptors_with_report_from_state_dir,
    };
    use preen_core::plugin_lock::{LockedPlugin, PluginLockfile};
    use preen_core::smart_care::SmartCareCapability;
    use std::fs;
    use std::path::Path;

    fn build_pack(base: &Path, pack_id: &str, action_type: &str, capability_tag: Option<&str>) {
        build_pack_at(
            &base.join("plugins").join(pack_id),
            pack_id,
            action_type,
            capability_tag,
        );
    }

    fn build_pack_at(
        pack_dir: &Path,
        pack_id: &str,
        action_type: &str,
        capability_tag: Option<&str>,
    ) {
        fs::create_dir_all(pack_dir.join("rules")).unwrap();
        let command_block = if action_type == "RunCommand" {
            r#"command = ["true"]"#
        } else {
            "command = []"
        };
        let params_block = match capability_tag {
            Some(tag) => format!(r#"params = {{ smart_care_capability = "{tag}" }}"#),
            None => "params = {}".to_string(),
        };
        fs::write(
            pack_dir.join("manifest.toml"),
            format!(
                r#"
schema_version = 1
pack_id = "{pack_id}"
name = "Test"
version = "1.0.0"
description = "Test plugin"
author = "Preen"
license = "MIT"
homepage = ""
core_compat = ">=0.1.0,<2.0.0"
action_api = 1
os_targets = ["Macos", "Linux"]
capabilities = ["FsRead"]

[[rules]]
id = "{pack_id}.rule"
name = "Rule"
rule_file = "rules/rule-1.toml"
"#
            ),
        )
        .unwrap();
        fs::write(
            pack_dir.join("rules/rule-1.toml"),
            format!(
                r#"
schema_version = 1
id = "{pack_id}.rule"
name = "Rule"
category = "Cache"
risk = "Low"
enabled = true

[match]
mode = "Paths"
paths = ["~/Library/Caches"]
strategy = "Recursive"
command = []
parser = ""

[action]
action_type = "{action_type}"
paths = ["~/Library/Caches"]
{command_block}
mode = "Confirm"
timeout_sec = 30
allow_globs = false
max_items = 100
package_manager = ""
project_types = []
{params_block}
"#
            ),
        )
        .unwrap();
    }

    fn locked_plugin(pack_id: &str) -> LockedPlugin {
        LockedPlugin {
            pack_id: pack_id.to_string(),
            source: "registry".to_string(),
            url: format!("https://example.com/{pack_id}"),
            rev: "0123456789abcdef0123456789abcdef01234567".to_string(),
            resolved_rev: None,
            version: "1.0.0".to_string(),
            manifest_hash: "sha256:a".to_string(),
            signature: "sha256:b".to_string(),
            trusted_identity: "https://example.com/workflow".to_string(),
        }
    }

    #[test]
    fn resolves_descriptors_from_installed_packs() {
        let temp = tempfile::tempdir().unwrap();
        build_pack(temp.path(), "preen-rs.cleanup.base", "TrashPaths", None);
        build_pack(
            temp.path(),
            "preen-rs.performance.base",
            "OptimizeSystem",
            None,
        );

        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![
                locked_plugin("preen-rs.cleanup.base"),
                locked_plugin("preen-rs.performance.base"),
            ],
        };

        let descriptors = resolve_descriptors_from_lockfile(temp.path(), &lockfile).unwrap();
        let cleanup = descriptors
            .iter()
            .find(|item| {
                item.pack_id == "preen-rs.cleanup.base"
                    && item.capability == SmartCareCapability::Cleanup
            })
            .unwrap();
        let performance = descriptors
            .iter()
            .find(|item| {
                item.pack_id == "preen-rs.performance.base"
                    && item.capability == SmartCareCapability::Performance
            })
            .unwrap();

        assert_eq!(
            cleanup.trusted_identity.as_deref(),
            Some("https://example.com/workflow")
        );
        assert_eq!(
            performance.trusted_identity.as_deref(),
            Some("https://example.com/workflow")
        );
    }

    #[test]
    fn resolves_all_capability_descriptors_for_smart_care_base_packs() {
        let temp = tempfile::tempdir().unwrap();
        build_pack(temp.path(), "preen-rs.cleanup.base", "TrashPaths", None);
        build_pack(
            temp.path(),
            "preen-rs.performance.base",
            "OptimizeSystem",
            None,
        );
        build_pack(
            temp.path(),
            "preen-rs.applications.base",
            "AppUninstall",
            None,
        );
        build_pack(
            temp.path(),
            "preen-rs.protection.base",
            "RunCommand",
            Some("protection"),
        );

        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![
                locked_plugin("preen-rs.cleanup.base"),
                locked_plugin("preen-rs.performance.base"),
                locked_plugin("preen-rs.applications.base"),
                locked_plugin("preen-rs.protection.base"),
            ],
        };

        let descriptors = resolve_descriptors_from_lockfile(temp.path(), &lockfile).unwrap();

        assert!(descriptors.iter().any(|item| {
            item.pack_id == "preen-rs.cleanup.base"
                && item.capability == SmartCareCapability::Cleanup
        }));
        assert!(descriptors.iter().any(|item| {
            item.pack_id == "preen-rs.performance.base"
                && item.capability == SmartCareCapability::Performance
        }));
        assert!(descriptors.iter().any(|item| {
            item.pack_id == "preen-rs.applications.base"
                && item.capability == SmartCareCapability::Applications
        }));
        assert!(descriptors.iter().any(|item| {
            item.pack_id == "preen-rs.protection.base"
                && item.capability == SmartCareCapability::Protection
        }));
    }

    #[test]
    fn resolves_from_dev_root_when_state_plugin_is_missing() {
        let state = tempfile::tempdir().unwrap();
        fs::create_dir_all(state.path().join("plugins")).unwrap();
        let dev = tempfile::tempdir().unwrap();
        build_pack_at(
            &dev.path().join("preen-rs.cleanup.base"),
            "preen-rs.cleanup.base",
            "TrashPaths",
            None,
        );

        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![locked_plugin("preen-rs.cleanup.base")],
        };

        let report = resolve_descriptors_from_lockfile_with_roots(
            state.path(),
            &lockfile,
            &[dev.path().to_path_buf()],
        )
        .unwrap();
        assert_eq!(report.descriptors.len(), 1);
        assert_eq!(
            report.descriptors[0].capability,
            SmartCareCapability::Cleanup,
            "dev fallback should resolve capability from template/worktree pack",
        );
        assert_eq!(report.loaded_from_state, 0);
        assert_eq!(report.loaded_from_dev_fallback, 1);
        assert_eq!(
            report.dev_fallback_pack_ids,
            vec!["preen-rs.cleanup.base".to_string()]
        );
    }

    #[test]
    fn skips_state_pack_when_installed_manifest_is_invalid() {
        let state = tempfile::tempdir().unwrap();
        let state_pack_dir = state.path().join("plugins").join("preen-rs.cleanup.base");
        fs::create_dir_all(&state_pack_dir).unwrap();
        fs::write(state_pack_dir.join("manifest.toml"), "invalid = [").unwrap();

        let dev = tempfile::tempdir().unwrap();
        build_pack_at(
            &dev.path().join("preen-rs.cleanup.base"),
            "preen-rs.cleanup.base",
            "TrashPaths",
            None,
        );

        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![locked_plugin("preen-rs.cleanup.base")],
        };

        let report = resolve_descriptors_from_lockfile_with_roots(
            state.path(),
            &lockfile,
            &[dev.path().to_path_buf()],
        )
        .unwrap();
        assert!(
            report.descriptors.is_empty(),
            "invalid installed state pack should be skipped",
        );
        assert_eq!(report.loaded_from_state, 0);
        assert_eq!(report.loaded_from_dev_fallback, 0);
        assert_eq!(
            report.skipped_plugins,
            vec!["preen-rs.cleanup.base".to_string()]
        );
        assert_eq!(
            report.source_summary(),
            "state-only (packs=0) | skipped=1",
            "summary should include skipped plugins",
        );
    }

    #[test]
    fn skips_plugin_when_pack_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("plugins")).unwrap();
        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![LockedPlugin {
                pack_id: "preen-rs.missing".to_string(),
                source: "registry".to_string(),
                url: "https://example.com/missing".to_string(),
                rev: "0123456789abcdef0123456789abcdef01234567".to_string(),
                resolved_rev: None,
                version: "1.0.0".to_string(),
                manifest_hash: "sha256:a".to_string(),
                signature: "sha256:b".to_string(),
                trusted_identity: "https://example.com/workflow".to_string(),
            }],
        };

        let report = resolve_descriptors_from_lockfile_with_report(temp.path(), &lockfile).unwrap();
        assert!(
            report.descriptors.is_empty(),
            "missing plugin should be skipped, not fail the whole resolution",
        );
        assert_eq!(report.skipped_plugins, vec!["preen-rs.missing".to_string()]);
        assert_eq!(report.source_summary(), "state-only (packs=0) | skipped=1");
    }

    #[test]
    fn source_summary_is_state_only_when_no_dev_fallback_is_used() {
        let temp = tempfile::tempdir().unwrap();
        build_pack(temp.path(), "preen-rs.cleanup.base", "TrashPaths", None);
        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![locked_plugin("preen-rs.cleanup.base")],
        };

        let report = resolve_descriptors_from_lockfile_with_report(temp.path(), &lockfile).unwrap();
        assert_eq!(report.source_summary(), "state-only (packs=1)");
    }

    #[test]
    fn resolves_from_state_dir_with_default_plugins_lock() {
        let temp = tempfile::tempdir().unwrap();
        build_pack(temp.path(), "preen-rs.cleanup.base", "TrashPaths", None);
        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![locked_plugin("preen-rs.cleanup.base")],
        };
        fs::write(
            temp.path().join(DEFAULT_PLUGIN_LOCKFILE_NAME),
            lockfile.to_string().unwrap(),
        )
        .unwrap();

        let descriptors = resolve_descriptors_from_state_dir(temp.path()).unwrap();
        assert_eq!(descriptors.len(), 1);
    }

    #[test]
    fn resolves_from_state_dir_with_legacy_lockfile_fallback() {
        let temp = tempfile::tempdir().unwrap();
        build_pack(temp.path(), "preen-rs.cleanup.base", "TrashPaths", None);
        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![locked_plugin("preen-rs.cleanup.base")],
        };
        fs::write(
            temp.path().join(LEGACY_PLUGIN_LOCKFILE_NAME),
            lockfile.to_string().unwrap(),
        )
        .unwrap();

        let descriptors = resolve_descriptors_from_state_dir(temp.path()).unwrap();
        assert_eq!(descriptors.len(), 1);
    }

    #[test]
    fn resolves_from_state_dir_by_scanning_plugins_dir_when_lockfile_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        build_pack(temp.path(), "preen-rs.cleanup.base", "TrashPaths", None);

        let report = resolve_descriptors_with_report_from_state_dir(temp.path()).unwrap();
        assert_eq!(report.source, DescriptorSource::PluginsDirScan);
        assert_eq!(report.source_summary(), "plugins-scan (packs=1)");
        assert_eq!(report.descriptors.len(), 1);
        assert_eq!(
            report.descriptors[0].capability,
            SmartCareCapability::Cleanup
        );
    }

    #[test]
    fn plugins_scan_fallback_returns_empty_report_when_plugins_dir_is_missing() {
        let temp = tempfile::tempdir().unwrap();

        let report = resolve_descriptors_with_report_from_state_dir(temp.path()).unwrap();
        assert_eq!(report.source, DescriptorSource::PluginsDirScan);
        assert_eq!(report.source_summary(), "plugins-scan (packs=0)");
        assert!(report.descriptors.is_empty());
    }

    #[test]
    fn supplements_lockfile_report_with_plugins_scan_entries_when_lockfile_is_stale() {
        let temp = tempfile::tempdir().unwrap();
        build_pack(
            temp.path(),
            "preen-rs.performance.base",
            "OptimizeSystem",
            None,
        );
        build_pack(temp.path(), "preen-rs.cleanup.base", "TrashPaths", None);

        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![locked_plugin("preen-rs.performance.base")],
        };
        fs::write(
            temp.path().join(DEFAULT_PLUGIN_LOCKFILE_NAME),
            lockfile.to_string().unwrap(),
        )
        .unwrap();

        let report = resolve_descriptors_with_report_from_state_dir(temp.path()).unwrap();
        assert_eq!(report.source, DescriptorSource::Lockfile);
        assert_eq!(report.loaded_from_state, 1);
        assert_eq!(report.loaded_from_plugins_scan, 1);
        assert!(
            report
                .descriptors
                .iter()
                .any(|item| item.pack_id == "preen-rs.cleanup.base")
        );
        assert!(report.source_summary().contains("plugins-scan-extra=1"));
    }

    #[test]
    fn does_not_count_plugins_scan_extra_when_same_pack_exists_in_lockfile() {
        let temp = tempfile::tempdir().unwrap();
        build_pack(temp.path(), "preen-rs.cleanup.base", "TrashPaths", None);

        let lockfile = PluginLockfile {
            schema_version: 1,
            plugins: vec![locked_plugin("preen-rs.cleanup.base")],
        };
        fs::write(
            temp.path().join(DEFAULT_PLUGIN_LOCKFILE_NAME),
            lockfile.to_string().unwrap(),
        )
        .unwrap();

        let report = resolve_descriptors_with_report_from_state_dir(temp.path()).unwrap();
        assert_eq!(report.source, DescriptorSource::Lockfile);
        assert_eq!(report.loaded_from_state, 1);
        assert_eq!(report.loaded_from_plugins_scan, 0);
        assert_eq!(report.source_summary(), "state-only (packs=1)");
    }
}
