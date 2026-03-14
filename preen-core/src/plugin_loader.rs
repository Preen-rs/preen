use std::fs;
use std::path::{Path, PathBuf};

use crate::plugin::{Manifest, RuleFile, ValidationError, validate_ruleset};

#[derive(Debug)]
pub enum LoaderError {
    Io(String),
    InvalidPath(String),
    Validation(ValidationError),
}

#[derive(Debug)]
pub struct LoadedRulePack {
    pub manifest: Manifest,
    pub rules: Vec<RuleFile>,
    pub base_dir: PathBuf,
}

pub fn load_rule_pack_from_dir(dir: &Path) -> Result<LoadedRulePack, LoaderError> {
    if !dir.exists() || !dir.is_dir() {
        return Err(LoaderError::InvalidPath(format!(
            "invalid rule pack dir: {}",
            dir.display()
        )));
    }
    let manifest_path = dir.join("manifest.toml");
    let manifest_text =
        fs::read_to_string(&manifest_path).map_err(|e| LoaderError::Io(e.to_string()))?;
    let manifest = manifest_text
        .parse::<Manifest>()
        .map_err(LoaderError::Validation)?;
    let core_version = env!("CARGO_PKG_VERSION");
    manifest
        .validate_with_core_version(core_version)
        .map_err(LoaderError::Validation)?;

    let mut rules = Vec::with_capacity(manifest.rules.len());
    for rule_ref in &manifest.rules {
        let rule_path = dir.join(&rule_ref.rule_file);
        let rule_text =
            fs::read_to_string(&rule_path).map_err(|e| LoaderError::Io(e.to_string()))?;
        let rule = rule_text
            .parse::<RuleFile>()
            .map_err(LoaderError::Validation)?;
        rules.push(rule);
    }

    validate_ruleset(&manifest, &rules).map_err(LoaderError::Validation)?;

    Ok(LoadedRulePack {
        manifest,
        rules,
        base_dir: dir.to_path_buf(),
    })
}
