use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::plugin::validate_pack_id;

pub const REGISTRY_SCHEMA_V1: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryIndex {
    pub schema_version: u32,
    pub generated_at: Option<String>,
    pub entries: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub pack_id: String,
    pub name: String,
    pub description: String,
    pub repo_url: String,
    pub latest_version: String,
    pub versions: Vec<RegistryVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryVersion {
    pub version: String,
    pub rev: String,
    pub manifest_hash: Option<String>,
    pub trusted_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRegistryPlugin {
    pub pack_id: String,
    pub version: String,
    pub url: String,
    pub rev: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    Parse(String),
    SchemaVersionUnsupported { found: u32, expected: u32 },
    MissingField { field: String },
    InvalidPackId { pack_id: String },
    DuplicatePackId { pack_id: String },
    PackNotFound { pack_id: String },
    VersionNotFound { pack_id: String, version: String },
}

impl FromStr for RegistryIndex {
    type Err = RegistryError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let index: RegistryIndex =
            toml::from_str(input).map_err(|e| RegistryError::Parse(e.to_string()))?;
        index.validate_basic()?;
        Ok(index)
    }
}

impl RegistryIndex {
    pub fn validate_basic(&self) -> Result<(), RegistryError> {
        if self.schema_version != REGISTRY_SCHEMA_V1 {
            return Err(RegistryError::SchemaVersionUnsupported {
                found: self.schema_version,
                expected: REGISTRY_SCHEMA_V1,
            });
        }
        let mut seen = std::collections::HashSet::new();
        for entry in &self.entries {
            if entry.pack_id.trim().is_empty() {
                return Err(RegistryError::MissingField {
                    field: "entries[].pack_id".to_string(),
                });
            }
            if validate_pack_id(&entry.pack_id).is_err() {
                return Err(RegistryError::InvalidPackId {
                    pack_id: entry.pack_id.clone(),
                });
            }
            if !seen.insert(entry.pack_id.clone()) {
                return Err(RegistryError::DuplicatePackId {
                    pack_id: entry.pack_id.clone(),
                });
            }
            if entry.repo_url.trim().is_empty() {
                return Err(RegistryError::MissingField {
                    field: "entries[].repo_url".to_string(),
                });
            }
            if entry.latest_version.trim().is_empty() {
                return Err(RegistryError::MissingField {
                    field: "entries[].latest_version".to_string(),
                });
            }
            if entry.versions.is_empty() {
                return Err(RegistryError::MissingField {
                    field: "entries[].versions".to_string(),
                });
            }
            for version in &entry.versions {
                if version.version.trim().is_empty() {
                    return Err(RegistryError::MissingField {
                        field: "entries[].versions[].version".to_string(),
                    });
                }
                if version.rev.trim().is_empty() {
                    return Err(RegistryError::MissingField {
                        field: "entries[].versions[].rev".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn resolve(
        &self,
        pack_id: &str,
        requested_version: Option<&str>,
    ) -> Result<ResolvedRegistryPlugin, RegistryError> {
        let entry = self
            .entries
            .iter()
            .find(|item| item.pack_id == pack_id)
            .ok_or_else(|| RegistryError::PackNotFound {
                pack_id: pack_id.to_string(),
            })?;
        let target = requested_version.unwrap_or(&entry.latest_version);
        let version = entry
            .versions
            .iter()
            .find(|item| item.version == target)
            .ok_or_else(|| RegistryError::VersionNotFound {
                pack_id: pack_id.to_string(),
                version: target.to_string(),
            })?;
        Ok(ResolvedRegistryPlugin {
            pack_id: entry.pack_id.clone(),
            version: version.version.clone(),
            url: entry.repo_url.clone(),
            rev: version.rev.clone(),
        })
    }
}
