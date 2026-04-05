use std::collections::HashSet;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::plugin::validate_pack_id;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLockfile {
    pub schema_version: u32,
    pub plugins: Vec<LockedPlugin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedPlugin {
    pub pack_id: String,
    pub source: String,
    pub url: String,
    pub rev: String,
    #[serde(default)]
    pub resolved_rev: Option<String>,
    pub version: String,
    pub manifest_hash: String,
    pub signature: String,
    pub trusted_identity: String,
}

impl LockedPlugin {
    pub fn validate_basic(&self) -> Result<(), LockfileError> {
        if self.pack_id.trim().is_empty() {
            return Err(LockfileError::MissingField {
                field: "plugins[].pack_id".to_string(),
            });
        }
        if validate_pack_id(&self.pack_id).is_err() {
            return Err(LockfileError::InvalidPackId {
                pack_id: self.pack_id.clone(),
            });
        }
        if self.url.trim().is_empty() {
            return Err(LockfileError::MissingField {
                field: "plugins[].url".to_string(),
            });
        }
        if self.rev.trim().is_empty() {
            return Err(LockfileError::MissingField {
                field: "plugins[].rev".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockfileError {
    SchemaVersionUnsupported { found: u32, expected: u32 },
    MissingField { field: String },
    InvalidPackId { pack_id: String },
    DuplicatePackId { pack_id: String },
    Parse(String),
}

impl PluginLockfile {
    pub const SCHEMA_V1: u32 = 1;

    pub fn validate_basic(&self) -> Result<(), LockfileError> {
        if self.schema_version != Self::SCHEMA_V1 {
            return Err(LockfileError::SchemaVersionUnsupported {
                found: self.schema_version,
                expected: Self::SCHEMA_V1,
            });
        }
        let mut seen = HashSet::new();
        for plugin in &self.plugins {
            plugin.validate_basic()?;
            if !seen.insert(plugin.pack_id.clone()) {
                return Err(LockfileError::DuplicatePackId {
                    pack_id: plugin.pack_id.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn to_string(&self) -> Result<String, LockfileError> {
        self.validate_basic()?;
        toml::to_string(self).map_err(|e| LockfileError::Parse(e.to_string()))
    }
}

impl FromStr for PluginLockfile {
    type Err = LockfileError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let lock: PluginLockfile =
            toml::from_str(input).map_err(|e| LockfileError::Parse(e.to_string()))?;
        lock.validate_basic()?;
        Ok(lock)
    }
}
