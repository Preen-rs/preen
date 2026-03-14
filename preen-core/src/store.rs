use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::ScanResult;
use crate::error::CoreError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRecord {
    pub scan_id: String,
    pub timestamp: DateTime<Local>,
    pub total_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRecord {
    pub item_id: String,
    pub scan_id: String,
    pub path: PathBuf,
    pub size: u64,
    pub can_undo: bool,
    pub undo_info: Option<String>,
    pub deleted: bool,
}

#[async_trait]
pub trait ScanStorePort: Send + Sync {
    async fn save_scan(&self, scan_id: &str, result: &ScanResult) -> Result<(), CoreError>;
    async fn load_item(&self, item_id: &str) -> Result<Option<ItemRecord>, CoreError>;
    async fn save_items(&self, items: &[ItemRecord]) -> Result<(), CoreError>;
    async fn list_scans(&self, limit: usize) -> Result<Vec<ScanRecord>, CoreError>;
    async fn purge_scan(&self, scan_id: &str) -> Result<(), CoreError>;
}
