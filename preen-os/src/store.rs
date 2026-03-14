use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use chrono::Local;
use keyring::Entry;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::env;

use preen_core::ScanResult;
use preen_core::error::CoreError;
use preen_core::store::{ItemRecord, ScanRecord, ScanStorePort};

use crate::OsError;

pub struct EncryptedStore {
    base_dir: PathBuf,
}

const STORE_MAGIC: &[u8; 8] = b"PREENSTR";
const STORE_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
enum StoreRecord {
    Scan(ScanRecord),
    Item(ItemRecord),
}

impl EncryptedStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    fn store_path(&self) -> PathBuf {
        self.base_dir.join("preen.store")
    }

    fn ensure_dir(&self) -> Result<(), OsError> {
        fs::create_dir_all(&self.base_dir).map_err(|e| OsError::Io {
            path: self.base_dir.to_string_lossy().to_string(),
            source: e,
        })
    }

    fn load_key(&self) -> Result<Vec<u8>, OsError> {
        if let Ok(key_hex) = env::var("PREEN_STORE_KEY_HEX") {
            return hex::decode(key_hex).map_err(|e| OsError::Store {
                message: format!("invalid key hex: {e}"),
            });
        }
        let entry = Entry::new("preen", "store_key").map_err(|e| OsError::Store {
            message: e.to_string(),
        })?;
        if let Ok(existing) = entry.get_password() {
            return hex::decode(existing).map_err(|e| OsError::Store {
                message: format!("invalid key hex: {e}"),
            });
        }
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let key_hex = hex::encode(&key);
        entry.set_password(&key_hex).map_err(|e| OsError::Store {
            message: e.to_string(),
        })?;
        Ok(key)
    }

    fn encrypt_record(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OsError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| OsError::Store {
            message: e.to_string(),
        })?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| OsError::Store {
                message: e.to_string(),
            })?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn append_record(&self, bytes: &[u8]) -> Result<(), OsError> {
        self.ensure_dir()?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.store_path())
            .map_err(|e| OsError::Io {
                path: self.store_path().to_string_lossy().to_string(),
                source: e,
            })?;
        if file
            .metadata()
            .map_err(|e| OsError::Io {
                path: self.store_path().to_string_lossy().to_string(),
                source: e,
            })?
            .len()
            == 0
        {
            file.write_all(STORE_MAGIC).map_err(|e| OsError::Io {
                path: self.store_path().to_string_lossy().to_string(),
                source: e,
            })?;
            file.write_all(&[STORE_VERSION]).map_err(|e| OsError::Io {
                path: self.store_path().to_string_lossy().to_string(),
                source: e,
            })?;
        }
        let len = bytes.len() as u32;
        file.write_all(&len.to_le_bytes())
            .map_err(|e| OsError::Io {
                path: self.store_path().to_string_lossy().to_string(),
                source: e,
            })?;
        file.write_all(bytes).map_err(|e| OsError::Io {
            path: self.store_path().to_string_lossy().to_string(),
            source: e,
        })
    }

    fn maybe_compact(&self, key: &[u8]) -> Result<bool, OsError> {
        let threshold = env::var("PREEN_STORE_COMPACT_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5 * 1024 * 1024);
        let size = fs::metadata(self.store_path())
            .map(|m| m.len())
            .unwrap_or(0);
        if size < threshold {
            return Ok(false);
        }
        let records = self.decrypt_records(key)?;
        let mut latest_scans = std::collections::HashMap::new();
        let mut latest_items = std::collections::HashMap::new();
        for record in records {
            match &record {
                StoreRecord::Scan(scan) => {
                    latest_scans.insert(scan.scan_id.clone(), record);
                }
                StoreRecord::Item(item) => {
                    latest_items.insert(item.item_id.clone(), record);
                }
            }
        }
        let mut compacted = Vec::new();
        compacted.extend(latest_scans.into_values());
        compacted.extend(latest_items.into_values());
        self.rewrite_records(key, &compacted)?;
        if env::var("PREEN_METRICS").ok().as_deref() == Some("stdout") {
            println!("[metrics] store.compaction = 1");
        }
        Ok(true)
    }

    fn rewrite_records(&self, key: &[u8], records: &[StoreRecord]) -> Result<(), OsError> {
        self.ensure_dir()?;
        let mut file = fs::File::create(self.store_path()).map_err(|e| OsError::Io {
            path: self.store_path().to_string_lossy().to_string(),
            source: e,
        })?;
        file.write_all(STORE_MAGIC).map_err(|e| OsError::Io {
            path: self.store_path().to_string_lossy().to_string(),
            source: e,
        })?;
        file.write_all(&[STORE_VERSION]).map_err(|e| OsError::Io {
            path: self.store_path().to_string_lossy().to_string(),
            source: e,
        })?;
        for record in records {
            let bytes = bincode::serialize(record).map_err(|e| OsError::Store {
                message: e.to_string(),
            })?;
            let encrypted = self.encrypt_record(key, &bytes)?;
            let len = encrypted.len() as u32;
            file.write_all(&len.to_le_bytes())
                .map_err(|e| OsError::Io {
                    path: self.store_path().to_string_lossy().to_string(),
                    source: e,
                })?;
            file.write_all(&encrypted).map_err(|e| OsError::Io {
                path: self.store_path().to_string_lossy().to_string(),
                source: e,
            })?;
        }
        Ok(())
    }

    fn decrypt_records(&self, key: &[u8]) -> Result<Vec<StoreRecord>, OsError> {
        if !self.store_path().exists() {
            return Ok(Vec::new());
        }
        let mut file = fs::File::open(self.store_path()).map_err(|e| OsError::Io {
            path: self.store_path().to_string_lossy().to_string(),
            source: e,
        })?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic).map_err(|e| OsError::Io {
            path: self.store_path().to_string_lossy().to_string(),
            source: e,
        })?;
        if &magic != STORE_MAGIC {
            return Err(OsError::Store {
                message: "invalid store magic".to_string(),
            });
        }
        let mut version = [0u8; 1];
        file.read_exact(&mut version).map_err(|e| OsError::Io {
            path: self.store_path().to_string_lossy().to_string(),
            source: e,
        })?;
        if version[0] != STORE_VERSION {
            return Err(OsError::Store {
                message: "unsupported store version".to_string(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| OsError::Store {
            message: e.to_string(),
        })?;
        let mut records = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            if file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).map_err(|e| OsError::Io {
                path: self.store_path().to_string_lossy().to_string(),
                source: e,
            })?;
            if buf.len() < 12 {
                return Err(OsError::Store {
                    message: "invalid record length".to_string(),
                });
            }
            let (nonce_bytes, ciphertext) = buf.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);
            let plaintext = cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| OsError::Store {
                    message: e.to_string(),
                })?;
            let record: StoreRecord =
                bincode::deserialize(&plaintext).map_err(|e| OsError::Store {
                    message: e.to_string(),
                })?;
            records.push(record);
        }
        Ok(records)
    }

    pub fn compact_for_test(&self) -> Result<bool, String> {
        let key = self.load_key().map_err(|e| e.to_string())?;
        self.maybe_compact(&key).map_err(|e| e.to_string())
    }
}

#[async_trait]
impl ScanStorePort for EncryptedStore {
    async fn save_scan(&self, _scan_id: &str, _result: &ScanResult) -> Result<(), CoreError> {
        let key = self.load_key().map_err(|e| CoreError::Store {
            message: e.to_string(),
        })?;
        let scan = ScanRecord {
            scan_id: _scan_id.to_string(),
            timestamp: Local::now(),
            total_size: _result.total_size,
        };
        let scan_bytes =
            bincode::serialize(&StoreRecord::Scan(scan)).map_err(|e| CoreError::Store {
                message: e.to_string(),
            })?;
        let encrypted = self
            .encrypt_record(&key, &scan_bytes)
            .map_err(|e| CoreError::Store {
                message: e.to_string(),
            })?;
        self.append_record(&encrypted)
            .map_err(|e| CoreError::Store {
                message: e.to_string(),
            })?;
        for item in &_result.items {
            let record = ItemRecord {
                item_id: item.id.clone(),
                scan_id: _scan_id.to_string(),
                path: item.path.clone(),
                size: item.size,
                can_undo: item.can_undo,
                undo_info: item.undo_info.clone(),
                deleted: false,
            };
            let bytes =
                bincode::serialize(&StoreRecord::Item(record)).map_err(|e| CoreError::Store {
                    message: e.to_string(),
                })?;
            let encrypted = self
                .encrypt_record(&key, &bytes)
                .map_err(|e| CoreError::Store {
                    message: e.to_string(),
                })?;
            self.append_record(&encrypted)
                .map_err(|e| CoreError::Store {
                    message: e.to_string(),
                })?;
        }
        let _ = self.maybe_compact(&key);
        Ok(())
    }

    async fn load_item(&self, _item_id: &str) -> Result<Option<ItemRecord>, CoreError> {
        let key = self.load_key().map_err(|e| CoreError::Store {
            message: e.to_string(),
        })?;
        let records = self.decrypt_records(&key).map_err(|e| CoreError::Store {
            message: e.to_string(),
        })?;
        let mut found = None;
        for record in records {
            if let StoreRecord::Item(item) = record
                && item.item_id == _item_id
            {
                found = Some(item);
            }
        }
        Ok(found)
    }

    async fn save_items(&self, items: &[ItemRecord]) -> Result<(), CoreError> {
        let key = self.load_key().map_err(|e| CoreError::Store {
            message: e.to_string(),
        })?;
        for item in items {
            let bytes = bincode::serialize(&StoreRecord::Item(item.clone())).map_err(|e| {
                CoreError::Store {
                    message: e.to_string(),
                }
            })?;
            let encrypted = self
                .encrypt_record(&key, &bytes)
                .map_err(|e| CoreError::Store {
                    message: e.to_string(),
                })?;
            self.append_record(&encrypted)
                .map_err(|e| CoreError::Store {
                    message: e.to_string(),
                })?;
        }
        let _ = self.maybe_compact(&key);
        Ok(())
    }

    async fn list_scans(&self, _limit: usize) -> Result<Vec<ScanRecord>, CoreError> {
        let key = self.load_key().map_err(|e| CoreError::Store {
            message: e.to_string(),
        })?;
        let records = self.decrypt_records(&key).map_err(|e| CoreError::Store {
            message: e.to_string(),
        })?;
        let mut scans = Vec::new();
        for record in records {
            if let StoreRecord::Scan(scan) = record {
                scans.push(scan);
            }
        }
        Ok(scans)
    }

    async fn purge_scan(&self, _scan_id: &str) -> Result<(), CoreError> {
        let key = self.load_key().map_err(|e| CoreError::Store {
            message: e.to_string(),
        })?;
        let records = self.decrypt_records(&key).map_err(|e| CoreError::Store {
            message: e.to_string(),
        })?;
        let mut filtered = Vec::new();
        for record in records {
            match &record {
                StoreRecord::Scan(scan) if scan.scan_id == _scan_id => {}
                StoreRecord::Item(item) if item.scan_id == _scan_id => {}
                _ => filtered.push(record),
            }
        }
        self.rewrite_records(&key, &filtered)
            .map_err(|e| CoreError::Store {
                message: e.to_string(),
            })?;
        Ok(())
    }
}
