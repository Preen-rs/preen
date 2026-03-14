use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use preen_core::FileSystemPort;
use preen_core::ItemCategory;
use preen_core::config::AppConfig;
use preen_core::rules::{ScanRule, ScanStrategy};
use preen_os::OsFileSystemAdapter;
use preen_os::store::EncryptedStore;

fn new_adapter(tmp: &tempfile::TempDir) -> OsFileSystemAdapter {
    unsafe {
        std::env::set_var(
            "PREEN_STORE_KEY_HEX",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }
    let store = EncryptedStore::new(tmp.path().to_path_buf());
    OsFileSystemAdapter::new(Arc::new(store))
}

#[tokio::test]
async fn allowlist_blocks_non_allowed_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let adapter = new_adapter(&tmp);

    let test_dir = PathBuf::from("/tmp/preen_allowlist_test");
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("file.txt"), "content").unwrap();

    let config = AppConfig {
        allowlist: vec!["/nonexistent".to_string()],
        ..AppConfig::default()
    };

    let rules = vec![ScanRule {
        id: "allowlist".to_string(),
        name: "Allowlist".to_string(),
        category: ItemCategory::Cache,
        path_pattern: test_dir.to_string_lossy().to_string(),
        strategy: ScanStrategy::Recursive,
        description: "Test".to_string(),
    }];

    let result = adapter.scan_cleanable_items(&rules, &config).await.unwrap();
    assert!(result.items.is_empty());

    fs::remove_dir_all(&test_dir).unwrap();
}

#[tokio::test]
async fn max_depth_limits_results() {
    let tmp = tempfile::tempdir().unwrap();
    let adapter = new_adapter(&tmp);

    let test_dir = PathBuf::from("/tmp/preen_depth_test");
    fs::create_dir_all(test_dir.join("a/b")).unwrap();
    fs::write(test_dir.join("a/b/file.txt"), "content").unwrap();

    let config = AppConfig {
        max_scan_depth: Some(0),
        ..AppConfig::default()
    };

    let rules = vec![ScanRule {
        id: "depth".to_string(),
        name: "Depth".to_string(),
        category: ItemCategory::Cache,
        path_pattern: test_dir.to_string_lossy().to_string(),
        strategy: ScanStrategy::Recursive,
        description: "Test".to_string(),
    }];

    let result = adapter.scan_cleanable_items(&rules, &config).await.unwrap();
    assert_eq!(result.items.len(), 1);
    assert!(result.items[0].path == test_dir);

    fs::remove_dir_all(&test_dir).unwrap();
}
