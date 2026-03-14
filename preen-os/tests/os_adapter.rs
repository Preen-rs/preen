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
async fn scan_cleanable_items() {
    let tmp = tempfile::tempdir().unwrap();
    let adapter = new_adapter(&tmp);
    let config = AppConfig::default();
    let rules = vec![
        ScanRule {
            id: "test-cache".to_string(),
            name: "Test Rule".to_string(),
            category: ItemCategory::Cache,
            path_pattern: "/tmp/preen_test_cache".to_string(),
            strategy: ScanStrategy::Recursive,
            description: "Temporary cache files for testing".to_string(),
        },
        ScanRule {
            id: "test-logs".to_string(),
            name: "Test Logs".to_string(),
            category: ItemCategory::Logs,
            path_pattern: "/tmp/preen_test_logs".to_string(),
            strategy: ScanStrategy::Shallow,
            description: "Temporary log files for testing".to_string(),
        },
    ];

    let cache_dir = PathBuf::from("/tmp/preen_test_cache");
    let log_dir = PathBuf::from("/tmp/preen_test_logs");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::create_dir_all(&log_dir).unwrap();
    fs::write(cache_dir.join("file1.tmp"), "content").unwrap();
    fs::create_dir_all(cache_dir.join("subdir")).unwrap();
    fs::write(cache_dir.join("subdir/file2.tmp"), "content").unwrap();
    fs::write(log_dir.join("log.txt"), "log content").unwrap();

    let result = adapter.scan_cleanable_items(&rules, &config).await.unwrap();
    assert!(!result.items.is_empty());
    assert!(result.total_size > 0);

    fs::remove_dir_all(&cache_dir).unwrap();
    fs::remove_dir_all(&log_dir).unwrap();
}

#[tokio::test]
async fn scan_with_regex_strategy() {
    let tmp = tempfile::tempdir().unwrap();
    let adapter = new_adapter(&tmp);
    let config = AppConfig {
        ignore_list: vec![],
        ..AppConfig::default()
    };

    let test_dir = PathBuf::from("/tmp/preen_regex_test");
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("match_this.log"), "content").unwrap();
    fs::write(test_dir.join("ignore_this.txt"), "content").unwrap();

    let rules = vec![ScanRule {
        id: "regex-rule".to_string(),
        name: "Regex Test".to_string(),
        category: ItemCategory::Logs,
        path_pattern: test_dir.to_string_lossy().to_string(),
        strategy: ScanStrategy::Regex(".*\\.log$".to_string()),
        description: "Finds .log files".to_string(),
    }];

    let result = adapter.scan_cleanable_items(&rules, &config).await.unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].path.file_name().unwrap(), "match_this.log");

    fs::remove_dir_all(&test_dir).unwrap();
}

#[tokio::test]
async fn scan_with_older_than_days_strategy() {
    let tmp = tempfile::tempdir().unwrap();
    let adapter = new_adapter(&tmp);
    let config = AppConfig {
        ignore_list: vec![],
        ..AppConfig::default()
    };

    let test_dir = PathBuf::from("/tmp/preen_old_files_test");
    fs::create_dir_all(&test_dir).unwrap();

    let old_file = test_dir.join("old_file.txt");
    fs::write(&old_file, "old content").unwrap();

    let rules = vec![ScanRule {
        id: "older-than-1-day".to_string(),
        name: "Older than 1 day".to_string(),
        category: ItemCategory::TemporaryFiles,
        path_pattern: test_dir.to_string_lossy().to_string(),
        strategy: ScanStrategy::OlderThanDays(1),
        description: "Finds files older than 1 day".to_string(),
    }];

    let result = adapter.scan_cleanable_items(&rules, &config).await.unwrap();
    assert!(result.items.is_empty());

    fs::remove_dir_all(&test_dir).unwrap();
}
