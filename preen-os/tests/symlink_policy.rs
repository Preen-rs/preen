use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use preen_core::FileSystemPort;
use preen_core::ItemCategory;
use preen_core::config::AppConfig;
use preen_core::rules::{ScanRule, ScanStrategy};
use preen_os::OsFileSystemAdapter;
use preen_os::store::EncryptedStore;

#[cfg(unix)]
use std::os::unix::fs::symlink;

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
async fn symlink_follow_policy() {
    if !cfg!(unix) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let adapter = new_adapter(&tmp);

    let real_dir = PathBuf::from("/tmp/preen_symlink_real");
    let link_dir = PathBuf::from("/tmp/preen_symlink_link");
    fs::create_dir_all(&real_dir).unwrap();
    fs::write(real_dir.join("file.txt"), "content").unwrap();
    let _ = fs::remove_file(&link_dir);
    let _ = fs::remove_dir_all(&link_dir);
    symlink(&real_dir, &link_dir).unwrap();

    let rules = vec![ScanRule {
        id: "symlink".to_string(),
        name: "Symlink".to_string(),
        category: ItemCategory::Cache,
        path_pattern: link_dir.to_string_lossy().to_string(),
        strategy: ScanStrategy::Recursive,
        description: "Test".to_string(),
    }];

    let config = AppConfig {
        follow_symlinks: false,
        ..AppConfig::default()
    };
    let result = adapter.scan_cleanable_items(&rules, &config).await.unwrap();
    assert!(!result.items.is_empty());

    let config = AppConfig {
        follow_symlinks: true,
        ..AppConfig::default()
    };
    let result = adapter.scan_cleanable_items(&rules, &config).await.unwrap();
    assert!(!result.items.is_empty());

    fs::remove_dir_all(&real_dir).unwrap();
    let _ = fs::remove_file(&link_dir);
}
