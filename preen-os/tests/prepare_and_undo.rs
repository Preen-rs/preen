use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use preen_core::CleanableItem;
use preen_core::FileSystemPort;
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
async fn prepare_clean_moves_to_trash() {
    if cfg!(target_os = "macos") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let adapter = new_adapter(&tmp);
    let test_file_path = PathBuf::from("/tmp/preen_test_file_to_trash.txt");
    fs::write(&test_file_path, "some content").unwrap();

    let item = CleanableItem {
        rule_id: "test".to_string(),
        id: "1".to_string(),
        category: preen_core::ItemCategory::Other("test".to_string()),
        path: test_file_path.clone(),
        size: 12,
        description: "Test file for trash".to_string(),
        can_undo: true,
        undo_info: None,
    };

    let prepared_items = adapter
        .prepare_clean(std::slice::from_ref(&item))
        .await
        .unwrap();
    assert!(!prepared_items.is_empty());
    assert!(prepared_items[0].undo_info.is_some());
    assert!(!test_file_path.exists());
}
