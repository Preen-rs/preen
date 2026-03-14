use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use preen_core::CleanableItem;
use preen_core::FileSystemPort;
use preen_os::OsFileSystemAdapter;
use preen_os::store::EncryptedStore;

#[tokio::test]
async fn undo_restores_file_on_macos() {
    if !cfg!(target_os = "macos") {
        return;
    }
    if std::env::var("PREEN_ENABLE_TRASH_TESTS").ok().as_deref() != Some("1") {
        return;
    }
    unsafe {
        std::env::set_var(
            "PREEN_STORE_KEY_HEX",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }
    let tmp = tempfile::tempdir().unwrap();
    let store = EncryptedStore::new(tmp.path().to_path_buf());
    let adapter = OsFileSystemAdapter::new(Arc::new(store));

    let test_file_path = PathBuf::from("/tmp/preen_undo_macos.txt");
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
    assert!(!test_file_path.exists());

    adapter.undo_clean(&prepared_items).await.unwrap();
    assert!(test_file_path.exists());

    fs::remove_file(&test_file_path).unwrap();
}
