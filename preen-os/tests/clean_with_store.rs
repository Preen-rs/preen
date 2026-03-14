use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use preen_core::FileSystemPort;
use preen_core::store::{ItemRecord, ScanStorePort};
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
async fn clean_items_deletes_file() {
    let tmp = tempfile::tempdir().unwrap();
    let adapter = new_adapter(&tmp);
    let store = preen_os::store::EncryptedStore::new(tmp.path().to_path_buf());

    let test_file = PathBuf::from("/tmp/preen_clean_test.txt");
    fs::write(&test_file, "content").unwrap();

    let item = ItemRecord {
        item_id: "item-1".to_string(),
        scan_id: "scan-1".to_string(),
        path: test_file.clone(),
        size: 7,
        can_undo: false,
        undo_info: None,
        deleted: false,
    };

    store.save_items(&[item]).await.unwrap();

    let freed = adapter.clean_items(&["item-1".to_string()]).await.unwrap();
    assert_eq!(freed, 7);
    assert!(!test_file.exists());
}
