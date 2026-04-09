use preen_core::ScanResult;
use preen_core::store::{ItemRecord, ScanStorePort};
use preen_os::store::EncryptedStore;
use std::fs;

fn set_test_key() {
    unsafe {
        std::env::set_var(
            "PREEN_STORE_KEY_HEX",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }
}

#[tokio::test]
async fn save_scan_and_load_item() {
    set_test_key();
    let tmp = tempfile::tempdir().unwrap();
    let store = EncryptedStore::new(tmp.path().to_path_buf());

    let result = ScanResult {
        executed_rules: vec![],
        total_size: 10,
        items: vec![preen_core::CleanableItem {
            rule_id: "r1".to_string(),
            id: "item-1".to_string(),
            category: preen_core::ItemCategory::Cache,
            path: "/tmp/item-1".into(),
            size: 10,
            description: "d".to_string(),
            can_undo: true,
            undo_info: None,
        }],
    };

    store.save_scan("scan-1", &result).await.unwrap();
    let item = store.load_item("item-1").await.unwrap().unwrap();
    assert_eq!(item.item_id, "item-1");
    assert!(!item.deleted);
}

#[tokio::test]
async fn save_items_updates_deleted_flag() {
    set_test_key();
    let tmp = tempfile::tempdir().unwrap();
    let store = EncryptedStore::new(tmp.path().to_path_buf());

    let item = ItemRecord {
        item_id: "item-2".to_string(),
        scan_id: "scan-1".to_string(),
        path: "/tmp/item-2".into(),
        size: 1,
        can_undo: false,
        undo_info: None,
        deleted: false,
    };
    store.save_items(&[item]).await.unwrap();

    let updated = ItemRecord {
        item_id: "item-2".to_string(),
        scan_id: "scan-1".to_string(),
        path: "/tmp/item-2".into(),
        size: 1,
        can_undo: false,
        undo_info: None,
        deleted: true,
    };
    store.save_items(&[updated]).await.unwrap();

    let item = store.load_item("item-2").await.unwrap().unwrap();
    assert!(item.deleted);
}

#[tokio::test]
async fn purge_scan_removes_records() {
    set_test_key();
    let tmp = tempfile::tempdir().unwrap();
    let store = EncryptedStore::new(tmp.path().to_path_buf());

    let result = ScanResult {
        executed_rules: vec![],
        total_size: 0,
        items: vec![preen_core::CleanableItem {
            rule_id: "r1".to_string(),
            id: "item-3".to_string(),
            category: preen_core::ItemCategory::Cache,
            path: "/tmp/item-3".into(),
            size: 0,
            description: "d".to_string(),
            can_undo: false,
            undo_info: None,
        }],
    };

    store.save_scan("scan-2", &result).await.unwrap();
    store.purge_scan("scan-2").await.unwrap();

    let item = store.load_item("item-3").await.unwrap();
    assert!(item.is_none());
    let scans = store.list_scans(10).await.unwrap();
    assert!(scans.is_empty());
}

#[tokio::test]
async fn invalid_store_magic_fails() {
    set_test_key();
    let tmp = tempfile::tempdir().unwrap();
    let store_path = tmp.path().join("preen.store");
    fs::write(&store_path, b"BADMAGIC").unwrap();

    let store = EncryptedStore::new(tmp.path().to_path_buf());
    let err = store.list_scans(10).await.unwrap_err();
    assert!(err.to_string().contains("invalid store magic"));
}

#[tokio::test]
async fn invalid_store_version_fails() {
    set_test_key();
    let tmp = tempfile::tempdir().unwrap();
    let store_path = tmp.path().join("preen.store");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PREENSTR");
    bytes.push(99);
    fs::write(&store_path, bytes).unwrap();

    let store = EncryptedStore::new(tmp.path().to_path_buf());
    let err = store.list_scans(10).await.unwrap_err();
    assert!(err.to_string().contains("unsupported store version"));
}

#[tokio::test]
async fn invalid_store_truncated_record_header_fails() {
    set_test_key();
    let tmp = tempfile::tempdir().unwrap();
    let store_path = tmp.path().join("preen.store");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PREENSTR");
    bytes.push(1);
    bytes.extend_from_slice(&[0x01, 0x02, 0x03]);
    fs::write(&store_path, bytes).unwrap();

    let store = EncryptedStore::new(tmp.path().to_path_buf());
    let err = store.list_scans(10).await.unwrap_err();
    assert!(err.to_string().contains("invalid record header length"));
}
