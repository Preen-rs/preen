use std::sync::Arc;

use preen_core::FileSystemPort;
use preen_core::config::AppConfig;
use preen_core::rules::ScanRule;
use preen_os::OsFileSystemAdapter;
use preen_os::store::EncryptedStore;

#[tokio::test]
async fn scan_saves_to_store() {
    let tmp = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var(
            "PREEN_STORE_KEY_HEX",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }
    let store = EncryptedStore::new(tmp.path().to_path_buf());
    let adapter = OsFileSystemAdapter::new(Arc::new(store));
    let rules: Vec<ScanRule> = vec![];
    let _ = adapter
        .scan_cleanable_items(&rules, &AppConfig::default())
        .await;
}
