use std::sync::Arc;

use preen_core::FileSystemPort;
use preen_os::OsFileSystemAdapter;
use preen_os::store::EncryptedStore;

#[tokio::test]
async fn metrics_env_stdout_no_panic() {
    unsafe {
        std::env::set_var("PREEN_METRICS", "stdout");
        std::env::set_var(
            "PREEN_STORE_KEY_HEX",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }
    let tmp = tempfile::tempdir().unwrap();
    let store = EncryptedStore::new(tmp.path().to_path_buf());
    let adapter = OsFileSystemAdapter::new(Arc::new(store));
    let _ = adapter
        .scan_cleanable_items(&[], &preen_core::config::AppConfig::default())
        .await;
    unsafe {
        std::env::remove_var("PREEN_METRICS");
    }
}
