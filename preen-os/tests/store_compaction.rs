use std::sync::Arc;

use preen_core::FileSystemPort;
use preen_core::metrics::StdoutMetrics;
use preen_os::OsFileSystemAdapter;
use preen_os::store::EncryptedStore;

#[tokio::test]
async fn store_compacts_when_threshold_exceeded() {
    unsafe {
        std::env::set_var(
            "PREEN_STORE_KEY_HEX",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        std::env::set_var("PREEN_STORE_COMPACT_BYTES", "1");
    }

    let tmp = tempfile::tempdir().unwrap();
    let store = EncryptedStore::new(tmp.path().to_path_buf());
    let adapter = OsFileSystemAdapter::with_metrics(Arc::new(store), Arc::new(StdoutMetrics));

    let _ = adapter
        .scan_cleanable_items(&[], &preen_core::config::AppConfig::default())
        .await;

    let compacted = EncryptedStore::new(tmp.path().to_path_buf())
        .compact_for_test()
        .unwrap();
    assert!(compacted);

    unsafe {
        std::env::remove_var("PREEN_STORE_COMPACT_BYTES");
    }
}
