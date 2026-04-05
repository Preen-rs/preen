use preen_core::plugin_lock::{LockedPlugin, LockfileError, PluginLockfile};

#[test]
fn lockfile_invalid_schema() {
    let lock = PluginLockfile {
        schema_version: 2,
        plugins: vec![],
    };
    let err = lock.validate_basic().unwrap_err();
    assert!(matches!(
        err,
        LockfileError::SchemaVersionUnsupported { .. }
    ));
}

#[test]
fn locked_plugin_missing_fields() {
    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![LockedPlugin {
            pack_id: "".to_string(),
            source: "git".to_string(),
            url: "".to_string(),
            rev: "".to_string(),
            resolved_rev: None,
            version: "0.1.0".to_string(),
            manifest_hash: "sha256:x".to_string(),
            signature: "sha256:y".to_string(),
            trusted_identity: "id".to_string(),
        }],
    };
    let err = lock.validate_basic().unwrap_err();
    assert!(matches!(err, LockfileError::MissingField { .. }));
}

#[test]
fn lockfile_duplicate_pack_id() {
    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![
            LockedPlugin {
                pack_id: "dup".to_string(),
                source: "git".to_string(),
                url: "https://example.com/a".to_string(),
                rev: "a".to_string(),
                resolved_rev: None,
                version: "0.1.0".to_string(),
                manifest_hash: "sha256:x".to_string(),
                signature: "sha256:y".to_string(),
                trusted_identity: "id".to_string(),
            },
            LockedPlugin {
                pack_id: "dup".to_string(),
                source: "git".to_string(),
                url: "https://example.com/b".to_string(),
                rev: "b".to_string(),
                resolved_rev: None,
                version: "0.2.0".to_string(),
                manifest_hash: "sha256:x".to_string(),
                signature: "sha256:y".to_string(),
                trusted_identity: "id".to_string(),
            },
        ],
    };
    let err = lock.validate_basic().unwrap_err();
    assert!(matches!(err, LockfileError::DuplicatePackId { .. }));
}

#[test]
fn lockfile_invalid_pack_id_format() {
    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![LockedPlugin {
            pack_id: "Bad.pack".to_string(),
            source: "git".to_string(),
            url: "https://example.com/a".to_string(),
            rev: "a".to_string(),
            resolved_rev: None,
            version: "0.1.0".to_string(),
            manifest_hash: "sha256:x".to_string(),
            signature: "sha256:y".to_string(),
            trusted_identity: "id".to_string(),
        }],
    };

    let err = lock.validate_basic().unwrap_err();
    assert!(matches!(err, LockfileError::InvalidPackId { .. }));
}

#[test]
fn lockfile_pack_id_path_traversal() {
    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![LockedPlugin {
            pack_id: "../dup".to_string(),
            source: "git".to_string(),
            url: "https://example.com/a".to_string(),
            rev: "a".to_string(),
            resolved_rev: None,
            version: "0.1.0".to_string(),
            manifest_hash: "sha256:x".to_string(),
            signature: "sha256:y".to_string(),
            trusted_identity: "id".to_string(),
        }],
    };

    let err = lock.validate_basic().unwrap_err();
    assert!(matches!(err, LockfileError::InvalidPackId { .. }));
}
