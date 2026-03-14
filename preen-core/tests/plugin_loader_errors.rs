use std::fs;

use preen_core::plugin_loader::{LoaderError, load_rule_pack_from_dir};

#[test]
fn missing_manifest_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let err = load_rule_pack_from_dir(tmp.path()).unwrap_err();
    assert!(matches!(err, LoaderError::Io(_)));
}

#[test]
fn missing_rule_file_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let manifest = r#"
        schema_version = 1
        pack_id = "test.pack"
        name = "Test Pack"
        version = "0.1.0"
        description = "desc"
        author = "me"
        license = "MIT"
        core_compat = ">=0.1.0,<2.0.0"
        action_api = 1
        os_targets = ["Linux"]
        capabilities = ["FsRead"]

        [[rules]]
        id = "rule-1"
        name = "Rule 1"
        rule_file = "rules/rule-1.toml"
    "#;

    fs::write(base.join("manifest.toml"), manifest).unwrap();
    let err = load_rule_pack_from_dir(base).unwrap_err();
    assert!(matches!(err, LoaderError::Io(_)));
}

#[test]
fn invalid_manifest_toml_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    fs::write(base.join("manifest.toml"), "invalid = [").unwrap();
    let err = load_rule_pack_from_dir(base).unwrap_err();
    assert!(matches!(err, LoaderError::Validation(_)));
}
