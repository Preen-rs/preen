use std::fs;

use preen_core::plugin_loader::load_rule_pack_from_dir;

#[test]
fn load_minimal_pack() {
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

    let rule = r#"
        schema_version = 1
        id = "rule-1"
        name = "Rule 1"
        category = "Cache"
        risk = "Low"
        enabled = true

        [match]
        mode = "Paths"
        paths = ["/tmp"]
        strategy = "Recursive"
        command = []

        [action]
        action_type = "TrashPaths"
        paths = ["/tmp"]
        command = []
        mode = "Confirm"
        timeout_sec = 60
        allow_globs = false
        max_items = 100
        package_manager = ""
        project_types = []
        params = {}
    "#;

    fs::create_dir_all(base.join("rules")).unwrap();
    fs::write(base.join("manifest.toml"), manifest).unwrap();
    fs::write(base.join("rules/rule-1.toml"), rule).unwrap();

    let loaded = load_rule_pack_from_dir(base).unwrap();
    assert_eq!(loaded.rules.len(), 1);
    assert_eq!(loaded.manifest.pack_id, "test.pack");
}
