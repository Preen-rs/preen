use std::fs;

use preen_cli::trust_policy_from_str;
use preen_core::plugin_loader::load_rule_pack_from_dir;

fn write_pack(base: &std::path::Path, signed: bool) {
    let manifest = if signed {
        r#"
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

            [signing]
            sigstore = true
            issuer = "https://token.actions.githubusercontent.com"
            identity = "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0"

            [[rules]]
            id = "rule-1"
            name = "Rule 1"
            rule_file = "rules/rule-1.toml"
        "#
    } else {
        r#"
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
        "#
    };

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
    if signed {
        fs::write(base.join("manifest.sig"), "sig").unwrap();
        fs::write(base.join("manifest.cert"), "cert").unwrap();
    }
}

#[test]
fn unsigned_pack_rejected_when_required() {
    let tmp = tempfile::tempdir().unwrap();
    write_pack(tmp.path(), false);
    let loaded = load_rule_pack_from_dir(tmp.path()).unwrap();

    let policy = trust_policy_from_str(
        r#"
        allowlist = []
        require_signed = true
        "#,
    )
    .unwrap();

    let result = preen_cli::verify_rule_pack_for_test(&loaded, &policy);
    assert!(result.unwrap_err().contains("signature required"));
}

#[test]
fn unsigned_pack_rejected_even_if_config_requests_not_required() {
    let tmp = tempfile::tempdir().unwrap();
    write_pack(tmp.path(), false);
    let loaded = load_rule_pack_from_dir(tmp.path()).unwrap();

    let policy_err = trust_policy_from_str(
        r#"
        allowlist = []
        require_signed = false
        "#,
    )
    .unwrap_err();
    assert!(policy_err.contains("require_signed=false"));

    let policy = trust_policy_from_str(
        r#"
        allowlist = []
        require_signed = true
        "#,
    )
    .unwrap();
    let result = preen_cli::verify_rule_pack_for_test(&loaded, &policy);
    assert!(result.unwrap_err().contains("signature required"));
}
