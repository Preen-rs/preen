use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use async_trait::async_trait;
use clap::Parser;
use preen_cli::{
    Cli, CliError, CliErrorKind, analyze_output_for_test, check_output_for_test,
    check_registry_freshness_for_test, clean_runtime_error_detail_code_for_test,
    clean_selection_summary_for_test, cli_label_for_test, clone_rule_pack_for_test,
    completion_output_for_test, default_signature_source_for_test, enforce_clean_scope_for_test,
    enforce_installer_scope_for_test, enforce_uninstall_scope_for_test, error_json_for_test,
    format_bytes_for_test, hint_for_detail_code_for_test, hint_message_for_test,
    install_plugin_in_dir_for_test, installer_output_for_test,
    installer_runtime_error_detail_code_for_test, load_lockfile_at, optimize_output_for_test,
    optimize_runtime_error_detail_code_for_test, parse_install_spec, parse_plugin_spec,
    plugin_info_json_for_test, plugin_install_json_for_test, plugin_list_json_for_test,
    plugin_preflight_all_for_test, plugin_preflight_all_json_for_test,
    plugin_preflight_json_for_test, plugin_remove_json_for_test, plugin_test_all_for_test,
    plugin_test_all_json_for_test, plugin_test_for_test, plugin_test_json_for_test,
    plugin_test_spec_json_for_test, plugin_update_json_for_test, plugin_verify_for_test,
    plugin_verify_json_for_test, plugin_verify_text_for_test,
    preferred_lockfile_read_path_for_test, preflight_failure_row_for_test,
    primary_hint_for_drift_fields_for_test, purge_output_for_test, registry_backup_path_for_test,
    registry_update_json_for_test, remove_output_for_test, resolve_registry_for_test, run_typed,
    run_typed_with_verifier_and_clean_executor_for_test, run_typed_with_verifier_for_test,
    save_lockfile_at, search_registry_for_test, search_registry_json_for_test,
    status_output_for_test, test_failure_row_for_test, touchid_output_for_test,
    trust_policy_from_str, uninstall_output_for_test, uninstall_runtime_error_detail_code_for_test,
    update_output_for_test, validate_registry_trust_inputs_for_test, verify_lockfile_hashes,
    write_registry_index_with_backup_for_test,
};
use preen_core::action_runtime::{
    ActionExecutionError, ActionExecutionResult, ActionExecutorPort, ExecutionPlan,
    RuntimeExecutionError,
};
use preen_core::plugin::{SignatureVerifier, VerificationInput, VerificationOutcome, VerifyError};
use preen_core::plugin_lock::{LockedPlugin, PluginLockfile};
use preen_core::rules::ScanRule;
use preen_core::{CleanableItem, ItemCategory, ScanResult};
use serde_json::Value;
use time::Duration as TimeDuration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct AlwaysOkVerifier;

impl SignatureVerifier for AlwaysOkVerifier {
    fn verify(&self, input: VerificationInput) -> Result<VerificationOutcome, VerifyError> {
        Ok(VerificationOutcome {
            identity: input.expected_identity.unwrap_or_default(),
        })
    }
}

struct AlwaysFailVerifier;

impl SignatureVerifier for AlwaysFailVerifier {
    fn verify(&self, _input: VerificationInput) -> Result<VerificationOutcome, VerifyError> {
        Err(VerifyError::SignatureInvalid("forced failure".to_string()))
    }
}

struct ForcedCleanErrorExecutor {
    error: ActionExecutionError,
}

#[async_trait]
impl ActionExecutorPort for ForcedCleanErrorExecutor {
    async fn execute(
        &self,
        _plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        Err(self.error.clone())
    }
}

fn run_git(args: &[&str]) {
    let out = Command::new("git").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn plugin_install_base_dir_from_env() -> PathBuf {
    match std::env::consts::OS {
        "macos" => PathBuf::from(std::env::var("HOME").unwrap())
            .join("Library")
            .join("Application Support")
            .join("Preen")
            .join("plugins"),
        "linux" => PathBuf::from(std::env::var("XDG_CONFIG_HOME").unwrap())
            .join("preen")
            .join("plugins"),
        other => panic!("unsupported os in test: {other}"),
    }
}

fn with_temp_user_env<T>(f: impl FnOnce() -> T) -> T {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let xdg = tmp.path().join("xdg");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&xdg).unwrap();

    let old_home: Option<OsString> = std::env::var_os("HOME");
    let old_xdg: Option<OsString> = std::env::var_os("XDG_CONFIG_HOME");
    // SAFETY: test caller holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_CONFIG_HOME", &xdg);
    }
    let out = f();
    // SAFETY: test caller holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        match old_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match old_xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }
    out
}

fn with_clean_path_override<T>(f: impl FnOnce() -> T) -> T {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(cache_dir.join("a.txt"), b"data").unwrap();
    let old = std::env::var_os("PREEN_CLEAN_PATHS");
    // SAFETY: test caller holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_CLEAN_PATHS", cache_dir.as_os_str());
    }
    let out = f();
    // SAFETY: test caller holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        match old {
            Some(v) => std::env::set_var("PREEN_CLEAN_PATHS", v),
            None => std::env::remove_var("PREEN_CLEAN_PATHS"),
        }
    }
    out
}

fn clean_error_json_for_forced_executor(error: ActionExecutionError) -> Value {
    let _guard = ENV_LOCK.lock().unwrap();
    with_clean_path_override(|| {
        let cli = Cli::try_parse_from(["preen", "clean", "--confirm", "--json"]).unwrap();
        let executor = ForcedCleanErrorExecutor { error };
        let err = run_typed_with_verifier_and_clean_executor_for_test(
            cli.clone(),
            &AlwaysOkVerifier,
            &executor,
        )
        .unwrap_err();
        serde_json::from_str(&cli.format_error(&err)).unwrap()
    })
}

fn check_passed_from_json(data: &Value, check_id: &str) -> Option<bool> {
    let checks = data.get("checks")?.as_array()?;
    for item in checks {
        if item.get("check").and_then(Value::as_str) == Some(check_id) {
            return item.get("passed").and_then(Value::as_bool);
        }
    }
    None
}

fn check_passed_from_verify_text(text: &str, check_id: &str) -> Option<bool> {
    let prefix = format!("check: id={check_id} ");
    for line in text.lines() {
        if line.starts_with(&prefix) {
            if line.contains(" passed=true") {
                return Some(true);
            }
            if line.contains(" passed=false") {
                return Some(false);
            }
        }
    }
    None
}

fn system_check_passed_from_json(data: &Value, check_id: &str) -> Option<bool> {
    let checks = data.get("checks")?.as_array()?;
    checks.iter().find_map(|item| {
        if item.get("id").and_then(Value::as_str) == Some(check_id) {
            item.get("passed").and_then(Value::as_bool)
        } else {
            None
        }
    })
}

fn init_preflight_git_repo(base: &Path) -> String {
    fs::create_dir_all(base.join("rules")).unwrap();
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
os_targets = ["Linux", "Macos"]
capabilities = ["FsRead"]

[signing]
sigstore = true
issuer = "https://token.actions.githubusercontent.com"
identity = "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0"

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
    fs::write(base.join("manifest.toml"), manifest).unwrap();
    fs::write(base.join("manifest.sig"), "sig").unwrap();
    fs::write(base.join("manifest.cert"), "cert").unwrap();
    fs::write(base.join("rules/rule-1.toml"), rule).unwrap();

    let base_s = base.to_str().unwrap().to_string();
    run_git(&["init", &base_s]);
    run_git(&["-C", &base_s, "config", "user.email", "test@example.com"]);
    run_git(&["-C", &base_s, "config", "user.name", "Test User"]);
    run_git(&["-C", &base_s, "add", "."]);
    run_git(&[
        "-c",
        "commit.gpgsign=false",
        "-C",
        &base_s,
        "commit",
        "-m",
        "init",
    ]);
    let out = Command::new("git")
        .args(["-C", &base_s, "rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_preflight_git_repo_with_old_tag(base: &Path) -> String {
    let first_commit = init_preflight_git_repo(base);
    let base_s = base.to_str().unwrap().to_string();
    run_git(&["-C", &base_s, "tag", "v0.0.1", &first_commit]);
    fs::write(base.join("README.md"), "next").unwrap();
    run_git(&["-C", &base_s, "add", "README.md"]);
    run_git(&[
        "-c",
        "commit.gpgsign=false",
        "-C",
        &base_s,
        "commit",
        "-m",
        "second",
    ]);
    "v0.0.1".to_string()
}

#[test]
fn parse_install_spec_ok() {
    let (url, rev) = parse_install_spec("https://github.com/Preen-rs/foo@v1.2.3").unwrap();
    assert_eq!(url, "https://github.com/Preen-rs/foo");
    assert_eq!(rev, "v1.2.3");
}

#[test]
fn parse_install_spec_missing_rev() {
    let err = parse_install_spec("https://github.com/Preen-rs/foo").unwrap_err();
    assert!(err.contains("missing @<tag|commit>"));
}

#[test]
fn parse_install_spec_empty_url_or_rev() {
    assert!(parse_install_spec("@v1").is_err());
    assert!(parse_install_spec("https://github.com/Preen-rs/foo@").is_err());
}

#[test]
fn parse_plugin_spec_registry() {
    let parsed = parse_plugin_spec("preen-rs.homebrew@1.2.0").unwrap();
    assert_eq!(
        parsed,
        preen_cli::InstallSpec::Registry {
            pack_id: "preen-rs.homebrew".to_string(),
            version: "1.2.0".to_string(),
        }
    );
}

#[test]
fn parse_plugin_spec_git_ssh() {
    let parsed = parse_plugin_spec("git@github.com:Preen-rs/preen-rulepack.git@v1.0.0").unwrap();
    assert_eq!(
        parsed,
        preen_cli::InstallSpec::Git {
            url: "git@github.com:Preen-rs/preen-rulepack.git".to_string(),
            rev: "v1.0.0".to_string(),
        }
    );
}

#[test]
fn resolve_registry_for_test_ok() {
    let index = r#"
schema_version = 1

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#;
    let (url, rev) = resolve_registry_for_test(index, "preen-rs.homebrew", "1.2.0").unwrap();
    assert_eq!(url, "https://github.com/Preen-rs/preen-rulepack-homebrew");
    assert_eq!(rev, "abc123");
}

#[test]
fn search_registry_for_test_filters() {
    let index = r#"
schema_version = 1

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack for brew"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"

[[entries]]
pack_id = "preen-rs.npm"
name = "Npm"
description = "Cleanup pack for node"
repo_url = "https://github.com/Preen-rs/preen-rulepack-npm"
latest_version = "0.3.0"
  [[entries.versions]]
  version = "0.3.0"
  rev = "def456"
"#;
    let all_rows = search_registry_for_test(index, None).unwrap();
    assert_eq!(all_rows.len(), 2);
    let brew_rows = search_registry_for_test(index, Some("brew")).unwrap();
    assert_eq!(brew_rows.len(), 1);
    assert!(brew_rows[0].starts_with("preen-rs.homebrew "));
}

#[test]
fn search_registry_json_for_test_filters() {
    let index = r#"
schema_version = 1

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack for brew"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#;
    let json = search_registry_json_for_test(index, Some("brew")).unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.search");
    assert_eq!(parsed["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        parsed["data"][0]["pack_id"].as_str().unwrap(),
        "preen-rs.homebrew"
    );
}

#[test]
fn default_signature_source_for_registry_source() {
    assert_eq!(
        default_signature_source_for_test("https://example.com/registry-index.toml"),
        "https://example.com/registry-index.toml.sig"
    );
    assert_eq!(
        default_signature_source_for_test("/tmp/registry-index.toml"),
        "/tmp/registry-index.toml.sig"
    );
}

#[test]
fn validate_registry_trust_inputs_guardrails() {
    let ok = validate_registry_trust_inputs_for_test(
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "https://token.actions.githubusercontent.com",
    );
    assert!(ok.is_ok());

    let bad_identity = validate_registry_trust_inputs_for_test(
        "https://github.com/other-org/repo/.github/workflows/release.yml@refs/heads/main",
        "https://token.actions.githubusercontent.com",
    );
    assert!(bad_identity.is_err());

    let bad_issuer = validate_registry_trust_inputs_for_test(
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "https://issuer.example.com",
    );
    assert!(bad_issuer.is_err());
}

#[test]
fn plugin_info_json_for_test_contains_fields() {
    let plugin = LockedPlugin {
        pack_id: "test.pack".to_string(),
        source: "git".to_string(),
        url: "https://github.com/Preen-rs/test".to_string(),
        rev: "abc123".to_string(),
        resolved_rev: Some("abc123".to_string()),
        version: "0.1.0".to_string(),
        manifest_hash: "sha256:deadbeef".to_string(),
        signature: "sha256:cafebabe".to_string(),
        trusted_identity: "https://github.com/Preen-rs/test".to_string(),
    };
    let json = plugin_info_json_for_test(&plugin).unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.info");
    assert_eq!(parsed["data"]["pack_id"].as_str().unwrap(), "test.pack");
    assert_eq!(parsed["data"]["source"].as_str().unwrap(), "git");
}

#[test]
fn plugin_list_json_for_test_contains_fields() {
    let plugins = vec![LockedPlugin {
        pack_id: "test.pack".to_string(),
        source: "git".to_string(),
        url: "https://github.com/Preen-rs/test".to_string(),
        rev: "abc123".to_string(),
        resolved_rev: Some("abc123".to_string()),
        version: "0.1.0".to_string(),
        manifest_hash: "sha256:deadbeef".to_string(),
        signature: "sha256:cafebabe".to_string(),
        trusted_identity: "https://github.com/Preen-rs/test".to_string(),
    }];
    let json = plugin_list_json_for_test(&plugins).unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.list");
    assert_eq!(parsed["data"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["data"][0]["pack_id"].as_str().unwrap(), "test.pack");
}

#[test]
fn plugin_verify_json_for_test_contains_fields() {
    let json = plugin_verify_json_for_test("test.pack", true, true, true).unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.verify");
    assert_eq!(parsed["data"]["pack_id"].as_str().unwrap(), "test.pack");
    assert!(parsed["data"]["manifest_hash_verified"].as_bool().unwrap());
    assert!(parsed["data"]["signature_hash_verified"].as_bool().unwrap());
    assert!(parsed["data"]["resolved_rev_verified"].as_bool().unwrap());
}

#[test]
fn plugin_verify_text_for_test_contains_summary_and_checks() {
    let text = plugin_verify_text_for_test("test.pack", "en-US");
    assert!(text.contains("summary: kind=verify pack_id=test.pack overall_passed=true"));
    assert!(text.contains(
        "verify: version_matches_lock=true manifest_hash_verified=true signature_hash_verified=true resolved_rev_verified=true",
    ));
    assert!(text.contains("checks: label=Checks"));
    assert!(text.contains("check: id=signature_verified"));
}

#[test]
fn plugin_test_json_for_test_contains_fields() {
    let json = plugin_test_json_for_test("test.pack").unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.test");
    assert_eq!(parsed["data"]["pack_id"].as_str().unwrap(), "test.pack");
    assert!(parsed["data"]["overall_passed"].as_bool().unwrap());
    assert!(parsed["data"]["version_matches_lock"].as_bool().unwrap());
    assert!(parsed["data"]["signature_verified"].as_bool().unwrap());
    assert!(parsed["data"]["checks"].as_array().is_some());
    assert!(parsed["data"]["duration_ms"].as_u64().is_some());
    assert!(parsed["data"]["drifts"].as_array().unwrap().is_empty());
}

#[test]
fn plugin_test_all_json_for_test_contains_fields() {
    let json = plugin_test_all_json_for_test().unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.test_all");
    assert!(parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(parsed["data"]["total"].as_u64().unwrap(), 0);
    assert_eq!(parsed["data"]["passed"].as_u64().unwrap(), 0);
    assert_eq!(parsed["data"]["failed"].as_u64().unwrap(), 0);
    assert!(parsed["data"]["results"].as_array().unwrap().is_empty());
    assert!(parsed["data"]["failures"].as_array().unwrap().is_empty());
}

#[test]
fn plugin_test_spec_json_for_test_contains_fields() {
    let json = plugin_test_spec_json_for_test("preen-rs.homebrew@1.2.0", "test.pack").unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.test_spec");
    assert_eq!(
        parsed["data"]["spec"].as_str().unwrap(),
        "preen-rs.homebrew@1.2.0"
    );
    assert_eq!(parsed["data"]["pack_id"].as_str().unwrap(), "test.pack");
    assert!(parsed["data"]["overall_passed"].as_bool().unwrap());
    assert!(parsed["data"]["checks"].as_array().is_some());
    assert!(parsed["data"]["duration_ms"].as_u64().is_some());
}

#[test]
fn plugin_preflight_json_for_test_contains_fields() {
    let json = plugin_preflight_json_for_test("preen-rs.homebrew@1.2.0", "test.pack").unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.preflight");
    assert_eq!(
        parsed["data"]["spec"].as_str().unwrap(),
        "preen-rs.homebrew@1.2.0"
    );
    assert_eq!(parsed["data"]["pack_id"].as_str().unwrap(), "test.pack");
    assert!(parsed["data"]["signature_verified"].as_bool().unwrap());
    assert!(parsed["data"]["checks"].as_array().is_some());
    assert!(parsed["data"]["duration_ms"].as_u64().is_some());
}

#[test]
fn plugin_preflight_all_json_for_test_contains_fields() {
    let json = plugin_preflight_all_json_for_test().unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.preflight_all");
    assert!(parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(parsed["data"]["total"].as_u64().unwrap(), 0);
    assert_eq!(parsed["data"]["passed"].as_u64().unwrap(), 0);
    assert_eq!(parsed["data"]["failed"].as_u64().unwrap(), 0);
    assert!(parsed["data"]["results"].as_array().unwrap().is_empty());
    assert!(parsed["data"]["failures"].as_array().unwrap().is_empty());
}

#[test]
fn plugin_install_update_remove_registry_json_helpers() {
    let install = plugin_install_json_for_test("a.pack", "1.0.0", "registry", "abc").unwrap();
    let install_v: Value = serde_json::from_str(&install).unwrap();
    assert_eq!(install_v["kind"].as_str().unwrap(), "plugin.install");
    assert_eq!(install_v["data"]["pack_id"].as_str().unwrap(), "a.pack");

    let update = plugin_update_json_for_test("a.pack", "1.1.0", "registry", "def").unwrap();
    let update_v: Value = serde_json::from_str(&update).unwrap();
    assert_eq!(update_v["kind"].as_str().unwrap(), "plugin.update");
    assert_eq!(update_v["data"]["rev"].as_str().unwrap(), "def");

    let remove = plugin_remove_json_for_test("a.pack", true).unwrap();
    let remove_v: Value = serde_json::from_str(&remove).unwrap();
    assert_eq!(remove_v["kind"].as_str().unwrap(), "plugin.remove");
    assert!(remove_v["data"]["removed"].as_bool().unwrap());

    let reg = registry_update_json_for_test(
        10,
        "/tmp/registry-index.toml",
        "warn",
        30,
        "https://example.com/registry-index.toml",
        "https://example.com/registry-index.toml.sig",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "https://token.actions.githubusercontent.com",
        false,
        Some("/tmp/registry-index.toml.bak"),
    )
    .unwrap();
    let reg_v: Value = serde_json::from_str(&reg).unwrap();
    assert_eq!(reg_v["kind"].as_str().unwrap(), "plugin.registry_update");
    assert_eq!(reg_v["data"]["entries"].as_u64().unwrap(), 10);
    assert_eq!(reg_v["data"]["stale_mode"].as_str().unwrap(), "warn");
    assert_eq!(reg_v["data"]["max_age_days"].as_i64().unwrap(), 30);
    assert_eq!(
        reg_v["data"]["source"].as_str().unwrap(),
        "https://example.com/registry-index.toml"
    );
    assert_eq!(
        reg_v["data"]["used_signature_source"].as_str().unwrap(),
        "https://example.com/registry-index.toml.sig"
    );
    assert_eq!(
        reg_v["data"]["identity"].as_str().unwrap(),
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main"
    );
    assert_eq!(
        reg_v["data"]["issuer"].as_str().unwrap(),
        "https://token.actions.githubusercontent.com"
    );
    assert!(!reg_v["data"]["strict_applied"].as_bool().unwrap());
    assert_eq!(
        reg_v["data"]["backup_path"].as_str().unwrap(),
        "/tmp/registry-index.toml.bak"
    );
}

#[test]
fn json_envelopes_have_exact_expected_data_keys() {
    let install = plugin_install_json_for_test("a.pack", "1.0.0", "registry", "abc").unwrap();
    let install_v: Value = serde_json::from_str(&install).unwrap();
    let install_keys = install_v["data"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        install_keys,
        BTreeSet::from([
            "pack_id".to_string(),
            "version".to_string(),
            "source".to_string(),
            "rev".to_string(),
        ])
    );

    let verify = plugin_verify_json_for_test("a.pack", true, true, true).unwrap();
    let verify_v: Value = serde_json::from_str(&verify).unwrap();
    let verify_keys = verify_v["data"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        verify_keys,
        BTreeSet::from([
            "pack_id".to_string(),
            "manifest_hash_verified".to_string(),
            "signature_hash_verified".to_string(),
            "resolved_rev_verified".to_string(),
        ])
    );

    let test = plugin_test_json_for_test("a.pack").unwrap();
    let test_v: Value = serde_json::from_str(&test).unwrap();
    let test_keys = test_v["data"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        test_keys,
        BTreeSet::from([
            "pack_id".to_string(),
            "overall_passed".to_string(),
            "version_matches_lock".to_string(),
            "manifest_hash_verified".to_string(),
            "signature_hash_verified".to_string(),
            "resolved_rev_verified".to_string(),
            "signature_verified".to_string(),
            "trust_verified".to_string(),
            "core_compat_verified".to_string(),
            "action_api_verified".to_string(),
            "os_target_verified".to_string(),
            "checks".to_string(),
            "duration_ms".to_string(),
            "drifts".to_string(),
        ])
    );

    let preflight_all = plugin_preflight_all_json_for_test().unwrap();
    let preflight_all_v: Value = serde_json::from_str(&preflight_all).unwrap();
    let preflight_all_keys = preflight_all_v["data"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        preflight_all_keys,
        BTreeSet::from([
            "overall_passed".to_string(),
            "total".to_string(),
            "passed".to_string(),
            "failed".to_string(),
            "results".to_string(),
            "failures".to_string(),
        ])
    );

    let test_all = plugin_test_all_json_for_test().unwrap();
    let test_all_v: Value = serde_json::from_str(&test_all).unwrap();
    let test_all_keys = test_all_v["data"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        test_all_keys,
        BTreeSet::from([
            "overall_passed".to_string(),
            "total".to_string(),
            "passed".to_string(),
            "failed".to_string(),
            "results".to_string(),
            "failures".to_string(),
        ])
    );

    let test_spec = plugin_test_spec_json_for_test("preen-rs.homebrew@1.2.0", "a.pack").unwrap();
    let test_spec_v: Value = serde_json::from_str(&test_spec).unwrap();
    let test_spec_keys = test_spec_v["data"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        test_spec_keys,
        BTreeSet::from([
            "overall_passed".to_string(),
            "spec".to_string(),
            "source".to_string(),
            "url".to_string(),
            "requested_rev".to_string(),
            "resolved_rev".to_string(),
            "pack_id".to_string(),
            "version".to_string(),
            "signature_verified".to_string(),
            "trust_verified".to_string(),
            "core_compat_verified".to_string(),
            "action_api_verified".to_string(),
            "os_target_verified".to_string(),
            "checks".to_string(),
            "duration_ms".to_string(),
        ])
    );

    let search = search_registry_json_for_test(
        r#"
schema_version = 1

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack for brew"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#,
        Some("brew"),
    )
    .unwrap();
    let search_v: Value = serde_json::from_str(&search).unwrap();
    let search_keys = search_v["data"][0]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        search_keys,
        BTreeSet::from([
            "pack_id".to_string(),
            "latest_version".to_string(),
            "description".to_string(),
        ])
    );
}

#[test]
fn error_json_for_test_contains_envelope() {
    let json = error_json_for_test("missing @<tag|commit> in install spec").unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"].as_u64().unwrap(), 1);
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "validation");
}

#[test]
fn error_json_for_test_includes_detail_code_when_present() {
    let json = error_json_for_test(
        "__preen_kind:validation__preen_code:preflight_spec_invalid__missing @<tag|commit> in install spec",
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "validation");
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "preflight_spec_invalid"
    );
}

#[test]
fn error_json_for_test_tagged_kinds() {
    let cases = [
        ("__preen_kind:validation__bad input", "validation"),
        ("__preen_kind:not_found__plugin not found", "not_found"),
        ("__preen_kind:trust__identity not allowed", "trust"),
        (
            "__preen_kind:verification__signature mismatch",
            "verification",
        ),
        ("__preen_kind:io__lockfile read failed", "io"),
        ("__preen_kind:network__registry fetch failed", "network"),
        ("__preen_kind:unsupported__unsupported OS", "unsupported"),
        ("__preen_kind:internal__git command failed", "internal"),
    ];

    for (input, expected_kind) in cases {
        let json = error_json_for_test(input).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["kind"].as_str().unwrap(), "error");
        assert_eq!(
            parsed["data"]["error_kind"].as_str().unwrap(),
            expected_kind
        );
    }
}

#[test]
fn wants_json_output_detects_flag() {
    let cli = Cli::try_parse_from(["preen", "plugin", "search", "--json"]).unwrap();
    assert!(cli.wants_json_output());
    let cli = Cli::try_parse_from(["preen", "clean", "--json"]).unwrap();
    assert!(cli.wants_json_output());
    let cli = Cli::try_parse_from(["preen", "status", "--json"]).unwrap();
    assert!(cli.wants_json_output());
    let cli = Cli::try_parse_from(["preen", "plugin", "registry-update", "--json"]).unwrap();
    assert!(cli.wants_json_output());
    let cli =
        Cli::try_parse_from(["preen", "plugin", "preflight", "x.pack@1.0.0", "--json"]).unwrap();
    assert!(cli.wants_json_output());
    let cli = Cli::try_parse_from(["preen", "plugin", "preflight", "--all", "--json"]).unwrap();
    assert!(cli.wants_json_output());
    let cli = Cli::try_parse_from(["preen", "plugin", "test", "x.pack", "--json"]).unwrap();
    assert!(cli.wants_json_output());
    let cli = Cli::try_parse_from(["preen", "plugin", "test", "--all", "--json"]).unwrap();
    assert!(cli.wants_json_output());
    let cli = Cli::try_parse_from(["preen", "plugin", "list"]).unwrap();
    assert!(!cli.wants_json_output());
}

#[test]
fn top_level_system_commands_are_implemented() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["preen", "touchid", "status", "--json"],
        vec!["preen", "completion", "zsh", "--json"],
        vec!["preen", "update", "--json"],
        vec!["preen", "remove", "--dry-run", "--json"],
    ];

    for args in cases {
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(run_typed(cli).is_ok());
    }
}

#[test]
fn clean_dry_run_executes_with_temp_path_override() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(cache_dir.join("a.txt"), b"data").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_CLEAN_PATHS", cache_dir.as_os_str());
    }

    let cli = Cli::try_parse_from(["preen", "clean", "--dry-run", "--json"]).unwrap();
    let result = run_typed(cli);

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_CLEAN_PATHS");
    }
    assert!(result.is_ok());
}

#[test]
fn clean_apply_requires_confirm_flag() {
    let cli = Cli::try_parse_from(["preen", "clean", "--json"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("clean_confirmation_required")
    );
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "clean_confirmation_required"
    );
}

#[test]
fn optimize_apply_requires_confirm_flag() {
    let cli = Cli::try_parse_from(["preen", "optimize", "--json"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("optimize_confirmation_required")
    );
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "optimize_confirmation_required"
    );
}

#[test]
fn optimize_text_error_is_classified_as_system_without_plugin_hints() {
    let cli = Cli::try_parse_from(["preen", "optimize"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    let out = cli.format_error(&err);
    assert!(out.contains("kind=validation"));
    assert!(out.contains("detail_code=optimize_confirmation_required"));
    assert!(!out.contains("hint_code="));
}

#[test]
fn optimize_dry_run_json_happy_path() {
    let output = optimize_output_for_test(true, false).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.optimize"));
    assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    assert!(output["data"]["task_count"].as_u64().unwrap_or(0) >= 1);
    let executed = output["data"]["executed_tasks"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!executed.is_empty());
}

#[test]
fn check_json_happy_path_without_fix() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = check_output_for_test(false).unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.check"));
        assert_eq!(output["data"]["mode"].as_str(), Some("check"));
        assert_eq!(output["data"]["fixes_applied"].as_u64(), Some(0));
        assert_eq!(
            system_check_passed_from_json(&output["data"], "state_dir_exists"),
            Some(false)
        );
    });
}

#[test]
fn check_fix_json_creates_state_and_plugin_dirs() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = check_output_for_test(true).unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.check"));
        assert_eq!(output["data"]["mode"].as_str(), Some("check_and_fix"));
        assert!(output["data"]["fixes_applied"].as_u64().unwrap_or(0) >= 1);
        assert_eq!(
            system_check_passed_from_json(&output["data"], "state_dir_exists"),
            Some(true)
        );
        assert_eq!(
            system_check_passed_from_json(&output["data"], "plugins_dir_exists"),
            Some(true)
        );
    });
}

#[test]
fn analyze_json_happy_path_with_explicit_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("dir-a")).unwrap();
    fs::create_dir_all(root.join("dir-b")).unwrap();
    fs::write(root.join("root.bin"), vec![0_u8; 512]).unwrap();
    fs::write(root.join("dir-a").join("nested.bin"), vec![0_u8; 128]).unwrap();

    let output = analyze_output_for_test(Some(root)).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.analyze"));
    assert_eq!(
        output["data"]["root"].as_str(),
        Some(root.to_string_lossy().as_ref())
    );
    assert!(output["data"]["scanned_entries"].as_u64().unwrap_or(0) >= 1);
    assert!(output["data"]["total_files"].as_u64().unwrap_or(0) >= 2);
    assert!(output["data"]["total_size_bytes"].as_u64().unwrap_or(0) >= 640);
    assert!(output["data"]["top_entries"].as_array().is_some());
}

#[test]
fn analyze_rejects_missing_root_path() {
    let missing = "/tmp/preen-analyze-missing-root-for-test";
    let cli = Cli::try_parse_from(["preen", "analyze", missing, "--json"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::NotFound);
    assert_eq!(err.detail_code.as_deref(), Some("analyze_root_not_found"));
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("analyze_root_not_found")
    );
}

#[test]
fn analyze_rejects_non_directory_root_path() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("only-file.txt");
    fs::write(&file_path, b"data").unwrap();

    let cli = Cli::try_parse_from([
        "preen",
        "analyze",
        file_path.to_string_lossy().as_ref(),
        "--json",
    ])
    .unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("analyze_root_not_directory")
    );
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("analyze_root_not_directory")
    );
}

#[test]
fn analyze_text_error_is_classified_as_system_without_plugin_hints() {
    let cli = Cli::try_parse_from(["preen", "analyze", "/tmp/preen-analyze-missing-root"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    let out = cli.format_error(&err);
    assert!(out.contains("kind=not_found"));
    assert!(out.contains("detail_code=analyze_root_not_found"));
    assert!(!out.contains("hint_code="));
}

#[test]
fn status_json_happy_path_with_temp_user_env() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = status_output_for_test().unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.status"));
        assert_eq!(output["data"]["mode"].as_str(), Some("status"));
        assert!(output["data"]["os"].as_str().is_some());
        assert!(output["data"]["arch"].as_str().is_some());
        assert!(output["data"]["state_dir"].as_str().is_some());
        assert!(output["data"]["checks"].as_array().is_some());
        assert!(output["data"]["plugin_count"].as_u64().is_some());
    });
}

#[test]
fn status_command_runs_without_error() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let cli = Cli::try_parse_from(["preen", "status", "--json"]).unwrap();
        let result = run_typed(cli);
        assert!(result.is_ok());
    });
}

#[test]
fn touchid_json_happy_path_enable_dry_run() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = touchid_output_for_test(Some("enable"), true).unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.touchid"));
        assert_eq!(output["data"]["action"].as_str(), Some("enable"));
        assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
        assert!(output["data"]["would_change"].is_boolean());
    });
}

#[test]
fn touchid_command_runs_without_error() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let cli = Cli::try_parse_from(["preen", "touchid", "status", "--json"]).unwrap();
        let result = run_typed(cli);
        assert!(result.is_ok());
    });
}

#[test]
fn completion_json_generates_script_for_explicit_shell() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = completion_output_for_test(Some("zsh"), true).unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.completion"));
        assert_eq!(output["data"]["mode"].as_str(), Some("generate"));
        assert_eq!(output["data"]["shell"].as_str(), Some("zsh"));
        let script = output["data"]["script"].as_str().unwrap_or_default();
        assert!(script.contains("compdef"));
        assert!(script.contains("preen"));
    });
}

#[test]
fn completion_dry_run_autodetect_writes_no_file() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let home = tempfile::tempdir().unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::set_var("HOME", home.path().as_os_str());
            std::env::set_var("SHELL", "/bin/zsh");
        }
        let output = completion_output_for_test(None, true).unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::remove_var("SHELL");
        }
        assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
        assert_eq!(output["data"]["installed"].as_bool(), Some(false));
        assert_eq!(output["data"]["changed"].as_bool(), Some(false));
        assert!(!home.path().join(".zshrc").exists());
    });
}

#[test]
fn update_json_happy_path_contains_suggested_command() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::set_var("PREEN_UPDATE_LATEST_VERSION", "9.9.9");
            std::env::set_var("PREEN_UPDATE_INSTALL_SOURCE", "cargo");
        }
        let output = update_output_for_test(false, false).unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::remove_var("PREEN_UPDATE_LATEST_VERSION");
            std::env::remove_var("PREEN_UPDATE_INSTALL_SOURCE");
        }
        assert_eq!(output["kind"].as_str(), Some("system.update"));
        assert_eq!(output["data"]["channel"].as_str(), Some("stable"));
        assert_eq!(output["data"]["install_source"].as_str(), Some("cargo"));
        let command = output["data"]["suggested_command"]
            .as_str()
            .unwrap_or_default();
        assert!(command.contains("cargo install"));
    });
}

#[test]
fn update_command_runs_without_error() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let cli = Cli::try_parse_from(["preen", "update", "--json"]).unwrap();
        let result = run_typed(cli);
        assert!(result.is_ok());
    });
}

#[test]
fn remove_json_happy_path_dry_run() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        fs::write(state_dir.path().join("plugins.lock"), "dummy").unwrap();
        fs::write(cache_dir.path().join("cache.tmp"), "dummy").unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::set_var("PREEN_REMOVE_STATE_DIR", state_dir.path().as_os_str());
            std::env::set_var("PREEN_REMOVE_CACHE_DIR", cache_dir.path().as_os_str());
            std::env::set_var("PREEN_UPDATE_INSTALL_SOURCE", "cargo");
        }
        let output = remove_output_for_test(true).unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::remove_var("PREEN_REMOVE_STATE_DIR");
            std::env::remove_var("PREEN_REMOVE_CACHE_DIR");
            std::env::remove_var("PREEN_UPDATE_INSTALL_SOURCE");
        }
        assert_eq!(output["kind"].as_str(), Some("system.remove"));
        assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
        assert!(output["data"]["detected_paths"].as_array().is_some());
        assert!(output["data"]["manual_steps"].as_array().is_some());
    });
}

#[test]
fn remove_apply_deletes_temp_paths() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let state_root = tempfile::tempdir().unwrap();
        let cache_root = tempfile::tempdir().unwrap();
        let state_path = state_root.path().join("state");
        let cache_path = cache_root.path().join("cache");
        fs::create_dir_all(&state_path).unwrap();
        fs::create_dir_all(&cache_path).unwrap();
        fs::write(state_path.join("plugins.lock"), "dummy").unwrap();
        fs::write(cache_path.join("cache.tmp"), "dummy").unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::set_var("PREEN_REMOVE_STATE_DIR", state_path.as_os_str());
            std::env::set_var("PREEN_REMOVE_CACHE_DIR", cache_path.as_os_str());
            std::env::set_var("PREEN_UPDATE_INSTALL_SOURCE", "cargo");
        }
        let output = remove_output_for_test(false).unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::remove_var("PREEN_REMOVE_STATE_DIR");
            std::env::remove_var("PREEN_REMOVE_CACHE_DIR");
            std::env::remove_var("PREEN_UPDATE_INSTALL_SOURCE");
        }
        assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
        assert!(!state_path.exists());
        assert!(!cache_path.exists());
        assert!(output["data"]["removed_paths"].as_array().is_some());
    });
}

#[test]
fn remove_command_runs_without_error() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let state_root = tempfile::tempdir().unwrap();
        let cache_root = tempfile::tempdir().unwrap();
        let state_path = state_root.path().join("state");
        let cache_path = cache_root.path().join("cache");
        fs::create_dir_all(&state_path).unwrap();
        fs::create_dir_all(&cache_path).unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::set_var("PREEN_REMOVE_STATE_DIR", state_path.as_os_str());
            std::env::set_var("PREEN_REMOVE_CACHE_DIR", cache_path.as_os_str());
        }
        let cli = Cli::try_parse_from(["preen", "remove", "--dry-run", "--json"]).unwrap();
        let result = run_typed(cli);
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::remove_var("PREEN_REMOVE_STATE_DIR");
            std::env::remove_var("PREEN_REMOVE_CACHE_DIR");
        }
        assert!(result.is_ok());
    });
}

#[test]
fn uninstall_requires_target_argument() {
    let cli = Cli::try_parse_from(["preen", "uninstall", "--json"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("uninstall_target_required")
    );
}

#[test]
fn uninstall_apply_requires_confirm_flag() {
    let cli = Cli::try_parse_from(["preen", "uninstall", "DemoApp", "--json"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("uninstall_confirmation_required")
    );
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "uninstall_confirmation_required"
    );
}

#[test]
fn uninstall_text_error_is_classified_as_system_without_plugin_hints() {
    let cli = Cli::try_parse_from(["preen", "uninstall", "DemoApp"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    let out = cli.format_error(&err);
    assert!(out.contains("kind=validation"));
    assert!(out.contains("detail_code=uninstall_confirmation_required"));
    assert!(!out.contains("hint_code="));
}

#[test]
fn uninstall_dry_run_json_happy_path() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let app_dir = temp.path().join("DemoApp.app");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(app_dir.join("Info.plist"), b"demo").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_UNINSTALL_PATHS", temp.path().as_os_str());
    }

    let output = uninstall_output_for_test(Some("DemoApp"), true, false).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.uninstall"));
    assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    assert_eq!(output["data"]["target"].as_str(), Some("DemoApp"));
    assert!(output["data"]["target_count"].as_u64().unwrap_or(0) >= 1);

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_UNINSTALL_PATHS");
    }
}

#[test]
fn uninstall_apply_confirm_deletes_targets() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let app_dir = temp.path().join("DemoApp.app");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(app_dir.join("Info.plist"), b"demo").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_UNINSTALL_PATHS", temp.path().as_os_str());
    }

    let output = uninstall_output_for_test(Some("DemoApp"), false, true).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.uninstall"));
    assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
    assert!(output["data"]["affected_items"].as_u64().unwrap_or(0) >= 1);
    assert!(!app_dir.exists());

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_UNINSTALL_PATHS");
    }
}

#[test]
fn uninstall_paths_mode_runs_without_error() {
    let cli = Cli::try_parse_from(["preen", "uninstall", "--paths", "--json"]).unwrap();
    let result = run_typed(cli);
    assert!(result.is_ok());
}

#[test]
fn purge_apply_requires_confirm_flag() {
    let cli = Cli::try_parse_from(["preen", "purge", "--json"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("purge_confirmation_required")
    );
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "purge_confirmation_required"
    );
}

#[test]
fn purge_dry_run_json_happy_path() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("app");
    let artifact = project.join("node_modules");
    fs::create_dir_all(&artifact).unwrap();
    fs::write(artifact.join("a.js"), b"1234").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_PURGE_PATHS", temp.path().as_os_str());
    }

    let output = purge_output_for_test(true, false).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.purge"));
    assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    assert!(output["data"]["target_count"].as_u64().unwrap_or(0) >= 1);

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_PURGE_PATHS");
    }
}

#[test]
fn purge_apply_confirm_deletes_targets() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("app");
    let artifact = project.join("target");
    fs::create_dir_all(&artifact).unwrap();
    fs::write(artifact.join("x.bin"), b"1234").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_PURGE_PATHS", temp.path().as_os_str());
    }

    let output = purge_output_for_test(false, true).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.purge"));
    assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
    assert!(output["data"]["affected_items"].as_u64().unwrap_or(0) >= 1);
    assert!(!artifact.exists());

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_PURGE_PATHS");
    }
}

#[test]
fn purge_paths_mode_runs_without_error() {
    let cli = Cli::try_parse_from(["preen", "purge", "--paths", "--json"]).unwrap();
    let result = run_typed(cli);
    assert!(result.is_ok());
}

#[test]
fn installer_apply_requires_confirm_flag() {
    let cli = Cli::try_parse_from(["preen", "installer", "--json"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("installer_confirmation_required")
    );
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "installer_confirmation_required"
    );
}

#[test]
fn installer_text_error_is_classified_as_system_without_plugin_hints() {
    let cli = Cli::try_parse_from(["preen", "installer"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    let out = cli.format_error(&err);
    assert!(out.contains("kind=validation"));
    assert!(out.contains("detail_code=installer_confirmation_required"));
    assert!(!out.contains("hint_code="));
}

#[test]
fn installer_dry_run_json_happy_path() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let installer = temp.path().join("Setup.pkg");
    fs::write(&installer, vec![0u8; 11 * 1024 * 1024]).unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_INSTALLER_PATHS", temp.path().as_os_str());
    }

    let output = installer_output_for_test(true, false).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.installer"));
    assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    assert!(output["data"]["target_count"].as_u64().unwrap_or(0) >= 1);

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_INSTALLER_PATHS");
    }
}

#[test]
fn installer_apply_confirm_deletes_targets() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let installer = temp.path().join("archive.dmg");
    fs::write(&installer, vec![0u8; 11 * 1024 * 1024]).unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_INSTALLER_PATHS", temp.path().as_os_str());
    }

    let output = installer_output_for_test(false, true).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.installer"));
    assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
    assert!(output["data"]["affected_items"].as_u64().unwrap_or(0) >= 1);
    assert!(!installer.exists());

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_INSTALLER_PATHS");
    }
}

#[test]
fn installer_paths_mode_runs_without_error() {
    let cli = Cli::try_parse_from(["preen", "installer", "--paths", "--json"]).unwrap();
    let result = run_typed(cli);
    assert!(result.is_ok());
}

#[test]
fn installer_scope_rejects_symlink_targets() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("root");
    let outside = fixture.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let outside_file = outside.join("Setup.pkg");
    fs::write(&outside_file, vec![0u8; 11 * 1024 * 1024]).unwrap();
    let link = root.join("linked.pkg");
    std::os::unix::fs::symlink(&outside_file, &link).unwrap();
    let roots = vec![root.to_string_lossy().to_string()];
    let selected = vec![link.to_string_lossy().to_string()];
    let err = enforce_installer_scope_for_test(&selected, &roots).unwrap_err();
    assert!(err.contains("installer_symlink_not_allowed"));
}

#[test]
fn installer_scope_rejects_outside_root_paths() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("root");
    let outside = fixture.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let outside_file = outside.join("Setup.pkg");
    fs::write(&outside_file, vec![0u8; 11 * 1024 * 1024]).unwrap();
    let roots = vec![root.to_string_lossy().to_string()];
    let selected = vec![outside_file.to_string_lossy().to_string()];
    let err = enforce_installer_scope_for_test(&selected, &roots).unwrap_err();
    assert!(err.contains("installer_path_scope_violation"));
}

#[test]
fn uninstall_scope_rejects_symlink_targets() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("root");
    let outside = fixture.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let outside_file = outside.join("DemoApp.app");
    fs::write(&outside_file, b"demo").unwrap();
    let link = root.join("linked.app");
    std::os::unix::fs::symlink(&outside_file, &link).unwrap();
    let roots = vec![root.to_string_lossy().to_string()];
    let selected = vec![link.to_string_lossy().to_string()];
    let err = enforce_uninstall_scope_for_test(&selected, &roots).unwrap_err();
    assert!(err.contains("uninstall_symlink_not_allowed"));
}

#[test]
fn uninstall_scope_rejects_outside_root_paths() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("root");
    let outside = fixture.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let outside_file = outside.join("DemoApp.app");
    fs::write(&outside_file, b"demo").unwrap();
    let roots = vec![root.to_string_lossy().to_string()];
    let selected = vec![outside_file.to_string_lossy().to_string()];
    let err = enforce_uninstall_scope_for_test(&selected, &roots).unwrap_err();
    assert!(err.contains("uninstall_path_scope_violation"));
}

#[test]
fn clean_json_maps_command_denied_detail_code() {
    let parsed = clean_error_json_for_forced_executor(ActionExecutionError::CommandDenied {
        command: "rm".to_string(),
    });
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "internal");
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "clean_command_denied"
    );
}

#[test]
fn clean_json_maps_command_timeout_detail_code() {
    let parsed = clean_error_json_for_forced_executor(ActionExecutionError::CommandTimeout {
        command: "brew cleanup".to_string(),
        timeout_sec: 5,
    });
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "internal");
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "clean_command_timeout"
    );
}

#[test]
fn clean_json_maps_command_non_zero_detail_code() {
    let parsed = clean_error_json_for_forced_executor(ActionExecutionError::CommandNonZero {
        command: "brew cleanup".to_string(),
        code: Some(1),
    });
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "internal");
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "clean_command_non_zero"
    );
}

#[test]
fn clean_apply_with_confirm_executes_with_temp_path_override() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    let target_file = cache_dir.join("a.txt");
    fs::write(&target_file, b"data").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_CLEAN_PATHS", cache_dir.as_os_str());
    }

    let cli = Cli::try_parse_from(["preen", "clean", "--confirm", "--json"]).unwrap();
    let result = run_typed(cli);

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_CLEAN_PATHS");
    }
    assert!(result.is_ok());
    assert!(cache_dir.exists());
    assert!(!target_file.exists());
}

#[test]
fn clean_apply_with_delete_strategy_executes() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    let target_file = cache_dir.join("a.txt");
    fs::write(&target_file, b"data").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_CLEAN_PATHS", cache_dir.as_os_str());
    }

    let cli = Cli::try_parse_from([
        "preen",
        "clean",
        "--confirm",
        "--strategy",
        "delete",
        "--json",
    ])
    .unwrap();
    let result = run_typed(cli);

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_CLEAN_PATHS");
    }
    assert!(result.is_ok());
    assert!(!target_file.exists());
}

#[test]
fn clean_apply_rejects_symlink_targets() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    let outside_file = temp.path().join("outside.txt");
    fs::write(&outside_file, b"data").unwrap();
    let symlink_path = cache_dir.join("link.txt");
    std::os::unix::fs::symlink(&outside_file, &symlink_path).unwrap();
    let roots = vec![cache_dir.to_string_lossy().to_string()];
    let selected = vec![symlink_path.to_string_lossy().to_string()];
    let err = enforce_clean_scope_for_test(&selected, &roots).unwrap_err();
    assert!(err.contains("clean_symlink_not_allowed"));
}

#[test]
fn clean_apply_respects_selection_limit() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    let f1 = cache_dir.join("a.txt");
    let f2 = cache_dir.join("b.txt");
    fs::write(&f1, b"12345").unwrap();
    fs::write(&f2, b"1234").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_CLEAN_PATHS", cache_dir.as_os_str());
        std::env::set_var("PREEN_CLEAN_MAX_ITEMS", "1");
    }

    let cli = Cli::try_parse_from(["preen", "clean", "--confirm", "--json"]).unwrap();
    let result = run_typed(cli);

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_CLEAN_MAX_ITEMS");
        std::env::remove_var("PREEN_CLEAN_PATHS");
    }
    assert!(result.is_ok());
    let remaining = usize::from(f1.exists()) + usize::from(f2.exists());
    assert_eq!(remaining, 1);
}

#[test]
fn clean_selection_summary_prefers_larger_items() {
    let roots = vec!["/tmp/cache".to_string()];
    let scan = ScanResult {
        executed_rules: vec![ScanRule {
            id: "rule-1".to_string(),
            name: "Rule".to_string(),
            category: ItemCategory::Cache,
            path_pattern: "/tmp/cache".to_string(),
            strategy: preen_core::rules::ScanStrategy::Recursive,
            description: "desc".to_string(),
        }],
        total_size: 300,
        items: vec![
            CleanableItem {
                rule_id: "rule-1".to_string(),
                id: "a".to_string(),
                category: ItemCategory::Cache,
                path: PathBuf::from("/tmp/cache/a"),
                size: 100,
                description: "a".to_string(),
                can_undo: true,
                undo_info: None,
            },
            CleanableItem {
                rule_id: "rule-1".to_string(),
                id: "b".to_string(),
                category: ItemCategory::Cache,
                path: PathBuf::from("/tmp/cache/b"),
                size: 200,
                description: "b".to_string(),
                can_undo: true,
                undo_info: None,
            },
        ],
    };

    let (paths, bytes) = clean_selection_summary_for_test(&scan, &roots, 1);
    assert_eq!(paths, vec!["/tmp/cache/b".to_string()]);
    assert_eq!(bytes, 200);
}

#[test]
fn format_bytes_for_test_uses_expected_units() {
    assert_eq!(format_bytes_for_test(12), "12 B");
    assert_eq!(format_bytes_for_test(2048), "2.00 KiB");
    assert_eq!(format_bytes_for_test(5 * 1024 * 1024), "5.00 MiB");
}

#[test]
fn top_level_system_command_option_matrix_parses() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["preen", "clean", "--dry-run", "--json"],
        vec!["preen", "clean", "--confirm", "--json"],
        vec![
            "preen",
            "clean",
            "--confirm",
            "--strategy",
            "delete",
            "--json",
        ],
        vec![
            "preen",
            "clean",
            "--confirm",
            "--strategy",
            "trash",
            "--json",
        ],
        vec!["preen", "uninstall", "DemoApp", "--dry-run", "--json"],
        vec!["preen", "uninstall", "DemoApp", "--confirm", "--json"],
        vec!["preen", "uninstall", "--paths", "--json"],
        vec!["preen", "optimize", "--dry-run", "--json"],
        vec!["preen", "optimize", "--confirm", "--json"],
        vec!["preen", "analyze", "/tmp", "--json"],
        vec!["preen", "status", "--json"],
        vec!["preen", "purge", "--dry-run", "--json"],
        vec!["preen", "purge", "--confirm", "--json"],
        vec!["preen", "purge", "--paths", "--json"],
        vec!["preen", "installer", "--dry-run", "--json"],
        vec!["preen", "installer", "--confirm", "--json"],
        vec!["preen", "installer", "--paths", "--json"],
        vec!["preen", "check", "--fix", "--json"],
        vec!["preen", "touchid", "enable", "--dry-run", "--json"],
        vec!["preen", "completion", "zsh", "--dry-run", "--json"],
        vec!["preen", "update", "--force", "--nightly", "--json"],
        vec!["preen", "remove", "--dry-run", "--json"],
    ];
    for args in cases {
        Cli::try_parse_from(args).unwrap();
    }
}

#[test]
fn top_level_system_commands_short_flags_parse() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["preen", "clean", "-n"],
        vec!["preen", "uninstall", "DemoApp", "-n"],
        vec!["preen", "optimize", "-n"],
        vec!["preen", "purge", "-n"],
        vec!["preen", "installer", "-n"],
        vec!["preen", "touchid", "-n"],
        vec!["preen", "completion", "-n"],
        vec!["preen", "update", "-f"],
        vec!["preen", "remove", "-n"],
    ];
    for args in cases {
        Cli::try_parse_from(args).unwrap();
    }
}

#[test]
fn top_level_system_commands_reject_unknown_flags() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["preen", "clean", "--unexpected-flag"],
        vec!["preen", "uninstall", "DemoApp", "--unexpected-flag"],
        vec!["preen", "optimize", "--unexpected-flag"],
        vec!["preen", "analyze", "--unexpected-flag"],
        vec!["preen", "status", "--unexpected-flag"],
        vec!["preen", "purge", "--unexpected-flag"],
        vec!["preen", "installer", "--unexpected-flag"],
        vec!["preen", "check", "--unexpected-flag"],
        vec!["preen", "touchid", "--unexpected-flag"],
        vec!["preen", "completion", "--unexpected-flag"],
        vec!["preen", "update", "--unexpected-flag"],
        vec!["preen", "remove", "--unexpected-flag"],
    ];
    for args in cases {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn clean_rejects_dry_run_with_confirm_conflict() {
    let parsed = Cli::try_parse_from(["preen", "clean", "--dry-run", "--confirm"]);
    assert!(parsed.is_err());
}

#[test]
fn uninstall_rejects_dry_run_with_confirm_conflict() {
    let parsed = Cli::try_parse_from(["preen", "uninstall", "DemoApp", "--dry-run", "--confirm"]);
    assert!(parsed.is_err());
}

#[test]
fn optimize_rejects_dry_run_with_confirm_conflict() {
    let parsed = Cli::try_parse_from(["preen", "optimize", "--dry-run", "--confirm"]);
    assert!(parsed.is_err());
}

#[test]
fn uninstall_paths_rejects_target_dry_run_or_confirm_conflicts() {
    let with_target = Cli::try_parse_from(["preen", "uninstall", "DemoApp", "--paths"]);
    assert!(with_target.is_err());
    let with_dry_run = Cli::try_parse_from(["preen", "uninstall", "--paths", "--dry-run"]);
    assert!(with_dry_run.is_err());
    let with_confirm = Cli::try_parse_from(["preen", "uninstall", "--paths", "--confirm"]);
    assert!(with_confirm.is_err());
}

#[test]
fn purge_rejects_dry_run_with_confirm_conflict() {
    let parsed = Cli::try_parse_from(["preen", "purge", "--dry-run", "--confirm"]);
    assert!(parsed.is_err());
}

#[test]
fn purge_paths_rejects_dry_run_or_confirm_conflicts() {
    let with_dry_run = Cli::try_parse_from(["preen", "purge", "--paths", "--dry-run"]);
    assert!(with_dry_run.is_err());
    let with_confirm = Cli::try_parse_from(["preen", "purge", "--paths", "--confirm"]);
    assert!(with_confirm.is_err());
}

#[test]
fn installer_rejects_dry_run_with_confirm_conflict() {
    let parsed = Cli::try_parse_from(["preen", "installer", "--dry-run", "--confirm"]);
    assert!(parsed.is_err());
}

#[test]
fn installer_paths_rejects_dry_run_or_confirm_conflicts() {
    let with_dry_run = Cli::try_parse_from(["preen", "installer", "--paths", "--dry-run"]);
    assert!(with_dry_run.is_err());
    let with_confirm = Cli::try_parse_from(["preen", "installer", "--paths", "--confirm"]);
    assert!(with_confirm.is_err());
}

#[test]
fn touchid_rejects_invalid_action() {
    let parsed = Cli::try_parse_from(["preen", "touchid", "invalid-action", "--dry-run"]);
    assert!(parsed.is_err());
}

#[test]
fn completion_rejects_invalid_shell() {
    let parsed = Cli::try_parse_from(["preen", "completion", "invalid-shell", "--dry-run"]);
    assert!(parsed.is_err());
}

#[test]
fn format_error_respects_json_flag() {
    let json_cli = Cli::try_parse_from(["preen", "plugin", "search", "--json"]).unwrap();
    let plain_cli = Cli::try_parse_from(["preen", "plugin", "search"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Trust,
        detail_code: None,
        message: "identity not allowed".to_string(),
    };

    let json_out = json_cli.format_error(&err);
    let parsed: Value = serde_json::from_str(&json_out).unwrap();
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "trust");
    assert_eq!(
        parsed["data"]["message"].as_str().unwrap(),
        "identity not allowed"
    );

    let plain_out = plain_cli.format_error(&err);
    assert!(plain_out.contains("kind=trust"));
    assert!(plain_out.contains("kind_label="));
    assert!(plain_out.contains("message="));
}

#[test]
fn format_error_uses_locale_and_hint_for_text_mode() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_LANG", "de-DE");
    }
    let plain_cli = Cli::try_parse_from(["preen", "plugin", "search"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Verification,
        detail_code: Some("preflight_os_target_failed".to_string()),
        message: "unsupported os target".to_string(),
    };
    let out = plain_cli.format_error(&err);
    assert!(out.contains("kind=verification"));
    assert!(out.contains("kind_label=Verifizierung"));
    assert!(out.contains("detail_code=preflight_os_target_failed"));
    assert!(out.contains("hint_code=os_target_failed"));
    assert!(out.contains("message=Plugin unterstuetzt dieses Betriebssystem nicht."));
    assert!(out.contains("Betriebssystem"));
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_LANG");
    }
}

#[test]
fn format_error_localizes_system_command_not_implemented_in_de() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_LANG", "de-DE");
    }
    let cli = Cli::try_parse_from(["preen", "status"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Unsupported,
        detail_code: Some("command_not_implemented".to_string()),
        message: "remove command is not implemented yet".to_string(),
    };
    let out = cli.format_error(&err);
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_LANG");
    }
    assert!(out.contains("kind=unsupported"));
    assert!(out.contains("kind_label=Nicht unterstuetzt"));
    assert!(out.contains("remove Befehl ist noch nicht implementiert."));
    assert!(!out.contains("hint_code="));
}

#[test]
fn format_error_localizes_clean_confirmation_in_de() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_LANG", "de-DE");
    }
    let cli = Cli::try_parse_from(["preen", "clean"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    let out = cli.format_error(&err);
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_LANG");
    }
    assert!(out.contains("detail_code=clean_confirmation_required"));
    assert!(out.contains("Clean-Anwenden benoetigt --confirm."));
    assert!(!out.contains("hint_code="));
}

#[test]
fn format_error_system_locale_fallback_to_en_us() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_LANG", "fr-FR");
    }
    let cli = Cli::try_parse_from(["preen", "status"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Unsupported,
        detail_code: Some("command_not_implemented".to_string()),
        message: "remove command is not implemented yet".to_string(),
    };
    let out = cli.format_error(&err);
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_LANG");
    }
    assert!(out.contains("kind_label=Unsupported"));
    assert!(out.contains("remove command is not implemented yet"));
}

#[test]
fn format_error_localizes_common_text_message_in_de() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_LANG", "de-DE");
    }
    let plain_cli = Cli::try_parse_from(["preen", "plugin", "search"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Trust,
        detail_code: None,
        message: "identity not allowed".to_string(),
    };
    let out = plain_cli.format_error(&err);
    assert!(out.contains("kind_label=Vertrauen"));
    assert!(out.contains("message=Identitaet ist nicht erlaubt."));
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_LANG");
    }
}

#[test]
fn run_typed_returns_validation_for_invalid_install_spec() {
    let cli =
        Cli::try_parse_from(["preen", "plugin", "install", "invalid-spec-without-rev"]).unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert!(err.message.contains("missing @<tag|commit>"));
}

#[test]
fn run_typed_returns_detail_code_for_install_clone_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let err = clone_rule_pack_for_test(
        "file:///definitely/missing/repo",
        "v0.0.1",
        &tmp.path().join("repo"),
    )
    .map(|_| ())
    .unwrap_err();
    let err = CliError::from(err);
    assert_eq!(err.kind, CliErrorKind::Internal);
    assert_eq!(err.detail_code.as_deref(), Some("install_clone_failed"));
}

#[test]
fn detail_code_hints_prioritize_security_and_compatibility() {
    let (code, action, priority) =
        hint_for_detail_code_for_test("preflight_signature_or_trust_failed");
    assert_eq!(code, "trust_or_signature_failed");
    assert_eq!(action, "check_sigstore_identity_and_trust_policy");
    assert_eq!(priority, 0);

    let (code, _, priority) = hint_for_detail_code_for_test("preflight_action_api_unsupported");
    assert_eq!(code, "action_api_unsupported");
    assert_eq!(priority, 1);

    let (code, _, priority) = hint_for_detail_code_for_test("verify_manifest_hash_drift");
    assert_eq!(code, "manifest_hash_drift");
    assert_eq!(priority, 2);

    let (code, _, priority) = hint_for_detail_code_for_test("test_signature_or_trust_failed");
    assert_eq!(code, "trust_or_signature_failed");
    assert_eq!(priority, 0);
}

#[test]
fn preflight_failure_row_formatter_uses_detail_code_hint() {
    let row = preflight_failure_row_for_test(
        "file:///missing/repo@deadbeef",
        "internal",
        Some("preflight_clone_failed"),
        "git clone failed",
        "en-US",
    );
    assert!(row.contains("detail_code=preflight_clone_failed"));
    assert!(row.contains("hint_code=source_checkout_failed"));
    assert!(row.contains("hint_action=validate_git_url_and_pinned_rev"));
}

#[test]
fn test_failure_row_formatter_falls_back_to_unknown_without_detail_code() {
    let row = test_failure_row_for_test(
        "test.pack",
        "verification",
        None,
        "plugin test report failed",
        "en-US",
    );
    assert!(row.contains("detail_code=none"));
    assert!(row.contains("hint_code=unknown_failure"));
    assert!(row.contains("hint_action=collect_logs_and_retry"));
}

#[test]
fn drift_hint_selects_highest_priority_failure() {
    let hint = primary_hint_for_drift_fields_for_test(&[
        "version",
        "manifest_hash",
        "signature_or_trust",
        "os_targets",
    ])
    .unwrap();
    assert_eq!(hint.0, "trust_or_signature_failed");
    assert_eq!(hint.2, 0);
}

#[test]
fn hint_message_supports_de_and_en_fallback() {
    let de = hint_message_for_test("os_target_failed", "de-DE");
    assert!(de.contains("Betriebssystem"));

    let en = hint_message_for_test("os_target_failed", "en-US");
    assert!(en.contains("operating system"));

    let fallback = hint_message_for_test("unknown_failure", "fr-FR");
    assert!(fallback.contains("Unknown failure"));
}

#[test]
fn cli_label_supports_de_and_fallback() {
    assert_eq!(cli_label_for_test("de-DE", "summary"), "Zusammenfassung");
    assert_eq!(cli_label_for_test("de-DE", "checks"), "Pruefungen");
    assert_eq!(cli_label_for_test("fr-FR", "summary"), "Summary");
}

#[test]
fn run_typed_returns_validation_for_invalid_preflight_spec() {
    let cli =
        Cli::try_parse_from(["preen", "plugin", "preflight", "invalid-spec-without-rev"]).unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(err.detail_code.as_deref(), Some("preflight_spec_invalid"));
    assert!(err.message.contains("missing @<tag|commit>"));
}

#[test]
fn run_typed_returns_validation_when_plugin_preflight_missing_target() {
    let cli = Cli::try_parse_from(["preen", "plugin", "preflight"]).unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert!(err.message.contains("spec is required unless --all is set"));
}

#[test]
fn run_typed_returns_not_found_for_missing_plugin_info() {
    let tmp = tempfile::tempdir().unwrap();
    let lockfile = tmp.path().join("missing.lock");
    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "info",
        "not.exist",
        "--lockfile",
        lockfile.to_str().unwrap(),
    ])
    .unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::NotFound);
    assert_eq!(err.message, "plugin not found");
}

#[test]
fn run_typed_returns_not_found_for_missing_plugin_test() {
    let tmp = tempfile::tempdir().unwrap();
    let lockfile = tmp.path().join("missing.lock");
    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "test",
        "not.exist",
        "--lockfile",
        lockfile.to_str().unwrap(),
    ])
    .unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::NotFound);
    assert_eq!(err.message, "plugin not found");
}

#[test]
fn install_verify_remove_lifecycle_with_temp_user_state_dirs() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{rev}", repo.to_string_lossy());
        let lockfile = tmp.path().join("plugins.lock");

        let install = Cli::try_parse_from([
            "preen",
            "plugin",
            "install",
            &spec,
            "--lockfile",
            lockfile.to_str().unwrap(),
        ])
        .unwrap();
        run_typed_with_verifier_for_test(install, &AlwaysOkVerifier).unwrap();

        let base_dir = plugin_install_base_dir_from_env();
        let pack_dir = base_dir.join("test.pack");
        assert!(pack_dir.exists(), "installed plugin dir missing");

        let verify = Cli::try_parse_from([
            "preen",
            "plugin",
            "verify",
            "test.pack",
            "--lockfile",
            lockfile.to_str().unwrap(),
        ])
        .unwrap();
        run_typed_with_verifier_for_test(verify, &AlwaysOkVerifier).unwrap();

        let remove = Cli::try_parse_from([
            "preen",
            "plugin",
            "remove",
            "test.pack",
            "--lockfile",
            lockfile.to_str().unwrap(),
        ])
        .unwrap();
        run_typed_with_verifier_for_test(remove, &AlwaysOkVerifier).unwrap();

        let lock = load_lockfile_at(&lockfile).unwrap();
        assert!(
            lock.plugins.is_empty(),
            "lockfile must be empty after remove"
        );
        assert!(!pack_dir.exists(), "plugin dir must be removed");

        let verify_after_remove = Cli::try_parse_from([
            "preen",
            "plugin",
            "verify",
            "test.pack",
            "--lockfile",
            lockfile.to_str().unwrap(),
        ])
        .unwrap();
        let err =
            run_typed_with_verifier_for_test(verify_after_remove, &AlwaysOkVerifier).unwrap_err();
        assert_eq!(err.kind, CliErrorKind::NotFound);
    });
}

#[test]
fn update_plugin_rewrites_tampered_lock_hashes() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{rev}", repo.to_string_lossy());
        let lockfile = tmp.path().join("plugins.lock");

        let install = Cli::try_parse_from([
            "preen",
            "plugin",
            "install",
            &spec,
            "--lockfile",
            lockfile.to_str().unwrap(),
        ])
        .unwrap();
        run_typed_with_verifier_for_test(install, &AlwaysOkVerifier).unwrap();

        let mut lock = load_lockfile_at(&lockfile).unwrap();
        lock.plugins[0].manifest_hash = "sha256:tampered".to_string();
        lock.plugins[0].signature = "sha256:tampered".to_string();
        save_lockfile_at(&lockfile, &lock).unwrap();

        let update = Cli::try_parse_from([
            "preen",
            "plugin",
            "update",
            "test.pack",
            "--lockfile",
            lockfile.to_str().unwrap(),
        ])
        .unwrap();
        run_typed_with_verifier_for_test(update, &AlwaysOkVerifier).unwrap();

        let repaired = load_lockfile_at(&lockfile).unwrap();
        assert_ne!(repaired.plugins[0].manifest_hash, "sha256:tampered");
        assert_ne!(repaired.plugins[0].signature, "sha256:tampered");
    });
}

#[test]
fn update_plugin_not_found_returns_not_found_error() {
    let tmp = tempfile::tempdir().unwrap();
    let lockfile = tmp.path().join("plugins.lock");
    save_lockfile_at(
        &lockfile,
        &PluginLockfile {
            schema_version: PluginLockfile::SCHEMA_V1,
            plugins: Vec::new(),
        },
    )
    .unwrap();
    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "update",
        "missing.pack",
        "--lockfile",
        lockfile.to_str().unwrap(),
    ])
    .unwrap();
    let err = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::NotFound);
}

#[test]
fn run_typed_returns_validation_when_plugin_test_missing_target() {
    let cli = Cli::try_parse_from(["preen", "plugin", "test"]).unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert!(
        err.message
            .contains("target is required unless --all is set")
    );
}

#[test]
fn run_typed_registry_update_rejects_invalid_identity() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_REGISTRY_SOURCE");
        std::env::remove_var("PREEN_REGISTRY_SIGNATURE_SOURCE");
        std::env::remove_var("PREEN_REGISTRY_IDENTITY");
        std::env::remove_var("PREEN_REGISTRY_ISSUER");
    }
    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        "file:///tmp/registry-index.toml",
        "--identity",
        "https://github.com/other-org/repo/.github/workflows/release.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Trust);
    assert!(err.message.contains("registry identity must start with"));
}

#[test]
fn run_typed_registry_update_rejects_invalid_issuer() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_REGISTRY_SOURCE");
        std::env::remove_var("PREEN_REGISTRY_SIGNATURE_SOURCE");
        std::env::remove_var("PREEN_REGISTRY_IDENTITY");
        std::env::remove_var("PREEN_REGISTRY_ISSUER");
    }
    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        "file:///tmp/registry-index.toml",
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://issuer.example.com",
    ])
    .unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Trust);
    assert!(err.message.contains("registry issuer must be"));
}

#[test]
fn write_registry_index_with_backup_creates_backup_and_updates_content() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("registry-index.toml");
    fs::write(&path, "old-index").unwrap();

    write_registry_index_with_backup_for_test(&path, "new-index").unwrap();
    let backup = registry_backup_path_for_test(&path);
    assert_eq!(fs::read_to_string(&path).unwrap(), "new-index");
    assert_eq!(fs::read_to_string(backup).unwrap(), "old-index");
}

#[test]
fn write_registry_index_with_backup_writes_new_file_without_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("registry-index.toml");
    assert!(!path.exists());

    write_registry_index_with_backup_for_test(&path, "content").unwrap();
    let backup = registry_backup_path_for_test(&path);
    assert_eq!(fs::read_to_string(&path).unwrap(), "content");
    assert!(!backup.exists());
}

#[test]
fn check_registry_freshness_rejects_stale_in_error_mode() {
    let generated_at = (OffsetDateTime::now_utc() - TimeDuration::days(45))
        .format(&Rfc3339)
        .unwrap();
    let err = check_registry_freshness_for_test(Some(&generated_at), "error", 30).unwrap_err();
    assert!(err.contains("stale"));
}

#[test]
fn check_registry_freshness_allows_stale_in_warn_mode() {
    let generated_at = (OffsetDateTime::now_utc() - TimeDuration::days(45))
        .format(&Rfc3339)
        .unwrap();
    let result = check_registry_freshness_for_test(Some(&generated_at), "warn", 30);
    assert!(result.is_ok());
}

#[test]
fn check_registry_freshness_rejects_invalid_mode_and_missing_generated_at_in_error_mode() {
    let generated_at = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let mode_err =
        check_registry_freshness_for_test(Some(&generated_at), "strict", 30).unwrap_err();
    assert!(mode_err.contains("PREEN_REGISTRY_STALE_MODE"));
    let missing_err = check_registry_freshness_for_test(None, "error", 30).unwrap_err();
    assert!(missing_err.contains("missing generated_at"));
}

#[test]
fn run_typed_registry_update_local_source_success_with_injected_verifier() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap();

    let written = fs::read_to_string(&cache).unwrap();
    assert!(written.contains("pack_id = \"preen-rs.homebrew\""));
}

#[test]
fn run_typed_registry_update_then_preflight_registry_spec_success() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    let preflight_cli =
        Cli::try_parse_from(["preen", "plugin", "preflight", "test.pack@0.1.0"]).unwrap();
    let result = run_typed_with_verifier_for_test(preflight_cli, &AlwaysOkVerifier);
    assert!(result.is_ok());
}

#[test]
fn registry_update_then_install_and_verify_registry_spec_success() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let lockfile = tmp.path().join("preen-plugins.lock");
    let install_dir = tmp.path().join("installed-plugins");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    let locked = install_plugin_in_dir_for_test(
        "test.pack@0.1.0",
        Some(&lockfile),
        &install_dir,
        &AlwaysOkVerifier,
    )
    .unwrap();

    assert_eq!(locked.pack_id, "test.pack");
    assert_eq!(locked.version, "0.1.0");
    assert!(install_dir.join("test.pack").join("manifest.toml").exists());

    let lock = load_lockfile_at(&lockfile).unwrap();
    assert_eq!(lock.plugins.len(), 1);
    assert_eq!(lock.plugins[0].pack_id, "test.pack");
    assert_eq!(lock.plugins[0].version, "0.1.0");

    let verify_text = plugin_verify_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        false,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap();
    assert!(verify_text.contains("summary: kind=verify pack_id=test.pack overall_passed=true"));
    assert!(verify_text.contains("checks: label=Checks"));
    assert_eq!(
        check_passed_from_verify_text(&verify_text, "version_matches_lock"),
        Some(true)
    );
    assert_eq!(
        check_passed_from_verify_text(&verify_text, "signature_verified"),
        Some(true)
    );
    assert_eq!(
        check_passed_from_verify_text(&verify_text, "trust_verified"),
        Some(true)
    );
    assert_eq!(
        check_passed_from_verify_text(&verify_text, "core_compat_verified"),
        Some(true)
    );
    assert_eq!(
        check_passed_from_verify_text(&verify_text, "action_api_verified"),
        Some(true)
    );
    assert_eq!(
        check_passed_from_verify_text(&verify_text, "os_target_verified"),
        Some(true)
    );

    let verify_json = plugin_verify_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&verify_json).unwrap();
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.verify");
    assert_eq!(parsed["data"]["pack_id"].as_str().unwrap(), "test.pack");
    assert!(parsed["data"]["manifest_hash_verified"].as_bool().unwrap());
    assert!(parsed["data"]["signature_hash_verified"].as_bool().unwrap());
    assert!(parsed["data"]["resolved_rev_verified"].as_bool().unwrap());
}

#[test]
fn registry_update_install_then_verify_fails_on_manifest_tamper() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let lockfile = tmp.path().join("preen-plugins.lock");
    let install_dir = tmp.path().join("installed-plugins");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    install_plugin_in_dir_for_test(
        "test.pack@0.1.0",
        Some(&lockfile),
        &install_dir,
        &AlwaysOkVerifier,
    )
    .unwrap();

    let manifest_path = install_dir.join("test.pack").join("manifest.toml");
    let mut manifest = fs::read_to_string(&manifest_path).unwrap();
    manifest.push_str("\n# tampered\n");
    fs::write(&manifest_path, manifest).unwrap();

    let err = plugin_verify_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        false,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap_err();
    assert!(err.contains("__preen_kind:verification__"));
    assert!(err.contains("preen_code:verify_manifest_hash_drift"));
    assert!(err.contains("manifest hash mismatch"));
}

#[test]
fn registry_update_install_then_verify_fails_on_signature_or_trust() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let lockfile = tmp.path().join("preen-plugins.lock");
    let install_dir = tmp.path().join("installed-plugins");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    install_plugin_in_dir_for_test(
        "test.pack@0.1.0",
        Some(&lockfile),
        &install_dir,
        &AlwaysOkVerifier,
    )
    .unwrap();

    let err = plugin_verify_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        true,
        "en-US",
        &AlwaysFailVerifier,
    )
    .unwrap_err();
    assert!(err.contains("__preen_kind:verification__"));
    assert!(err.contains("preen_code:verify_signature_or_trust_failed"));
    assert!(err.contains("verification failed"));
}

#[test]
fn registry_update_install_then_test_detects_manifest_tamper() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let lockfile = tmp.path().join("preen-plugins.lock");
    let install_dir = tmp.path().join("installed-plugins");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    install_plugin_in_dir_for_test(
        "test.pack@0.1.0",
        Some(&lockfile),
        &install_dir,
        &AlwaysOkVerifier,
    )
    .unwrap();

    let manifest_path = install_dir.join("test.pack").join("manifest.toml");
    let mut manifest = fs::read_to_string(&manifest_path).unwrap();
    manifest.push_str("\n# tampered\n");
    fs::write(&manifest_path, manifest).unwrap();

    let text = plugin_test_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        false,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap();
    assert!(text.contains("summary: kind=test pack_id=test.pack overall_passed=false"));
    assert!(text.contains("drift: field=manifest_hash"));

    let json = plugin_test_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.test");
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("test_manifest_hash_drift")
    );
    let drifts = parsed["data"]["drifts"].as_array().unwrap();
    assert!(
        drifts
            .iter()
            .any(|drift| drift["field"].as_str() == Some("manifest_hash"))
    );
}

#[test]
fn registry_update_install_then_test_detects_signature_tamper() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let lockfile = tmp.path().join("preen-plugins.lock");
    let install_dir = tmp.path().join("installed-plugins");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    install_plugin_in_dir_for_test(
        "test.pack@0.1.0",
        Some(&lockfile),
        &install_dir,
        &AlwaysOkVerifier,
    )
    .unwrap();

    let signature_path = install_dir.join("test.pack").join("manifest.sig");
    let mut signature = fs::read_to_string(&signature_path).unwrap();
    signature.push_str("\n# tampered\n");
    fs::write(&signature_path, signature).unwrap();

    let json = plugin_test_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("test_signature_hash_drift")
    );
    let drifts = parsed["data"]["drifts"].as_array().unwrap();
    assert!(
        drifts
            .iter()
            .any(|drift| drift["field"].as_str() == Some("signature_hash"))
    );
}

#[test]
fn registry_update_install_then_test_detects_resolved_rev_drift() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let lockfile = tmp.path().join("preen-plugins.lock");
    let install_dir = tmp.path().join("installed-plugins");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    install_plugin_in_dir_for_test(
        "test.pack@0.1.0",
        Some(&lockfile),
        &install_dir,
        &AlwaysOkVerifier,
    )
    .unwrap();

    let mut lock = load_lockfile_at(&lockfile).unwrap();
    lock.plugins[0].resolved_rev = Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string());
    save_lockfile_at(&lockfile, &lock).unwrap();

    let text = plugin_test_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        false,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap();
    assert!(text.contains("summary: kind=test pack_id=test.pack overall_passed=false"));
    assert!(text.contains("primary_failure: detail_code=test_resolved_rev_drift"));
    assert!(text.contains("drift: field=resolved_rev"));
}

#[test]
fn registry_update_install_then_test_detects_version_drift() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let lockfile = tmp.path().join("preen-plugins.lock");
    let install_dir = tmp.path().join("installed-plugins");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    install_plugin_in_dir_for_test(
        "test.pack@0.1.0",
        Some(&lockfile),
        &install_dir,
        &AlwaysOkVerifier,
    )
    .unwrap();

    let mut lock = load_lockfile_at(&lockfile).unwrap();
    lock.plugins[0].version = "0.1.1".to_string();
    save_lockfile_at(&lockfile, &lock).unwrap();

    let json = plugin_test_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("test_version_drift")
    );
    assert!(!parsed["data"]["version_matches_lock"].as_bool().unwrap());
    assert_eq!(
        check_passed_from_json(&parsed["data"], "version_matches_lock"),
        Some(false)
    );
    let drifts = parsed["data"]["drifts"].as_array().unwrap();
    assert!(
        drifts
            .iter()
            .any(|drift| drift["field"].as_str() == Some("version"))
    );
}

#[test]
fn registry_update_install_then_test_detects_signature_or_trust_drift() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let lockfile = tmp.path().join("preen-plugins.lock");
    let install_dir = tmp.path().join("installed-plugins");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    install_plugin_in_dir_for_test(
        "test.pack@0.1.0",
        Some(&lockfile),
        &install_dir,
        &AlwaysOkVerifier,
    )
    .unwrap();

    let json = plugin_test_for_test(
        "test.pack",
        Some(&lockfile),
        &install_dir,
        true,
        "en-US",
        &AlwaysFailVerifier,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("test_signature_or_trust_failed")
    );
    assert!(!parsed["data"]["signature_verified"].as_bool().unwrap());
    assert!(!parsed["data"]["trust_verified"].as_bool().unwrap());
    assert_eq!(
        check_passed_from_json(&parsed["data"], "signature_verified"),
        Some(false)
    );
    assert_eq!(
        check_passed_from_json(&parsed["data"], "trust_verified"),
        Some(false)
    );
    let drifts = parsed["data"]["drifts"].as_array().unwrap();
    assert!(
        drifts
            .iter()
            .any(|drift| drift["field"].as_str() == Some("signature_or_trust"))
    );
}

#[test]
fn registry_update_install_then_test_all_includes_failure_row_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);

    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");
    let lockfile = tmp.path().join("preen-plugins.lock");
    let install_dir = tmp.path().join("installed-plugins");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "test.pack"
name = "Test Pack"
description = "Cleanup pack"
repo_url = "file://{}"
latest_version = "0.1.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{rev}"
"#,
            repo.display(),
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let update_cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    run_typed_with_verifier_for_test(update_cli, &AlwaysOkVerifier).unwrap();

    install_plugin_in_dir_for_test(
        "test.pack@0.1.0",
        Some(&lockfile),
        &install_dir,
        &AlwaysOkVerifier,
    )
    .unwrap();

    let manifest_path = install_dir.join("test.pack").join("manifest.toml");
    let mut manifest = fs::read_to_string(&manifest_path).unwrap();
    manifest.push_str("\n# tampered\n");
    fs::write(&manifest_path, manifest).unwrap();

    let json =
        plugin_test_all_for_test(Some(&lockfile), &install_dir, true, &AlwaysOkVerifier).unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.test_all");
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(parsed["data"]["failed"].as_u64(), Some(1));

    let failures = parsed["data"]["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["pack_id"].as_str(), Some("test.pack"));
    assert_eq!(failures[0]["error_kind"].as_str(), Some("verification"));
    assert_eq!(
        failures[0]["detail_code"].as_str(),
        Some("test_manifest_hash_drift")
    );
}

#[test]
fn run_typed_registry_update_local_source_verification_failure() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{now}"

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS");
    }

    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    let err = run_typed_with_verifier_for_test(cli, &AlwaysFailVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Verification);
    assert!(
        err.message
            .contains("registry signature verification failed")
    );
    assert!(!cache.exists());
}

#[test]
fn run_typed_registry_update_stale_error_mode_blocks_write() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");

    let old = (OffsetDateTime::now_utc() - TimeDuration::days(100))
        .format(&Rfc3339)
        .unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{old}"

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "error");
        std::env::set_var("PREEN_REGISTRY_MAX_AGE_DAYS", "30");
    }

    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    let err = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert!(err.message.contains("stale"));
    assert!(!cache.exists());
}

#[test]
fn run_typed_registry_update_strict_overrides_warn_mode() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");

    let old = (OffsetDateTime::now_utc() - TimeDuration::days(100))
        .format(&Rfc3339)
        .unwrap();
    fs::write(
        &index,
        format!(
            r#"
schema_version = 1
generated_at = "{old}"

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#
        ),
    )
    .unwrap();
    fs::write(&sig, "sig").unwrap();

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", "warn");
        std::env::set_var("PREEN_REGISTRY_MAX_AGE_DAYS", "30");
    }

    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--strict",
        "--source",
        &format!("file://{}", index.display()),
        "--signature-source",
        &format!("file://{}", sig.display()),
        "--identity",
        "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
        "--issuer",
        "https://token.actions.githubusercontent.com",
    ])
    .unwrap();
    let err = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert!(err.message.contains("stale"));
    assert!(!cache.exists());
}

#[test]
fn run_typed_preflight_local_git_success_with_injected_verifier() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);
    let spec = format!("file://{}@{}", repo.display(), rev);
    let cli = Cli::try_parse_from(["preen", "plugin", "preflight", &spec]).unwrap();
    let result = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier);
    assert!(result.is_ok());
}

#[test]
fn run_typed_preflight_local_git_verification_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);
    let spec = format!("file://{}@{}", repo.display(), rev);
    let cli = Cli::try_parse_from(["preen", "plugin", "preflight", &spec]).unwrap();
    let err = run_typed_with_verifier_for_test(cli, &AlwaysFailVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Verification);
}

#[test]
fn run_typed_preflight_local_git_old_tag_success_with_injected_verifier() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo_with_old_tag(&repo);
    let spec = format!("file://{}@{}", repo.display(), rev);
    let cli = Cli::try_parse_from(["preen", "plugin", "preflight", &spec]).unwrap();
    let result = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier);
    assert!(result.is_ok());
}

#[test]
fn run_typed_preflight_all_local_git_success_with_injected_verifier() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);
    let lockfile = tmp.path().join("preen-plugins.lock");
    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![LockedPlugin {
            pack_id: "test.pack".to_string(),
            source: "git".to_string(),
            url: format!("file://{}", repo.display()),
            rev: rev.clone(),
            resolved_rev: Some(rev),
            version: "0.1.0".to_string(),
            manifest_hash: "sha256:deadbeef".to_string(),
            signature: "sha256:cafebabe".to_string(),
            trusted_identity:
                "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0"
                    .to_string(),
        }],
    };
    save_lockfile_at(&lockfile, &lock).unwrap();
    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "preflight",
        "--all",
        "--lockfile",
        lockfile.to_str().unwrap(),
    ])
    .unwrap();
    let result = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier);
    assert!(result.is_ok());
}

#[test]
fn run_typed_preflight_all_returns_verification_error_when_any_item_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);
    let lockfile = tmp.path().join("preen-plugins.lock");
    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![
            LockedPlugin {
                pack_id: "test.pack".to_string(),
                source: "git".to_string(),
                url: format!("file://{}", repo.display()),
                rev,
                resolved_rev: None,
                version: "0.1.0".to_string(),
                manifest_hash: "sha256:deadbeef".to_string(),
                signature: "sha256:cafebabe".to_string(),
                trusted_identity:
                    "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0"
                        .to_string(),
            },
            LockedPlugin {
                pack_id: "bad.pack".to_string(),
                source: "git".to_string(),
                url: "file:///definitely/missing/repo".to_string(),
                rev: "deadbeef".to_string(),
                resolved_rev: None,
                version: "0.1.0".to_string(),
                manifest_hash: "sha256:deadbeef".to_string(),
                signature: "sha256:cafebabe".to_string(),
                trusted_identity: "https://github.com/Preen-rs/test".to_string(),
            },
        ],
    };
    save_lockfile_at(&lockfile, &lock).unwrap();
    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "preflight",
        "--all",
        "--lockfile",
        lockfile.to_str().unwrap(),
    ])
    .unwrap();
    let err = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Verification);
    assert_eq!(err.detail_code.as_deref(), Some("preflight_all_failed"));
}

#[test]
fn preflight_all_json_includes_clone_failure_detail_code() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);
    let lockfile = tmp.path().join("preen-plugins.lock");
    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![
            LockedPlugin {
                pack_id: "ok.pack".to_string(),
                source: "git".to_string(),
                url: format!("file://{}", repo.display()),
                rev,
                resolved_rev: None,
                version: "0.1.0".to_string(),
                manifest_hash: "sha256:deadbeef".to_string(),
                signature: "sha256:cafebabe".to_string(),
                trusted_identity:
                    "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0"
                        .to_string(),
            },
            LockedPlugin {
                pack_id: "bad.pack".to_string(),
                source: "git".to_string(),
                url: "file:///definitely/missing/repo".to_string(),
                rev: "deadbeef".to_string(),
                resolved_rev: None,
                version: "0.1.0".to_string(),
                manifest_hash: "sha256:deadbeef".to_string(),
                signature: "sha256:cafebabe".to_string(),
                trusted_identity: "https://github.com/Preen-rs/test".to_string(),
            },
        ],
    };
    save_lockfile_at(&lockfile, &lock).unwrap();

    let json = plugin_preflight_all_for_test(Some(&lockfile), &AlwaysOkVerifier).unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.preflight_all");
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(parsed["data"]["failed"].as_u64(), Some(1));
    let failures = parsed["data"]["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures[0]["detail_code"].as_str(),
        Some("preflight_clone_failed")
    );
}

#[test]
fn preflight_all_json_includes_signature_or_trust_detail_code() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);
    let lockfile = tmp.path().join("preen-plugins.lock");
    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![LockedPlugin {
            pack_id: "ok.pack".to_string(),
            source: "git".to_string(),
            url: format!("file://{}", repo.display()),
            rev,
            resolved_rev: None,
            version: "0.1.0".to_string(),
            manifest_hash: "sha256:deadbeef".to_string(),
            signature: "sha256:cafebabe".to_string(),
            trusted_identity:
                "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0"
                    .to_string(),
        }],
    };
    save_lockfile_at(&lockfile, &lock).unwrap();

    let json = plugin_preflight_all_for_test(Some(&lockfile), &AlwaysFailVerifier).unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.preflight_all");
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(parsed["data"]["failed"].as_u64(), Some(1));
    let failures = parsed["data"]["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures[0]["detail_code"].as_str(),
        Some("preflight_signature_or_trust_failed")
    );
    let (code, _, priority) =
        hint_for_detail_code_for_test(failures[0]["detail_code"].as_str().unwrap());
    assert_eq!(code, "trust_or_signature_failed");
    assert_eq!(priority, 0);
}

#[test]
fn run_typed_test_all_returns_verification_error_when_any_item_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let lockfile = tmp.path().join("preen-plugins.lock");
    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![LockedPlugin {
            pack_id: "missing.pack".to_string(),
            source: "git".to_string(),
            url: "file:///missing/repo".to_string(),
            rev: "deadbeef".to_string(),
            resolved_rev: None,
            version: "0.1.0".to_string(),
            manifest_hash: "sha256:deadbeef".to_string(),
            signature: "sha256:cafebabe".to_string(),
            trusted_identity: "https://github.com/Preen-rs/test".to_string(),
        }],
    };
    save_lockfile_at(&lockfile, &lock).unwrap();
    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "test",
        "--all",
        "--lockfile",
        lockfile.to_str().unwrap(),
    ])
    .unwrap();
    let err = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Verification);
    assert_eq!(err.detail_code.as_deref(), Some("test_all_failed"));
}

#[test]
fn run_typed_test_local_git_spec_success_with_injected_verifier() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let rev = init_preflight_git_repo(&repo);
    let spec = format!("file://{}@{}", repo.display(), rev);
    let cli = Cli::try_parse_from(["preen", "plugin", "test", &spec]).unwrap();
    let result = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier);
    assert!(result.is_ok());
}

#[test]
fn json_mode_formats_typed_error_as_error_envelope() {
    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "install",
        "invalid-spec-without-rev",
        "--json",
    ])
    .unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    let out = cli.format_error(&err);
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "validation");
    assert!(
        parsed["data"]["message"]
            .as_str()
            .unwrap()
            .contains("missing @<tag|commit>")
    );
}

#[test]
fn tagged_error_decodes_deterministically() {
    let cases = [
        (
            "__preen_kind:not_found__plugin not found",
            CliErrorKind::NotFound,
            None,
            "plugin not found",
        ),
        (
            "__preen_kind:validation__preen_code:preflight_spec_invalid__missing @<tag|commit> in install spec",
            CliErrorKind::Validation,
            Some("preflight_spec_invalid"),
            "missing @<tag|commit> in install spec",
        ),
        (
            "__preen_kind:internal__preen_code:install_clone_failed__git command failed: clone",
            CliErrorKind::Internal,
            Some("install_clone_failed"),
            "git command failed: clone",
        ),
        (
            "__preen_kind:verification__preen_code:test_all_failed__2 plugin test checks failed",
            CliErrorKind::Verification,
            Some("test_all_failed"),
            "2 plugin test checks failed",
        ),
    ];

    for (raw, expected_kind, expected_detail_code, expected_message) in cases {
        let err = CliError::from(raw.to_string());
        assert_eq!(err.kind, expected_kind);
        assert_eq!(err.detail_code.as_deref(), expected_detail_code);
        assert_eq!(err.message, expected_message);
    }
}

#[test]
fn clean_runtime_command_denied_maps_expected_detail_code() {
    let detail = clean_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandDenied {
            command: "echo".to_string(),
        },
    ));
    assert_eq!(detail.as_deref(), Some("clean_command_denied"));
}

#[test]
fn clean_runtime_command_timeout_maps_expected_detail_code() {
    let detail = clean_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandTimeout {
            command: "echo".to_string(),
            timeout_sec: 5,
        },
    ));
    assert_eq!(detail.as_deref(), Some("clean_command_timeout"));
}

#[test]
fn clean_runtime_command_non_zero_maps_expected_detail_code() {
    let detail = clean_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandNonZero {
            command: "echo".to_string(),
            code: Some(12),
        },
    ));
    assert_eq!(detail.as_deref(), Some("clean_command_non_zero"));
}

#[test]
fn installer_runtime_command_denied_maps_expected_detail_code() {
    let detail = installer_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandDenied {
            command: "echo".to_string(),
        },
    ));
    assert_eq!(detail.as_deref(), Some("installer_command_denied"));
}

#[test]
fn installer_runtime_command_timeout_maps_expected_detail_code() {
    let detail = installer_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandTimeout {
            command: "echo".to_string(),
            timeout_sec: 5,
        },
    ));
    assert_eq!(detail.as_deref(), Some("installer_command_timeout"));
}

#[test]
fn installer_runtime_command_non_zero_maps_expected_detail_code() {
    let detail = installer_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandNonZero {
            command: "echo".to_string(),
            code: Some(12),
        },
    ));
    assert_eq!(detail.as_deref(), Some("installer_command_non_zero"));
}

#[test]
fn uninstall_runtime_command_denied_maps_expected_detail_code() {
    let detail = uninstall_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandDenied {
            command: "echo".to_string(),
        },
    ));
    assert_eq!(detail.as_deref(), Some("uninstall_command_denied"));
}

#[test]
fn uninstall_runtime_command_timeout_maps_expected_detail_code() {
    let detail = uninstall_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandTimeout {
            command: "echo".to_string(),
            timeout_sec: 5,
        },
    ));
    assert_eq!(detail.as_deref(), Some("uninstall_command_timeout"));
}

#[test]
fn uninstall_runtime_command_non_zero_maps_expected_detail_code() {
    let detail = uninstall_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandNonZero {
            command: "echo".to_string(),
            code: Some(12),
        },
    ));
    assert_eq!(detail.as_deref(), Some("uninstall_command_non_zero"));
}

#[test]
fn optimize_runtime_command_denied_maps_expected_detail_code() {
    let detail = optimize_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandDenied {
            command: "echo".to_string(),
        },
    ));
    assert_eq!(detail.as_deref(), Some("optimize_command_denied"));
}

#[test]
fn optimize_runtime_command_timeout_maps_expected_detail_code() {
    let detail = optimize_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandTimeout {
            command: "echo".to_string(),
            timeout_sec: 5,
        },
    ));
    assert_eq!(detail.as_deref(), Some("optimize_command_timeout"));
}

#[test]
fn optimize_runtime_command_non_zero_maps_expected_detail_code() {
    let detail = optimize_runtime_error_detail_code_for_test(RuntimeExecutionError::Execute(
        ActionExecutionError::CommandNonZero {
            command: "echo".to_string(),
            code: Some(12),
        },
    ));
    assert_eq!(detail.as_deref(), Some("optimize_command_non_zero"));
}

#[test]
fn load_lockfile_missing_file_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("missing.lock");
    let loaded = load_lockfile_at(&path).unwrap();
    assert_eq!(loaded.plugins.len(), 0);
    assert_eq!(loaded.schema_version, PluginLockfile::SCHEMA_V1);
}

#[test]
fn load_lockfile_invalid_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bad.lock");
    fs::write(&path, "not = [toml").unwrap();
    let err = load_lockfile_at(&path).unwrap_err();
    assert!(err.contains("lockfile parse error"));
}

#[test]
fn load_lockfile_duplicate_pack_id_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("dup.lock");
    let content = r#"
schema_version = 1

[[plugins]]
pack_id = "dup.pack"
source = "git"
url = "https://github.com/Preen-rs/test"
rev = "abc123"
version = "0.1.0"
manifest_hash = "sha256:deadbeef"
signature = "sha256:cafebabe"
trusted_identity = "https://github.com/Preen-rs/test"

[[plugins]]
pack_id = "dup.pack"
source = "git"
url = "https://github.com/Preen-rs/test2"
rev = "def456"
version = "0.1.1"
manifest_hash = "sha256:deadbeef"
signature = "sha256:cafebabe"
trusted_identity = "https://github.com/Preen-rs/test"
"#;
    fs::write(&path, content).unwrap();
    let err = load_lockfile_at(&path).unwrap_err();
    assert!(err.contains("DuplicatePackId"));
}

#[test]
fn preferred_lockfile_read_path_uses_default_when_present() {
    let tmp = tempfile::tempdir().unwrap();
    let default_path = tmp.path().join("state").join("plugins.lock");
    let legacy_path = tmp.path().join("preen-plugins.lock");
    fs::create_dir_all(default_path.parent().unwrap()).unwrap();
    fs::write(&default_path, "schema_version = 1\n").unwrap();
    fs::write(&legacy_path, "schema_version = 1\n").unwrap();

    let selected = preferred_lockfile_read_path_for_test(&default_path, &legacy_path);
    assert_eq!(selected, default_path);
}

#[test]
fn preferred_lockfile_read_path_falls_back_to_legacy_when_default_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let default_path = tmp.path().join("state").join("plugins.lock");
    let legacy_path = tmp.path().join("preen-plugins.lock");
    fs::write(&legacy_path, "schema_version = 1\n").unwrap();

    let selected = preferred_lockfile_read_path_for_test(&default_path, &legacy_path);
    assert_eq!(selected, legacy_path);
}

#[test]
fn preferred_lockfile_read_path_prefers_default_path_when_both_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let default_path = tmp.path().join("state").join("plugins.lock");
    let legacy_path = tmp.path().join("preen-plugins.lock");

    let selected = preferred_lockfile_read_path_for_test(&default_path, &legacy_path);
    assert_eq!(selected, default_path);
}

#[test]
fn lockfile_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("preen-plugins.lock");

    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![LockedPlugin {
            pack_id: "test.pack".to_string(),
            source: "git".to_string(),
            url: "https://github.com/Preen-rs/test".to_string(),
            rev: "abc123".to_string(),
            resolved_rev: None,
            version: "0.1.0".to_string(),
            manifest_hash: "sha256:deadbeef".to_string(),
            signature: "sha256:cafebabe".to_string(),
            trusted_identity: "https://github.com/Preen-rs/test".to_string(),
        }],
    };

    save_lockfile_at(&path, &lock).unwrap();
    let loaded = load_lockfile_at(&path).unwrap();
    assert_eq!(loaded.plugins.len(), 1);
    assert_eq!(loaded.plugins[0].pack_id, "test.pack");

    fs::remove_file(path).unwrap();
}

#[test]
fn verify_lockfile_hashes_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let pack_dir = base.join("test.pack");
    fs::create_dir_all(&pack_dir).unwrap();
    fs::write(pack_dir.join("manifest.toml"), "manifest").unwrap();
    fs::write(pack_dir.join("manifest.sig"), "sig").unwrap();

    let manifest_hash = preen_cli::hash_file_for_test(&pack_dir.join("manifest.toml")).unwrap();
    let sig_hash = preen_cli::hash_file_for_test(&pack_dir.join("manifest.sig")).unwrap();

    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![LockedPlugin {
            pack_id: "test.pack".to_string(),
            source: "git".to_string(),
            url: "https://github.com/Preen-rs/test".to_string(),
            rev: "abc123".to_string(),
            resolved_rev: None,
            version: "0.1.0".to_string(),
            manifest_hash,
            signature: sig_hash,
            trusted_identity: "https://github.com/Preen-rs/test".to_string(),
        }],
    };

    verify_lockfile_hashes(&lock, base).unwrap();
}

#[test]
fn verify_lockfile_hashes_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let pack_dir = base.join("test.pack");
    fs::create_dir_all(&pack_dir).unwrap();
    fs::write(pack_dir.join("manifest.toml"), "manifest").unwrap();
    fs::write(pack_dir.join("manifest.sig"), "sig").unwrap();

    let lock = PluginLockfile {
        schema_version: PluginLockfile::SCHEMA_V1,
        plugins: vec![LockedPlugin {
            pack_id: "test.pack".to_string(),
            source: "git".to_string(),
            url: "https://github.com/Preen-rs/test".to_string(),
            rev: "abc123".to_string(),
            resolved_rev: None,
            version: "0.1.0".to_string(),
            manifest_hash: "sha256:deadbeef".to_string(),
            signature: "sha256:cafebabe".to_string(),
            trusted_identity: "https://github.com/Preen-rs/test".to_string(),
        }],
    };

    let err = verify_lockfile_hashes(&lock, base).unwrap_err();
    assert!(err.contains("hash mismatch"));
}

#[test]
fn trust_policy_from_str_ok() {
    let input = r#"
        allowlist = ["id1", "id2"]
        require_signed = true
    "#;
    let policy = trust_policy_from_str(input).unwrap();
    assert_eq!(policy.allowlist.len(), 2);
    assert!(policy.require_signed);
}

#[test]
fn trust_policy_from_str_invalid() {
    let input = "allowlist = [";
    assert!(trust_policy_from_str(input).is_err());
}

#[test]
fn trust_policy_rejects_require_signed_false() {
    let input = r#"
        allowlist = []
        require_signed = false
    "#;
    let err = trust_policy_from_str(input).unwrap_err();
    assert!(err.contains("require_signed=false"));
}
