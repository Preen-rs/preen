use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use async_trait::async_trait;
use clap::Parser;
use preen_cli::{
    Cli, CliError, CliErrorKind, analyze_output_for_test, analyze_output_with_debug_for_test,
    analyze_output_with_depth_for_test, analyze_selection_for_trash_for_test,
    analyze_text_output_for_test, check_output_for_test, check_output_with_debug_for_test,
    check_registry_freshness_for_test, check_text_output_for_test, clean_output_for_test,
    clean_runtime_error_detail_code_for_test, clean_selection_summary_for_test,
    clean_text_output_for_test, clean_whitelist_output_for_test,
    clean_whitelist_text_output_for_test, cli_label_for_test, clone_rule_pack_for_test,
    completion_output_for_test, completion_text_output_for_test, default_signature_source_for_test,
    enforce_clean_scope_for_test, enforce_installer_scope_for_test,
    enforce_uninstall_scope_for_test, error_json_for_test, format_bytes_for_test,
    hint_for_detail_code_for_test, hint_message_for_test, install_plugin_in_dir_for_test,
    installer_output_for_test, installer_output_with_debug_for_test, installer_paths_json_for_test,
    installer_paths_text_for_test, installer_runtime_error_detail_code_for_test,
    installer_text_output_for_test, is_git_filter_unsupported_error_for_test,
    is_system_detail_code_for_test, list_plugins_with_options_for_test, load_lockfile_at,
    map_clone_error_detail_code_for_test, map_error_with_detail_code_for_test,
    optimize_output_for_test, optimize_output_with_debug_for_test,
    optimize_output_with_executor_for_test, optimize_runtime_error_detail_code_for_test,
    optimize_text_output_for_test, optimize_whitelist_output_for_test,
    optimize_whitelist_text_output_for_test, parse_install_spec, parse_plugin_spec,
    plugin_info_json_for_test, plugin_install_json_for_test, plugin_install_text_for_test,
    plugin_list_json_for_test, plugin_preflight_all_for_test, plugin_preflight_all_json_for_test,
    plugin_preflight_json_for_test, plugin_remove_json_for_test, plugin_test_all_for_test,
    plugin_test_all_json_for_test, plugin_test_for_test, plugin_test_json_for_test,
    plugin_test_spec_json_for_test, plugin_update_json_for_test, plugin_update_text_for_test,
    plugin_verify_for_test, plugin_verify_json_for_test, plugin_verify_text_for_test,
    preferred_lockfile_read_path_for_test, preflight_failure_row_for_test,
    primary_hint_for_drift_fields_for_test, progress_line_for_test, purge_output_for_test,
    purge_output_with_debug_for_test, purge_paths_json_for_test, purge_paths_text_for_test,
    purge_text_output_for_test, registry_backup_path_for_test,
    registry_source_detail_code_for_test, registry_update_json_for_test, remove_output_for_test,
    remove_text_output_for_test, resolve_registry_for_test, run_typed,
    run_typed_with_verifier_and_clean_executor_for_test, run_typed_with_verifier_for_test,
    runtime_error_detail_code_for_prefix_for_test, save_lockfile_at, search_registry_for_test,
    search_registry_json_for_test, search_registry_with_options_for_test,
    should_emit_formatted_error, status_output_for_test, status_should_emit_json_for_test,
    status_text_output_for_test, status_watch_output_for_test, test_failure_row_for_test,
    touchid_output_for_test, touchid_text_output_for_test, trust_policy_from_str,
    uninstall_output_for_test, uninstall_output_with_debug_for_test, uninstall_paths_json_for_test,
    uninstall_paths_text_for_test, uninstall_runtime_error_detail_code_for_test,
    uninstall_text_output_for_test, update_output_for_test, update_output_with_execute_for_test,
    update_text_output_for_test, validate_registry_trust_inputs_for_test, verify_lockfile_hashes,
    write_registry_index_with_backup_for_test,
};
use preen_core::action_runtime::{
    ActionExecutionError, ActionExecutionResult, ActionExecutorPort, ExecutionPlan, PlanError,
    RuntimeExecutionError, SafetyViolation,
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

fn static_detail_codes_from_source_for_test() -> BTreeSet<String> {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");
    let source = fs::read_to_string(source_path).unwrap();
    let mut codes = BTreeSet::new();
    let mut cursor = 0;
    while let Some(rel) = source[cursor..].find("err_code(") {
        let start = cursor + rel + "err_code(".len();
        let segment = &source[start..];
        if let Some(first_comma_rel) = segment.find(',') {
            let second_arg = segment[(first_comma_rel + 1)..].trim_start();
            if let Some(without_opening_quote) = second_arg.strip_prefix('"')
                && let Some(end_quote_rel) = without_opening_quote.find('"')
            {
                let code = &without_opening_quote[..end_quote_rel];
                if !code.is_empty() && code.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_') {
                    codes.insert(code.to_string());
                }
            }
        }
        cursor = start;
    }
    codes
}

fn json_kinds_from_source_for_test() -> BTreeSet<String> {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");
    let source = fs::read_to_string(source_path).unwrap();
    let mut kinds = BTreeSet::new();
    let mut cursor = 0;
    while let Some(rel) = source[cursor..].find("to_json_envelope(") {
        let start = cursor + rel + "to_json_envelope(".len();
        let segment = &source[start..];
        let first_arg = segment.trim_start();
        if let Some(without_opening_quote) = first_arg.strip_prefix('"')
            && let Some(end_quote_rel) = without_opening_quote.find('"')
        {
            let kind = &without_opening_quote[..end_quote_rel];
            if !kind.is_empty() {
                kinds.insert(kind.to_string());
            }
        }
        cursor = start;
    }
    kinds
}

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

struct MissingCertVerifier;

impl SignatureVerifier for MissingCertVerifier {
    fn verify(&self, _input: VerificationInput) -> Result<VerificationOutcome, VerifyError> {
        Err(VerifyError::SignatureInvalid(
            "manifest certificate is missing".to_string(),
        ))
    }
}

struct UntrustedIdentityVerifier;

impl SignatureVerifier for UntrustedIdentityVerifier {
    fn verify(&self, _input: VerificationInput) -> Result<VerificationOutcome, VerifyError> {
        Ok(VerificationOutcome {
            identity:
                "https://github.com/Preen-rs/other/.github/workflows/release.yml@refs/heads/main"
                    .to_string(),
        })
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

struct AlwaysSuccessExecutor;

#[async_trait]
impl ActionExecutorPort for AlwaysSuccessExecutor {
    async fn execute(
        &self,
        _plan: &ExecutionPlan,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        Ok(ActionExecutionResult {
            affected_items: 1,
            freed_bytes: 0,
            warnings: Vec::new(),
        })
    }
}

fn run_git_in(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git -C {} {:?} failed: {}",
        repo.display(),
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn run_git_in_no_sign(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-c")
        .arg("commit.gpgsign=false")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git -c commit.gpgsign=false -C {} {:?} failed: {}",
        repo.display(),
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn git_stdout_in(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git -C {} {:?} failed: {}",
        repo.display(),
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
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
    with_temp_fixture_env(
        |root| {
            let home = root.join("home");
            let xdg = root.join("xdg");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&xdg).unwrap();
            vec![
                ("HOME", home.into_os_string()),
                ("XDG_CONFIG_HOME", xdg.into_os_string()),
                (
                    "PREEN_TRUST_ALLOWLIST",
                    OsString::from(
                        "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0,https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main",
                    ),
                ),
            ]
        },
        f,
    )
}

fn with_invalid_trust_allowlist<T>(f: impl FnOnce() -> T) -> T {
    with_env_state_overrides(
        &[(
            "PREEN_TRUST_ALLOWLIST",
            Some(OsString::from("not-an-identity")),
        )],
        f,
    )
}

fn with_env_state_overrides<T>(overrides: &[(&str, Option<OsString>)], f: impl FnOnce() -> T) -> T {
    let previous: Vec<(&str, Option<OsString>)> = overrides
        .iter()
        .map(|(key, _)| (*key, std::env::var_os(key)))
        .collect();

    // SAFETY: test caller holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        for (key, value) in overrides {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    let out = f();

    // SAFETY: test caller holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        for (key, old_value) in previous {
            match old_value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    out
}

fn with_env_overrides<T>(overrides: &[(&str, OsString)], f: impl FnOnce() -> T) -> T {
    let state_overrides: Vec<(&str, Option<OsString>)> = overrides
        .iter()
        .map(|(key, value)| (*key, Some(value.clone())))
        .collect();
    with_env_state_overrides(&state_overrides, f)
}

fn with_temp_fixture_env<T>(
    setup: impl FnOnce(&Path) -> Vec<(&'static str, OsString)>,
    f: impl FnOnce() -> T,
) -> T {
    let temp = tempfile::tempdir().unwrap();
    let overrides = setup(temp.path());
    with_env_overrides(&overrides, f)
}

fn with_clean_path_override<T>(f: impl FnOnce() -> T) -> T {
    with_temp_fixture_env(
        |root| {
            let cache_dir = root.join("cache");
            fs::create_dir_all(&cache_dir).unwrap();
            fs::write(cache_dir.join("a.txt"), b"data").unwrap();
            vec![("PREEN_CLEAN_PATHS", cache_dir.into_os_string())]
        },
        f,
    )
}

fn with_purge_path_override<T>(f: impl FnOnce() -> T) -> T {
    with_temp_fixture_env(
        |root| {
            let workspace = root.join("workspace");
            let purge_target = workspace.join("node_modules");
            fs::create_dir_all(&purge_target).unwrap();
            fs::write(purge_target.join("placeholder.js"), b"const x = 1;").unwrap();
            vec![
                ("PREEN_PURGE_PATHS", workspace.into_os_string()),
                ("PREEN_PURGE_MIN_AGE_DAYS", OsString::from("0")),
            ]
        },
        f,
    )
}

fn with_installer_path_override<T>(f: impl FnOnce() -> T) -> T {
    with_temp_fixture_env(
        |root| {
            let downloads = root.join("downloads");
            fs::create_dir_all(&downloads).unwrap();
            let installer = downloads.join("Setup.pkg");
            fs::write(&installer, vec![0u8; 11 * 1024 * 1024]).unwrap();
            vec![("PREEN_INSTALLER_PATHS", downloads.into_os_string())]
        },
        f,
    )
}

fn with_uninstall_path_override<T>(f: impl FnOnce() -> T) -> T {
    with_temp_fixture_env(
        |root| {
            let apps = root.join("apps");
            fs::create_dir_all(&apps).unwrap();
            let app = apps.join("DemoApp.app");
            fs::write(&app, b"demo").unwrap();
            vec![("PREEN_UNINSTALL_PATHS", apps.into_os_string())]
        },
        f,
    )
}

fn with_shell_env<T>(shell: Option<&str>, f: impl FnOnce() -> T) -> T {
    with_env_state_overrides(&[("SHELL", shell.map(OsString::from))], f)
}

fn with_completion_env<T>(
    home: &Path,
    shell: Option<&str>,
    completion_shell: Option<&str>,
    f: impl FnOnce() -> T,
) -> T {
    with_env_state_overrides(
        &[
            ("HOME", Some(home.as_os_str().to_os_string())),
            ("SHELL", shell.map(OsString::from)),
            (
                "PREEN_COMPLETION_SHELL",
                completion_shell.map(OsString::from),
            ),
        ],
        f,
    )
}

fn with_status_metrics_env<T>(overrides: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
    let env_overrides: Vec<(&str, OsString)> = overrides
        .iter()
        .map(|(key, value)| (*key, OsString::from(*value)))
        .collect();
    with_env_overrides(&env_overrides, f)
}

fn with_debug_log_env<T>(key: &str, path: &Path, f: impl FnOnce() -> T) -> T {
    with_env_overrides(&[(key, path.as_os_str().to_os_string())], f)
}

fn clear_registry_trust_env() {
    // SAFETY: test caller holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_REGISTRY_SOURCE");
        std::env::remove_var("PREEN_REGISTRY_SIGNATURE_SOURCE");
        std::env::remove_var("PREEN_REGISTRY_IDENTITY");
        std::env::remove_var("PREEN_REGISTRY_ISSUER");
    }
}

fn apply_registry_freshness_env(cache: &Path, stale_mode: &str, max_age_days: Option<&str>) {
    // SAFETY: test caller holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_REGISTRY_INDEX", cache.to_str().unwrap());
        std::env::set_var("PREEN_REGISTRY_STALE_MODE", stale_mode);
        match max_age_days {
            Some(days) => std::env::set_var("PREEN_REGISTRY_MAX_AGE_DAYS", days),
            None => std::env::remove_var("PREEN_REGISTRY_MAX_AGE_DAYS"),
        }
    }
}

fn with_analyze_root_fixture<T>(f: impl FnOnce(&Path) -> T) -> T {
    let analyze_root = tempfile::tempdir().unwrap();
    fs::create_dir_all(analyze_root.path().join("nested")).unwrap();
    fs::write(
        analyze_root.path().join("nested").join("sample.bin"),
        b"sample",
    )
    .unwrap();
    f(analyze_root.path())
}

fn with_update_release_env<T>(f: impl FnOnce() -> T) -> T {
    with_env_overrides(
        &[
            ("PREEN_UPDATE_LATEST_VERSION", OsString::from("9.9.9")),
            ("PREEN_UPDATE_INSTALL_SOURCE", OsString::from("cargo")),
        ],
        f,
    )
}

fn with_update_install_source_env<T>(source: &str, f: impl FnOnce() -> T) -> T {
    with_env_overrides(
        &[("PREEN_UPDATE_INSTALL_SOURCE", OsString::from(source))],
        f,
    )
}

fn with_remove_targets_env<T>(f: impl FnOnce() -> T) -> T {
    with_temp_fixture_env(
        |root| {
            let state_dir = root.join("state");
            let cache_dir = root.join("cache");
            fs::create_dir_all(&state_dir).unwrap();
            fs::create_dir_all(&cache_dir).unwrap();
            fs::write(state_dir.join("plugins.lock"), "dummy").unwrap();
            fs::write(cache_dir.join("cache.tmp"), "dummy").unwrap();
            vec![
                ("PREEN_REMOVE_STATE_DIR", state_dir.into_os_string()),
                ("PREEN_REMOVE_CACHE_DIR", cache_dir.into_os_string()),
                ("PREEN_UPDATE_INSTALL_SOURCE", OsString::from("cargo")),
            ]
        },
        f,
    )
}

fn with_remove_paths_env<T>(
    seed_files: bool,
    install_source: Option<&str>,
    f: impl FnOnce(&Path, &Path) -> T,
) -> T {
    let state_root = tempfile::tempdir().unwrap();
    let cache_root = tempfile::tempdir().unwrap();
    let state_path = state_root.path().join("state");
    let cache_path = cache_root.path().join("cache");
    fs::create_dir_all(&state_path).unwrap();
    fs::create_dir_all(&cache_path).unwrap();
    if seed_files {
        fs::write(state_path.join("plugins.lock"), "dummy").unwrap();
        fs::write(cache_path.join("cache.tmp"), "dummy").unwrap();
    }

    let mut overrides = vec![
        (
            "PREEN_REMOVE_STATE_DIR",
            state_path.clone().into_os_string(),
        ),
        (
            "PREEN_REMOVE_CACHE_DIR",
            cache_path.clone().into_os_string(),
        ),
    ];
    if let Some(source) = install_source {
        overrides.push(("PREEN_UPDATE_INSTALL_SOURCE", OsString::from(source)));
    }

    with_env_overrides(&overrides, || f(&state_path, &cache_path))
}

const REGISTRY_SIGN_IDENTITY: &str =
    "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main";
const REGISTRY_SIGN_ISSUER: &str = "https://token.actions.githubusercontent.com";

fn file_source_url(path: &Path) -> String {
    format!("file://{}", path.display())
}

struct RegistryIndexEntrySpec<'a> {
    pack_id: &'a str,
    name: &'a str,
    description: &'a str,
    repo_url: &'a str,
    latest_version: &'a str,
    rev: &'a str,
}

fn write_registry_index_single_entry(
    index: &Path,
    generated_at: &str,
    entry: &RegistryIndexEntrySpec<'_>,
) {
    fs::write(
        index,
        format!(
            r#"
schema_version = 1
generated_at = "{generated_at}"

[[entries]]
pack_id = "{pack_id}"
name = "{name}"
description = "{description}"
repo_url = "{repo_url}"
latest_version = "{latest_version}"
  [[entries.versions]]
  version = "{latest_version}"
  rev = "{rev}"
"#,
            pack_id = entry.pack_id,
            name = entry.name,
            description = entry.description,
            repo_url = entry.repo_url,
            latest_version = entry.latest_version,
            rev = entry.rev,
        ),
    )
    .unwrap();
}

fn write_registry_signature(sig: &Path) {
    fs::write(
        sig,
        r#"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"ZmFrZS1jZXJ0"}},"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"ZmFrZS1kaWdlc3Q="},"signature":"ZmFrZS1zaWduYXR1cmU="}}"#,
    )
    .unwrap();
}

fn write_homebrew_registry_index(index: &Path, generated_at: &str) {
    write_registry_index_single_entry(
        index,
        generated_at,
        &RegistryIndexEntrySpec {
            pack_id: "preen-rs.homebrew",
            name: "Homebrew",
            description: "Cleanup pack",
            repo_url: "https://github.com/Preen-rs/preen-rulepack-homebrew",
            latest_version: "1.2.0",
            rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647",
        },
    );
}

fn run_registry_update_cli_with_verifier<V: SignatureVerifier>(
    index: &Path,
    sig: &Path,
    verifier: &V,
) -> Result<(), CliError> {
    let cli = make_registry_update_cli(index, sig);
    run_typed_with_verifier_for_test(cli, verifier)
}

fn make_registry_update_cli(index: &Path, sig: &Path) -> Cli {
    make_registry_update_cli_with_strict_mode(index, sig, false)
}

fn make_registry_update_cli_with_strict_mode(index: &Path, sig: &Path, strict: bool) -> Cli {
    let source = file_source_url(index);
    let signature_source = file_source_url(sig);
    let mut args = vec![
        "preen".to_string(),
        "plugin".to_string(),
        "registry-update".to_string(),
    ];
    if strict {
        args.push("--strict".to_string());
    }
    args.extend([
        "--source".to_string(),
        source,
        "--signature-source".to_string(),
        signature_source,
        "--identity".to_string(),
        REGISTRY_SIGN_IDENTITY.to_string(),
        "--issuer".to_string(),
        REGISTRY_SIGN_ISSUER.to_string(),
    ]);
    Cli::try_parse_from(args).unwrap()
}

struct RegistryRepoFixture {
    _tmp: tempfile::TempDir,
    repo: PathBuf,
    rev: String,
    index: PathBuf,
    sig: PathBuf,
    cache: PathBuf,
    lockfile: PathBuf,
    install_dir: PathBuf,
}

impl RegistryRepoFixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo(&repo);
        let index = tmp.path().join("registry-index.toml");
        let sig = tmp.path().join("registry-index.toml.sig");
        let cache = tmp.path().join("cache-index.toml");
        let lockfile = tmp.path().join("preen-plugins.lock");
        let install_dir = tmp.path().join("installed-plugins");
        Self {
            _tmp: tmp,
            repo,
            rev,
            index,
            sig,
            cache,
            lockfile,
            install_dir,
        }
    }

    fn write_test_pack_index(&self) {
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let repo_url = file_source_url(&self.repo);
        write_registry_index_single_entry(
            &self.index,
            &now,
            &RegistryIndexEntrySpec {
                pack_id: "test.pack",
                name: "Test Pack",
                description: "Cleanup pack",
                repo_url: &repo_url,
                latest_version: "0.1.0",
                rev: &self.rev,
            },
        );
        write_registry_signature(&self.sig);
    }

    fn run_registry_update<V: SignatureVerifier>(&self, verifier: &V) -> Result<(), CliError> {
        run_registry_update_cli_with_verifier(&self.index, &self.sig, verifier)
    }

    fn prepare_registry<V: SignatureVerifier>(&self, verifier: &V) -> Result<(), CliError> {
        self.write_test_pack_index();
        apply_registry_freshness_env(&self.cache, "warn", None);
        self.run_registry_update(verifier)
    }

    fn install_test_pack<V: SignatureVerifier>(
        &self,
        verifier: &V,
    ) -> Result<LockedPlugin, String> {
        install_plugin_in_dir_for_test(
            "test.pack@0.1.0",
            Some(&self.lockfile),
            &self.install_dir,
            verifier,
        )
    }
}

fn with_env_lock<T>(f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().unwrap();
    f()
}

fn forced_executor_error_json_for_args(args: &[&str], error: ActionExecutionError) -> Value {
    let cli = Cli::try_parse_from(args).unwrap();
    let executor = ForcedCleanErrorExecutor { error };
    let err = run_typed_with_verifier_and_clean_executor_for_test(
        cli.clone(),
        &AlwaysOkVerifier,
        &executor,
    )
    .unwrap_err();
    serde_json::from_str(&cli.format_error(&err)).unwrap()
}

fn clean_error_json_for_forced_executor(error: ActionExecutionError) -> Value {
    with_env_lock(|| {
        with_clean_path_override(|| {
            forced_executor_error_json_for_args(&["preen", "clean", "--confirm", "--json"], error)
        })
    })
}

fn purge_error_json_for_forced_executor(error: ActionExecutionError) -> Value {
    with_env_lock(|| {
        with_purge_path_override(|| {
            forced_executor_error_json_for_args(&["preen", "purge", "--confirm", "--json"], error)
        })
    })
}

fn installer_error_json_for_forced_executor(error: ActionExecutionError) -> Value {
    with_env_lock(|| {
        with_installer_path_override(|| {
            forced_executor_error_json_for_args(
                &["preen", "installer", "--confirm", "--json"],
                error,
            )
        })
    })
}

fn uninstall_error_json_for_forced_executor(error: ActionExecutionError) -> Value {
    with_env_lock(|| {
        with_uninstall_path_override(|| {
            forced_executor_error_json_for_args(
                &["preen", "uninstall", "DemoApp.app", "--confirm", "--json"],
                error,
            )
        })
    })
}

fn optimize_error_json_for_forced_executor(error: ActionExecutionError) -> Value {
    with_env_lock(|| {
        forced_executor_error_json_for_args(&["preen", "optimize", "--confirm", "--json"], error)
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

fn assert_system_envelope(output: &Value, kind: &str, required_data_fields: &[&str]) {
    assert_eq!(output["schema_version"].as_u64(), Some(1));
    assert_eq!(output["kind"].as_str(), Some(kind));
    for field in required_data_fields {
        assert!(
            !output["data"][field].is_null(),
            "missing required data field: {field}"
        );
    }
}

fn assert_paths_envelope(output: &Value, kind: &str) {
    assert_eq!(output["schema_version"].as_u64(), Some(1));
    assert_eq!(output["kind"].as_str(), Some(kind));
    let roots = output["data"]["roots"]
        .as_array()
        .expect("roots must be an array");
    assert!(!roots.is_empty(), "roots array must not be empty");
    assert!(roots.iter().all(|value| value.as_str().is_some()));
}

fn parse_json_value(json: &str) -> Value {
    serde_json::from_str(json).unwrap()
}

fn assert_json_envelope_kind(output: &Value, kind: &str) {
    assert_eq!(output["schema_version"].as_u64(), Some(1));
    assert_eq!(output["kind"].as_str(), Some(kind));
}

fn object_keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
}

fn assert_object_keys_exact(name: &str, value: &Value, expected: &[&str]) {
    let actual = object_keys(value);
    let expected = expected
        .iter()
        .map(|field| (*field).to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "{name} key set changed");
}

fn assert_data_keys_exact(output: &Value, kind: &str, expected: &[&str]) {
    assert_json_envelope_kind(output, kind);
    assert_object_keys_exact(kind, &output["data"], expected);
}

fn assert_empty_aggregate_results(output: &Value) {
    assert_eq!(output["data"]["total"].as_u64(), Some(0));
    assert_eq!(output["data"]["passed"].as_u64(), Some(0));
    assert_eq!(output["data"]["failed"].as_u64(), Some(0));
    assert!(output["data"]["results"].as_array().unwrap().is_empty());
    assert!(output["data"]["failures"].as_array().unwrap().is_empty());
}

fn assert_plugin_report_common_fields(output: &Value, pack_id: &str) {
    assert_eq!(output["data"]["pack_id"].as_str(), Some(pack_id));
    assert!(output["data"]["checks"].as_array().is_some());
    assert!(output["data"]["suggested_actions"].as_array().is_some());
    assert!(output["data"]["duration_ms"].as_u64().is_some());
}

fn assert_plugin_drifts_empty(output: &Value) {
    assert!(output["data"]["drifts"].as_array().unwrap().is_empty());
}

fn assert_text_markers(name: &str, text: &str, markers: &[&str]) {
    for marker in markers {
        assert!(
            text.contains(marker),
            "{name} missing marker `{marker}`. output:\n{text}"
        );
    }
}

fn assert_text_markers_with_summary_mode(
    name: &str,
    text: &str,
    kind: &str,
    mode: &str,
    markers: &[&str],
) {
    let summary_marker = format!("summary: kind={kind}");
    let mode_marker = format!("mode: {mode}");
    assert!(
        text.contains(&summary_marker),
        "{name} missing marker `{summary_marker}`. output:\n{text}"
    );
    assert!(
        text.contains(&mode_marker),
        "{name} missing marker `{mode_marker}`. output:\n{text}"
    );
    assert_text_markers(name, text, markers);
}

fn action_list_contains(actions: &[Value], command: &str) -> bool {
    actions.iter().any(|value| value.as_str() == Some(command))
}

fn assert_actions_include(actions: &[Value], commands: &[&str]) {
    for command in commands {
        assert!(
            action_list_contains(actions, command),
            "missing action `{command}` in {actions:?}"
        );
    }
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

fn assert_verify_error_has_detail_and_hint(
    raw_error: String,
    expected_kind: CliErrorKind,
    expected_detail_code: &str,
    expected_hint_code: &str,
) {
    let expected_kind_str = match expected_kind {
        CliErrorKind::Validation => "validation",
        CliErrorKind::NotFound => "not_found",
        CliErrorKind::Trust => "trust",
        CliErrorKind::Verification => "verification",
        CliErrorKind::Io => "io",
        CliErrorKind::Network => "network",
        CliErrorKind::Unsupported => "unsupported",
        CliErrorKind::Internal => "internal",
    };
    let err = CliError::from(raw_error);
    assert_eq!(err.kind, expected_kind);
    assert_eq!(err.detail_code.as_deref(), Some(expected_detail_code));

    let cli = Cli::try_parse_from(["preen", "plugin", "verify", "test.pack", "--json"]).unwrap();
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(parsed["kind"].as_str(), Some("error"));
    assert_eq!(
        parsed["data"]["error_kind"].as_str(),
        Some(expected_kind_str)
    );
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some(expected_detail_code)
    );
    assert_eq!(
        parsed["data"]["hint_code"].as_str(),
        Some(expected_hint_code)
    );
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

    run_git_in(base, &["init"]);
    run_git_in(base, &["config", "user.email", "test@example.com"]);
    run_git_in(base, &["config", "user.name", "Test User"]);
    run_git_in(base, &["add", "."]);
    run_git_in_no_sign(base, &["commit", "-m", "init"]);
    git_stdout_in(base, &["rev-parse", "HEAD"])
}

fn rewrite_rule_action_type(rule_path: &Path, action_type_toml: &str) {
    let rule = fs::read_to_string(rule_path).unwrap();
    let replacement = format!("action_type = {action_type_toml}");
    let mutated = rule.replacen("action_type = \"TrashPaths\"", &replacement, 1);
    assert_ne!(rule, mutated);
    fs::write(rule_path, mutated).unwrap();
}

fn set_repo_rule_action_type(repo: &Path, action_type_toml: &str) -> String {
    let rule_path = repo.join("rules/rule-1.toml");
    rewrite_rule_action_type(&rule_path, action_type_toml);
    run_git_in(repo, &["add", "rules/rule-1.toml"]);
    run_git_in_no_sign(repo, &["commit", "-m", "set unsupported action type"]);
    git_stdout_in(repo, &["rev-parse", "HEAD"])
}

fn set_installed_rule_action_type(install_dir: &Path, action_type_toml: &str) {
    let rule_path = install_dir.join("test.pack").join("rules/rule-1.toml");
    rewrite_rule_action_type(&rule_path, action_type_toml);
}

fn init_preflight_git_repo_with_old_tag(base: &Path) -> String {
    let first_commit = init_preflight_git_repo(base);
    run_git_in(base, &["tag", "v0.0.1", &first_commit]);
    fs::write(base.join("README.md"), "next").unwrap();
    run_git_in(base, &["add", "README.md"]);
    run_git_in_no_sign(base, &["commit", "-m", "second"]);
    "v0.0.1".to_string()
}

fn git_rev_parse(repo: &Path, rev: &str) -> String {
    git_stdout_in(repo, &["rev-parse", rev])
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
  rev = "381d2c7b496b0efce4ef8be8f89a74b0ba40c647"
"#;
    let (url, rev) = resolve_registry_for_test(index, "preen-rs.homebrew", "1.2.0").unwrap();
    assert_eq!(url, "https://github.com/Preen-rs/preen-rulepack-homebrew");
    assert_eq!(rev, "381d2c7b496b0efce4ef8be8f89a74b0ba40c647");
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
  rev = "381d2c7b496b0efce4ef8be8f89a74b0ba40c647"

[[entries]]
pack_id = "preen-rs.npm"
name = "Npm"
description = "Cleanup pack for node"
repo_url = "https://github.com/Preen-rs/preen-rulepack-npm"
latest_version = "0.3.0"
  [[entries.versions]]
  version = "0.3.0"
  rev = "b2a4a429f1ef8bf7662274b6dc2621f2a03a369f"
"#;
    let all_rows = search_registry_for_test(index, None).unwrap();
    assert_eq!(all_rows.len(), 2);
    let brew_rows = search_registry_for_test(index, Some("brew")).unwrap();
    assert_eq!(brew_rows.len(), 1);
    assert!(brew_rows[0].starts_with("preen-rs.homebrew "));
}

#[test]
fn search_registry_with_options_for_test_sorts_and_pages() {
    let index = r#"
schema_version = 1

[[entries]]
pack_id = "preen-rs.b"
name = "B"
description = "B pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-b"
latest_version = "1.0.0"
  [[entries.versions]]
  version = "1.0.0"
  rev = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[[entries]]
pack_id = "preen-rs.a"
name = "A"
description = "A pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-a"
latest_version = "2.0.0"
  [[entries.versions]]
  version = "2.0.0"
  rev = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
    let rows =
        search_registry_with_options_for_test(index, None, "pack_id", false, 0, None).unwrap();
    assert_eq!(rows[0], "preen-rs.a 2.0.0 A pack");
    assert_eq!(rows[1], "preen-rs.b 1.0.0 B pack");

    let rows =
        search_registry_with_options_for_test(index, None, "version", true, 0, Some(1)).unwrap();
    assert_eq!(rows, vec!["preen-rs.a 2.0.0 A pack".to_string()]);
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
  rev = "381d2c7b496b0efce4ef8be8f89a74b0ba40c647"
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
        rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
        resolved_rev: Some("381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string()),
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
    assert!(parsed["data"]["resolved_rev"].as_str().is_some());
    assert!(parsed["data"]["installed_path"].as_str().is_some());
    assert!(parsed["data"]["installed_path_exists"].as_bool().is_some());
}

#[test]
fn plugin_list_json_for_test_contains_fields() {
    let plugins = vec![LockedPlugin {
        pack_id: "test.pack".to_string(),
        source: "git".to_string(),
        url: "https://github.com/Preen-rs/test".to_string(),
        rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
        resolved_rev: Some("381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string()),
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
    assert!(parsed["data"][0]["resolved_rev"].as_str().is_some());
}

#[test]
fn list_plugins_with_options_for_test_filters_and_sorts() {
    let plugins = vec![
        LockedPlugin {
            pack_id: "preen-rs.b".to_string(),
            source: "git".to_string(),
            url: "https://example.com/b".to_string(),
            rev: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            resolved_rev: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            version: "1.0.0".to_string(),
            manifest_hash: "sha256:b".to_string(),
            signature: "sha256:b".to_string(),
            trusted_identity: "https://github.com/Preen-rs/test".to_string(),
        },
        LockedPlugin {
            pack_id: "preen-rs.a".to_string(),
            source: "registry".to_string(),
            url: "https://example.com/a".to_string(),
            rev: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            resolved_rev: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            version: "2.0.0".to_string(),
            manifest_hash: "sha256:a".to_string(),
            signature: "sha256:a".to_string(),
            trusted_identity: "https://github.com/Preen-rs/test".to_string(),
        },
    ];
    let rows = list_plugins_with_options_for_test(&plugins, None, None, "pack_id", false).unwrap();
    assert_eq!(
        rows[0],
        "preen-rs.a 2.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        rows[1],
        "preen-rs.b 1.0.0 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );

    let rows = list_plugins_with_options_for_test(
        &plugins,
        Some("preen-rs"),
        Some("registry"),
        "version",
        true,
    )
    .unwrap();
    assert_eq!(
        rows,
        vec!["preen-rs.a 2.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()]
    );
}

#[test]
fn plugin_verify_json_for_test_contains_fields() {
    let json = plugin_verify_json_for_test("test.pack", true, true, true).unwrap();
    let parsed = parse_json_value(&json);
    assert_json_envelope_kind(&parsed, "plugin.verify");
    assert_plugin_report_common_fields(&parsed, "test.pack");
    assert!(parsed["data"]["overall_passed"].as_bool().unwrap());
    assert!(parsed["data"]["version_matches_lock"].as_bool().unwrap());
    assert!(parsed["data"]["manifest_hash_verified"].as_bool().unwrap());
    assert!(parsed["data"]["signature_hash_verified"].as_bool().unwrap());
    assert!(parsed["data"]["resolved_rev_verified"].as_bool().unwrap());
    assert_plugin_drifts_empty(&parsed);
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
    let parsed = parse_json_value(&json);
    assert_json_envelope_kind(&parsed, "plugin.test");
    assert_plugin_report_common_fields(&parsed, "test.pack");
    assert!(parsed["data"]["overall_passed"].as_bool().unwrap());
    assert!(parsed["data"]["version_matches_lock"].as_bool().unwrap());
    assert!(parsed["data"]["signature_verified"].as_bool().unwrap());
    assert_plugin_drifts_empty(&parsed);
}

#[test]
fn plugin_test_all_json_for_test_contains_fields() {
    let json = plugin_test_all_json_for_test().unwrap();
    let parsed = parse_json_value(&json);
    assert_json_envelope_kind(&parsed, "plugin.test_all");
    assert!(parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_empty_aggregate_results(&parsed);
}

#[test]
fn plugin_test_spec_json_for_test_contains_fields() {
    let json = plugin_test_spec_json_for_test("preen-rs.homebrew@1.2.0", "test.pack").unwrap();
    let parsed = parse_json_value(&json);
    assert_json_envelope_kind(&parsed, "plugin.test_spec");
    assert_eq!(
        parsed["data"]["spec"].as_str().unwrap(),
        "preen-rs.homebrew@1.2.0"
    );
    assert_plugin_report_common_fields(&parsed, "test.pack");
    assert!(parsed["data"]["overall_passed"].as_bool().unwrap());
}

#[test]
fn plugin_preflight_json_for_test_contains_fields() {
    let json = plugin_preflight_json_for_test("preen-rs.homebrew@1.2.0", "test.pack").unwrap();
    let parsed = parse_json_value(&json);
    assert_json_envelope_kind(&parsed, "plugin.preflight");
    assert_eq!(
        parsed["data"]["spec"].as_str().unwrap(),
        "preen-rs.homebrew@1.2.0"
    );
    assert_plugin_report_common_fields(&parsed, "test.pack");
    assert!(parsed["data"]["signature_verified"].as_bool().unwrap());
}

#[test]
fn plugin_preflight_all_json_for_test_contains_fields() {
    let json = plugin_preflight_all_json_for_test().unwrap();
    let parsed = parse_json_value(&json);
    assert_json_envelope_kind(&parsed, "plugin.preflight_all");
    assert!(parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_empty_aggregate_results(&parsed);
}

#[test]
fn plugin_install_update_remove_registry_json_helpers() {
    let install = plugin_install_json_for_test("a.pack", "1.0.0", "registry", "abc").unwrap();
    let install_v: Value = serde_json::from_str(&install).unwrap();
    assert_eq!(install_v["kind"].as_str().unwrap(), "plugin.install");
    assert_eq!(install_v["data"]["pack_id"].as_str().unwrap(), "a.pack");
    assert_eq!(install_v["data"]["resolved_rev"].as_str().unwrap(), "abc");
    assert!(install_v["data"]["installed_path"].as_str().is_some());
    assert!(install_v["data"]["lockfile_path"].as_str().is_some());

    let update = plugin_update_json_for_test("a.pack", "1.1.0", "registry", "def").unwrap();
    let update_v: Value = serde_json::from_str(&update).unwrap();
    assert_eq!(update_v["kind"].as_str().unwrap(), "plugin.update");
    assert_eq!(update_v["data"]["rev"].as_str().unwrap(), "def");
    assert_eq!(update_v["data"]["resolved_rev"].as_str().unwrap(), "def");
    assert!(update_v["data"]["installed_path"].as_str().is_some());
    assert!(update_v["data"]["lockfile_path"].as_str().is_some());

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
fn plugin_install_and_update_text_outputs_include_next_steps() {
    let install = plugin_install_text_for_test("a.pack", "1.0.0", "registry", "abc");
    assert!(install.contains("summary: kind=install"));
    assert!(install.contains("resolved_rev: abc"));
    assert!(install.contains("installed_path: "));
    assert!(install.contains("lockfile_path: "));
    assert!(install.contains("next_step: preen plugin verify a.pack"));
    assert!(install.contains("next_step: preen plugin test a.pack"));
    assert!(install.contains("next_step: preen plugin info a.pack"));

    let update = plugin_update_text_for_test("a.pack", "1.1.0", "registry", "def");
    assert!(update.contains("summary: kind=update"));
    assert!(update.contains("resolved_rev: def"));
    assert!(update.contains("installed_path: "));
    assert!(update.contains("lockfile_path: "));
    assert!(update.contains("next_step: preen plugin verify a.pack"));
    assert!(update.contains("next_step: preen plugin test a.pack"));
    assert!(update.contains("next_step: preen plugin info a.pack"));
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
            "resolved_rev".to_string(),
            "installed_path".to_string(),
            "lockfile_path".to_string(),
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
            "overall_passed".to_string(),
            "version_matches_lock".to_string(),
            "manifest_hash_verified".to_string(),
            "signature_hash_verified".to_string(),
            "resolved_rev_verified".to_string(),
            "checks".to_string(),
            "suggested_actions".to_string(),
            "duration_ms".to_string(),
            "drifts".to_string(),
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
            "suggested_actions".to_string(),
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
            "suggested_actions".to_string(),
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
  rev = "381d2c7b496b0efce4ef8be8f89a74b0ba40c647"
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

    let plugin = LockedPlugin {
        pack_id: "test.pack".to_string(),
        source: "git".to_string(),
        url: "https://github.com/Preen-rs/test".to_string(),
        rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
        resolved_rev: Some("381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string()),
        version: "0.1.0".to_string(),
        manifest_hash: "sha256:deadbeef".to_string(),
        signature: "sha256:cafebabe".to_string(),
        trusted_identity: "https://github.com/Preen-rs/test".to_string(),
    };
    let info = plugin_info_json_for_test(&plugin).unwrap();
    let info_v: Value = serde_json::from_str(&info).unwrap();
    assert_object_keys_exact(
        "plugin.info.data",
        &info_v["data"],
        &[
            "pack_id",
            "version",
            "rev",
            "resolved_rev",
            "source",
            "url",
            "installed_path",
            "installed_path_exists",
            "manifest_hash",
            "signature",
            "trusted_identity",
        ],
    );

    let list = plugin_list_json_for_test(&[plugin]).unwrap();
    let list_v: Value = serde_json::from_str(&list).unwrap();
    assert_json_envelope_kind(&list_v, "plugin.list");
    assert_object_keys_exact(
        "plugin.list.item",
        &list_v["data"][0],
        &["pack_id", "version", "rev", "resolved_rev", "source"],
    );

    let remove = plugin_remove_json_for_test("a.pack", true).unwrap();
    let remove_v: Value = serde_json::from_str(&remove).unwrap();
    assert_object_keys_exact(
        "plugin.remove.data",
        &remove_v["data"],
        &["pack_id", "removed"],
    );

    let error_plugin = error_json_for_test(
        "__preen_kind:validation__preen_code:preflight_spec_invalid__missing @<tag|commit> in install spec",
    )
    .unwrap();
    let error_plugin_v: Value = serde_json::from_str(&error_plugin).unwrap();
    assert_object_keys_exact(
        "error(plugin).data",
        &error_plugin_v["data"],
        &[
            "error_kind",
            "detail_code",
            "hint_code",
            "hint_action",
            "hint_message",
            "message",
        ],
    );

    let error_system = error_json_for_test(
        "__preen_kind:unsupported__preen_code:command_not_implemented__remove command is not implemented yet",
    )
    .unwrap();
    let error_system_v: Value = serde_json::from_str(&error_system).unwrap();
    assert_object_keys_exact(
        "error(system).data",
        &error_system_v["data"],
        &["error_kind", "detail_code", "message"],
    );
}

#[test]
fn system_json_envelopes_have_exact_expected_data_keys() {
    let _guard = ENV_LOCK.lock().unwrap();

    let clean = with_clean_path_override(|| clean_output_for_test(true, false, None).unwrap());
    assert_data_keys_exact(
        &clean,
        "system.clean",
        &[
            "mode",
            "strategy",
            "scanned_items",
            "target_count",
            "estimated_freed_bytes",
            "preview_paths",
            "affected_items",
            "freed_bytes",
            "whitelist_entries",
            "whitelist_hits",
            "risk_summary",
            "warnings",
            "audit_events",
        ],
    );
    assert_object_keys_exact(
        "system.clean.risk_summary",
        &clean["data"]["risk_summary"],
        &["high_targets", "requires_confirmation"],
    );

    let clean_whitelist = with_temp_user_env(|| clean_whitelist_output_for_test().unwrap());
    assert_data_keys_exact(
        &clean_whitelist,
        "system.clean.whitelist",
        &["path", "entries", "created", "defaults_written"],
    );

    let purge = with_purge_path_override(|| purge_output_for_test(true, false).unwrap());
    assert_data_keys_exact(
        &purge,
        "system.purge",
        &[
            "mode",
            "scanned_roots",
            "scanned_dirs",
            "min_age_days",
            "skipped_recent",
            "target_count",
            "estimated_freed_bytes",
            "preview_paths",
            "affected_items",
            "freed_bytes",
            "warnings",
            "audit_events",
        ],
    );

    let purge_paths = with_purge_path_override(|| purge_paths_json_for_test().unwrap());
    assert_data_keys_exact(&purge_paths, "system.purge.paths", &["roots"]);

    let installer =
        with_installer_path_override(|| installer_output_for_test(true, false).unwrap());
    assert_data_keys_exact(
        &installer,
        "system.installer",
        &[
            "mode",
            "scanned_roots",
            "scanned_files",
            "scan_depth",
            "target_count",
            "estimated_freed_bytes",
            "preview_paths",
            "affected_items",
            "freed_bytes",
            "warnings",
            "audit_events",
        ],
    );

    let installer_paths = with_installer_path_override(|| installer_paths_json_for_test().unwrap());
    assert_data_keys_exact(&installer_paths, "system.installer.paths", &["roots"]);

    let uninstall = with_uninstall_path_override(|| {
        uninstall_output_for_test(Some("DemoApp.app"), true, false).unwrap()
    });
    assert_data_keys_exact(
        &uninstall,
        "system.uninstall",
        &[
            "mode",
            "target",
            "scanned_roots",
            "scanned_entries",
            "scan_depth",
            "target_count",
            "estimated_freed_bytes",
            "preview_paths",
            "affected_items",
            "freed_bytes",
            "warnings",
            "audit_events",
        ],
    );

    let uninstall_paths = with_uninstall_path_override(|| uninstall_paths_json_for_test().unwrap());
    assert_data_keys_exact(&uninstall_paths, "system.uninstall.paths", &["roots"]);

    let optimize = optimize_output_for_test(true, false).unwrap();
    assert_data_keys_exact(
        &optimize,
        "system.optimize",
        &[
            "mode",
            "os",
            "task_count",
            "executed_tasks",
            "affected_items",
            "post_check_run",
            "post_check_overall_passed",
            "post_check_suggested_actions",
            "warnings",
            "audit_events",
        ],
    );

    let optimize_whitelist = with_temp_user_env(|| optimize_whitelist_output_for_test().unwrap());
    assert_data_keys_exact(
        &optimize_whitelist,
        "system.optimize.whitelist",
        &[
            "path",
            "entries",
            "created",
            "defaults_written",
            "available_tasks",
        ],
    );

    with_temp_user_env(|| {
        let check = check_output_for_test(false).unwrap();
        assert_data_keys_exact(
            &check,
            "system.check",
            &[
                "mode",
                "overall_passed",
                "checks",
                "fixes_applied",
                "suggested_actions",
                "warnings",
            ],
        );

        let status = status_output_for_test().unwrap();
        assert_data_keys_exact(
            &status,
            "system.status",
            &[
                "mode",
                "os",
                "arch",
                "health_score",
                "state_dir",
                "plugin_count",
                "registry_index_present",
                "registry_generated_at",
                "registry_age_days",
                "metrics",
                "overall_passed",
                "checks",
                "suggested_actions",
                "warnings",
            ],
        );
        assert_object_keys_exact(
            "system.status.metrics",
            &status["data"]["metrics"],
            &[
                "cpu_cores",
                "load_avg_1m_milli",
                "load_avg_5m_milli",
                "load_avg_15m_milli",
                "uptime_seconds",
                "memory_total_bytes",
                "memory_used_bytes",
                "memory_used_pct",
                "disk_total_bytes",
                "disk_available_bytes",
                "disk_free_pct",
                "process_count",
                "network_rx_bytes",
                "network_tx_bytes",
            ],
        );

        let touchid = touchid_output_for_test(Some("status"), true).unwrap();
        assert_data_keys_exact(
            &touchid,
            "system.touchid",
            &[
                "mode",
                "action",
                "supported_os",
                "configured",
                "would_change",
                "applied",
                "warnings",
            ],
        );

        let completion = with_shell_env(Some("/bin/zsh"), || {
            completion_output_for_test(None, true).unwrap()
        });
        assert_data_keys_exact(
            &completion,
            "system.completion",
            &[
                "mode",
                "shell",
                "generated",
                "installed",
                "changed",
                "config_path",
                "snippet",
                "warnings",
            ],
        );

        let update = with_update_release_env(|| update_output_for_test(false, false).unwrap());
        assert_data_keys_exact(
            &update,
            "system.update",
            &[
                "mode",
                "channel",
                "force",
                "current_version",
                "latest_version",
                "update_available",
                "install_source",
                "suggested_command",
                "executed",
                "checks",
                "warnings",
            ],
        );

        let remove = with_remove_targets_env(|| remove_output_for_test(true, false).unwrap());
        assert_data_keys_exact(
            &remove,
            "system.remove",
            &[
                "mode",
                "executable",
                "detected_paths",
                "removed_paths",
                "skipped_paths",
                "checks",
                "manual_steps",
                "warnings",
            ],
        );
    });

    let analyze = with_analyze_root_fixture(|analyze_root| {
        analyze_output_for_test(Some(analyze_root)).unwrap()
    });
    assert_data_keys_exact(
        &analyze,
        "system.analyze",
        &[
            "root",
            "path",
            "max_depth",
            "top_entries_limit",
            "scanned_entries",
            "total_files",
            "total_dirs",
            "total_size_bytes",
            "total_size",
            "truncated_dirs",
            "entries",
            "top_entries",
            "warnings",
        ],
    );

    let status_watch = with_temp_user_env(|| status_watch_output_for_test(2).unwrap());
    assert_data_keys_exact(
        &status_watch,
        "system.status.watch",
        &["mode", "interval_sec", "ticks", "frames"],
    );
    assert_object_keys_exact(
        "system.status.watch.frame",
        &status_watch["data"]["frames"][0],
        &[
            "mode",
            "os",
            "arch",
            "health_score",
            "state_dir",
            "plugin_count",
            "registry_index_present",
            "registry_generated_at",
            "registry_age_days",
            "metrics",
            "overall_passed",
            "checks",
            "suggested_actions",
            "warnings",
        ],
    );
}

#[test]
fn json_kind_contract_is_frozen() {
    let actual = json_kinds_from_source_for_test();
    let expected: BTreeSet<String> = [
        "error",
        "plugin.info",
        "plugin.install",
        "plugin.list",
        "plugin.preflight",
        "plugin.preflight_all",
        "plugin.registry_update",
        "plugin.remove",
        "plugin.search",
        "plugin.test",
        "plugin.test_all",
        "plugin.test_spec",
        "plugin.update",
        "plugin.verify",
        "system.analyze",
        "system.check",
        "system.clean",
        "system.clean.whitelist",
        "system.completion",
        "system.installer",
        "system.installer.paths",
        "system.optimize",
        "system.optimize.whitelist",
        "system.purge",
        "system.purge.paths",
        "system.remove",
        "system.status",
        "system.status.watch",
        "system.touchid",
        "system.uninstall",
        "system.uninstall.paths",
        "system.update",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "json kind taxonomy changed");
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
    assert_eq!(parsed["data"]["hint_code"].as_str(), Some("invalid_spec"));
    assert_eq!(
        parsed["data"]["hint_action"].as_str(),
        Some("use_format_url_at_tag_or_commit")
    );
    assert!(parsed["data"]["hint_message"].as_str().is_some());
}

#[test]
fn error_json_for_test_omits_hint_for_system_detail_code() {
    let json = error_json_for_test(
        "__preen_kind:unsupported__preen_code:command_not_implemented__remove command is not implemented yet",
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("command_not_implemented")
    );
    assert!(parsed["data"]["hint_code"].is_null());
    assert!(parsed["data"]["hint_action"].is_null());
    assert!(parsed["data"]["hint_message"].is_null());
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
fn wants_json_output_detects_flag_for_all_top_level_system_commands() {
    let cases = [
        vec!["preen", "clean", "--json"],
        vec!["preen", "uninstall", "DemoApp", "--json"],
        vec!["preen", "optimize", "--json"],
        vec!["preen", "analyze", "--json"],
        vec!["preen", "status", "--json"],
        vec!["preen", "purge", "--json"],
        vec!["preen", "installer", "--json"],
        vec!["preen", "check", "--json"],
        vec!["preen", "touchid", "status", "--json"],
        vec!["preen", "completion", "zsh", "--json"],
        vec!["preen", "update", "--json"],
        vec!["preen", "remove", "--json"],
    ];

    for args in cases {
        let cli = Cli::try_parse_from(args.clone()).unwrap();
        assert!(
            cli.wants_json_output(),
            "json flag not detected for args: {args:?}"
        );
    }
}

#[test]
fn static_detail_code_contract_is_frozen() {
    let actual = static_detail_codes_from_source_for_test();
    let expected: BTreeSet<String> = [
        "analyze_cwd_unavailable",
        "analyze_home_missing",
        "analyze_interactive_invalid_path",
        "analyze_interactive_invalid_selection",
        "analyze_interactive_read_failed",
        "analyze_interactive_tty_required",
        "analyze_root_not_directory",
        "analyze_root_not_found",
        "analyze_root_not_resolvable",
        "analyze_target_not_readable",
        "clean_confirmation_required",
        "clean_dry_run_unsupported_os",
        "completion_executable_unknown",
        "completion_home_missing",
        "completion_read_failed",
        "completion_shell_unknown",
        "completion_write_failed",
        "install_action_api_unsupported",
        "install_action_type_unsupported",
        "install_core_compat_failed",
        "install_os_target_failed",
        "install_pack_load_failed",
        "install_spec_invalid",
        "installer_confirmation_required",
        "installer_no_roots",
        "optimize_confirmation_required",
        "optimize_no_tasks",
        "preflight_action_api_unsupported",
        "preflight_action_type_unsupported",
        "preflight_all_failed",
        "preflight_core_compat_failed",
        "preflight_os_target_failed",
        "preflight_pack_load_failed",
        "preflight_signature_or_trust_failed",
        "preflight_spec_invalid",
        "purge_confirmation_required",
        "purge_no_roots",
        "registry_identity_invalid",
        "registry_index_parse_failed",
        "registry_issuer_invalid",
        "registry_signature_verify_failed",
        "registry_source_missing",
        "remove_confirmation_required",
        "remove_execution_failed",
        "remove_path_resolve_failed",
        "remove_path_scope_violation",
        "status_state_dir_unavailable",
        "test_all_failed",
        "trust_policy_invalid",
        "trust_policy_missing",
        "update_execute_capture_write_failed",
        "update_execute_failed",
        "update_execute_mock_invalid",
        "update_nightly_unsupported_source",
        "uninstall_confirmation_required",
        "uninstall_no_roots",
        "uninstall_target_required",
        "verify_action_api_unsupported",
        "verify_action_type_unsupported",
        "verify_core_compat_failed",
        "verify_manifest_hash_drift",
        "verify_os_target_failed",
        "verify_pack_load_failed",
        "verify_resolved_rev_drift",
        "verify_signature_hash_drift",
        "verify_signature_or_trust_failed",
        "verify_version_drift",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "static detail-code taxonomy changed");
}

#[test]
fn static_detail_codes_keep_system_plugin_hint_boundary_in_json_mode() {
    let system_cli = Cli::try_parse_from(["preen", "status", "--json"]).unwrap();
    let plugin_cli = Cli::try_parse_from(["preen", "plugin", "search", "--json"]).unwrap();
    for detail_code in static_detail_codes_from_source_for_test() {
        let is_system = is_system_detail_code_for_test(&detail_code);
        let err = CliError {
            kind: CliErrorKind::Validation,
            detail_code: Some(detail_code.clone()),
            message: "boundary-check".to_string(),
        };
        let formatted = if is_system {
            system_cli.format_error(&err)
        } else {
            plugin_cli.format_error(&err)
        };
        let parsed: Value = serde_json::from_str(&formatted).unwrap();
        let hint_code = &parsed["data"]["hint_code"];
        let hint_action = &parsed["data"]["hint_action"];
        let hint_message = &parsed["data"]["hint_message"];
        if is_system {
            assert!(
                hint_code.is_null(),
                "system code must not expose plugin hint"
            );
            assert!(
                hint_action.is_null(),
                "system code must not expose plugin hint"
            );
            assert!(
                hint_message.is_null(),
                "system code must not expose plugin hint"
            );
        } else {
            assert!(hint_code.is_string(), "plugin code should expose hint_code");
            assert!(
                hint_action.is_string(),
                "plugin code should expose hint_action"
            );
            assert!(
                hint_message.is_string(),
                "plugin code should expose hint_message"
            );
        }
    }
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
fn clean_whitelist_json_mode_creates_default_file() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::remove_var("PREEN_CLEAN_WHITELIST_PATH");
        }
        let output = clean_whitelist_output_for_test().unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.clean.whitelist"));
        let path = output["data"]["path"].as_str().unwrap();
        assert!(Path::new(path).exists());
        assert!(output["data"]["entries"].as_u64().unwrap_or(0) >= 1);
    });
}

#[test]
fn clean_whitelist_text_contract_has_required_markers() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let text = clean_whitelist_text_output_for_test().unwrap();
        assert!(text.contains("summary: kind=system_clean_whitelist"));
        assert!(text.contains("path: "));
        assert!(text.contains("entries: "));
        assert!(text.contains("created: "));
        assert!(text.contains("defaults_written: "));
    });
}

#[test]
fn clean_debug_mode_writes_debug_log() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let debug_log = temp.path().join("clean-debug.log");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(cache_dir.join("a.txt"), b"data").unwrap();
    let result = with_env_overrides(
        &[
            ("PREEN_CLEAN_PATHS", cache_dir.as_os_str().to_os_string()),
            (
                "PREEN_CLEAN_DEBUG_LOG_PATH",
                debug_log.as_os_str().to_os_string(),
            ),
        ],
        || {
            let cli =
                Cli::try_parse_from(["preen", "clean", "--dry-run", "--debug", "--json"]).unwrap();
            run_typed(cli)
        },
    );
    assert!(result.is_ok());
    assert!(debug_log.exists());
    let content = fs::read_to_string(debug_log).unwrap();
    assert!(content.contains("scanned_items="));
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
    assert_eq!(output["data"]["post_check_run"].as_bool(), Some(false));
    assert!(output["data"]["post_check_overall_passed"].is_null());
    assert!(output["data"]["task_count"].as_u64().unwrap_or(0) >= 1);
    let executed = output["data"]["executed_tasks"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!executed.is_empty());
}

#[test]
fn optimize_debug_mode_writes_debug_log() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let debug_log = temp.path().join("optimize-debug.log");
    let output = with_debug_log_env("PREEN_OPTIMIZE_DEBUG_LOG_PATH", &debug_log, || {
        optimize_output_with_debug_for_test(true, false, true, &AlwaysSuccessExecutor).unwrap()
    });
    assert_eq!(output["kind"].as_str(), Some("system.optimize"));
    assert_eq!(
        output["data"]["debug_log_path"].as_str(),
        Some(debug_log.to_string_lossy().as_ref())
    );
    let log = fs::read_to_string(debug_log).unwrap();
    assert!(log.contains("mode=dry_run"));
    assert!(log.contains("selected_tasks="));
}

#[test]
fn optimize_whitelist_json_happy_path() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = optimize_whitelist_output_for_test().unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.optimize.whitelist"));
        assert!(
            output["data"]["path"]
                .as_str()
                .unwrap_or_default()
                .contains("optimize-whitelist")
        );
        assert!(output["data"]["entries"].as_u64().unwrap_or(0) >= 1);
        assert!(output["data"]["available_tasks"].as_u64().unwrap_or(0) >= 1);
    });
}

#[test]
fn optimize_whitelist_text_contract_has_required_markers() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let text = optimize_whitelist_text_output_for_test().unwrap();
        assert!(text.contains("summary: kind=system_optimize_whitelist"));
        assert!(text.contains("path: "));
        assert!(text.contains("entries: "));
        assert!(text.contains("available_tasks: "));
        assert!(text.contains("created: "));
        assert!(text.contains("defaults_written: "));
    });
}

#[test]
fn system_command_json_contract_matrix_has_required_fields() {
    let _guard = ENV_LOCK.lock().unwrap();

    let clean = with_clean_path_override(|| clean_output_for_test(true, false, None).unwrap());
    assert_system_envelope(
        &clean,
        "system.clean",
        &[
            "mode",
            "strategy",
            "target_count",
            "affected_items",
            "freed_bytes",
            "warnings",
            "audit_events",
        ],
    );
    assert!(clean["data"]["preview_paths"].is_array());

    let purge = with_purge_path_override(|| purge_output_for_test(true, false).unwrap());
    assert_system_envelope(
        &purge,
        "system.purge",
        &[
            "mode",
            "scanned_roots",
            "target_count",
            "affected_items",
            "freed_bytes",
            "warnings",
            "audit_events",
        ],
    );
    assert!(purge["data"]["preview_paths"].is_array());

    let installer =
        with_installer_path_override(|| installer_output_for_test(true, false).unwrap());
    assert_system_envelope(
        &installer,
        "system.installer",
        &[
            "mode",
            "scanned_roots",
            "target_count",
            "affected_items",
            "freed_bytes",
            "warnings",
            "audit_events",
        ],
    );
    assert!(installer["data"]["preview_paths"].is_array());

    let uninstall = with_uninstall_path_override(|| {
        uninstall_output_for_test(Some("DemoApp.app"), true, false).unwrap()
    });
    assert_system_envelope(
        &uninstall,
        "system.uninstall",
        &[
            "mode",
            "target",
            "scanned_roots",
            "target_count",
            "affected_items",
            "freed_bytes",
            "warnings",
            "audit_events",
        ],
    );
    assert!(uninstall["data"]["preview_paths"].is_array());

    let optimize = optimize_output_for_test(true, false).unwrap();
    assert_system_envelope(
        &optimize,
        "system.optimize",
        &[
            "mode",
            "os",
            "task_count",
            "affected_items",
            "post_check_run",
            "warnings",
            "audit_events",
        ],
    );
    assert!(optimize["data"]["executed_tasks"].is_array());
}

#[test]
fn system_command_text_contract_matrix_has_required_markers() {
    let _guard = ENV_LOCK.lock().unwrap();

    let clean = with_clean_path_override(|| clean_text_output_for_test(true, false, None).unwrap());
    assert_text_markers_with_summary_mode(
        "clean",
        &clean,
        "system_clean",
        "dry_run",
        &[
            "clean dry_run completed:",
            "strategy=",
            "scanned=",
            "targets=",
            "risk: high_targets=",
            "audit_events=",
        ],
    );

    let purge = with_purge_path_override(|| purge_text_output_for_test(true, false).unwrap());
    assert_text_markers_with_summary_mode(
        "purge",
        &purge,
        "system_purge",
        "dry_run",
        &[
            "Purge (dry-run)",
            "Scanned roots:",
            "Targets:",
            "Affected items:",
            "Audit events:",
        ],
    );

    let installer =
        with_installer_path_override(|| installer_text_output_for_test(true, false).unwrap());
    assert_text_markers_with_summary_mode(
        "installer",
        &installer,
        "system_installer",
        "dry_run",
        &[
            "Installer (dry-run)",
            "Scanned roots:",
            "Scanned files:",
            "Scan depth:",
            "Targets:",
            "Audit events:",
        ],
    );

    let uninstall = with_uninstall_path_override(|| {
        uninstall_text_output_for_test(Some("DemoApp.app"), true, false).unwrap()
    });
    assert_text_markers_with_summary_mode(
        "uninstall",
        &uninstall,
        "system_uninstall",
        "dry_run",
        &[
            "Uninstall (dry-run)",
            "Target: DemoApp.app",
            "Scanned entries:",
            "Scan depth:",
            "Targets:",
            "Audit events:",
        ],
    );

    let optimize = optimize_text_output_for_test(true, false).unwrap();
    assert_text_markers_with_summary_mode(
        "optimize",
        &optimize,
        "system_optimize",
        "dry_run",
        &[
            "Optimize (dry-run)",
            "OS:",
            "Tasks:",
            "Affected items:",
            "Audit events:",
        ],
    );
}

#[test]
fn system_paths_json_contract_matrix_has_required_fields() {
    let _guard = ENV_LOCK.lock().unwrap();

    let purge = with_purge_path_override(|| purge_paths_json_for_test().unwrap());
    assert_paths_envelope(&purge, "system.purge.paths");

    let installer = with_installer_path_override(|| installer_paths_json_for_test().unwrap());
    assert_paths_envelope(&installer, "system.installer.paths");

    let uninstall = with_uninstall_path_override(|| uninstall_paths_json_for_test().unwrap());
    assert_paths_envelope(&uninstall, "system.uninstall.paths");
}

#[test]
fn system_paths_text_contract_matrix_has_required_markers() {
    let _guard = ENV_LOCK.lock().unwrap();

    let purge = with_purge_path_override(purge_paths_text_for_test);
    assert_text_markers_with_summary_mode(
        "purge_paths",
        &purge,
        "system_paths command=purge",
        "paths",
        &["roots: count=", "Purge scan roots:", "- "],
    );

    let installer = with_installer_path_override(installer_paths_text_for_test);
    assert_text_markers_with_summary_mode(
        "installer_paths",
        &installer,
        "system_paths command=installer",
        "paths",
        &["roots: count=", "Installer scan roots:", "- "],
    );

    let uninstall = with_uninstall_path_override(uninstall_paths_text_for_test);
    assert_text_markers_with_summary_mode(
        "uninstall_paths",
        &uninstall,
        "system_paths command=uninstall",
        "paths",
        &["roots: count=", "Uninstall scan roots:", "- "],
    );
}

#[test]
fn system_support_commands_json_contract_matrix_has_required_fields() {
    let _guard = ENV_LOCK.lock().unwrap();

    with_temp_user_env(|| {
        let check = check_output_for_test(false).unwrap();
        assert_system_envelope(
            &check,
            "system.check",
            &[
                "mode",
                "overall_passed",
                "checks",
                "fixes_applied",
                "suggested_actions",
                "warnings",
            ],
        );
    });

    let analyze = with_analyze_root_fixture(|analyze_root| {
        analyze_output_for_test(Some(analyze_root)).unwrap()
    });
    assert_system_envelope(
        &analyze,
        "system.analyze",
        &[
            "root",
            "path",
            "max_depth",
            "top_entries_limit",
            "scanned_entries",
            "total_files",
            "total_dirs",
            "total_size",
            "total_size_bytes",
            "truncated_dirs",
            "entries",
            "top_entries",
            "warnings",
        ],
    );

    with_temp_user_env(|| {
        let status = status_output_for_test().unwrap();
        assert_system_envelope(
            &status,
            "system.status",
            &[
                "mode",
                "os",
                "arch",
                "health_score",
                "state_dir",
                "metrics",
                "overall_passed",
                "checks",
                "suggested_actions",
                "warnings",
            ],
        );

        let touchid = touchid_output_for_test(Some("status"), true).unwrap();
        assert_system_envelope(
            &touchid,
            "system.touchid",
            &[
                "mode",
                "action",
                "supported_os",
                "configured",
                "would_change",
                "applied",
                "warnings",
            ],
        );

        let completion = with_shell_env(Some("/bin/zsh"), || {
            completion_output_for_test(None, true).unwrap()
        });
        assert_system_envelope(
            &completion,
            "system.completion",
            &[
                "mode",
                "shell",
                "generated",
                "installed",
                "changed",
                "warnings",
            ],
        );

        let update = with_update_release_env(|| update_output_for_test(false, false).unwrap());
        assert_system_envelope(
            &update,
            "system.update",
            &[
                "mode",
                "channel",
                "force",
                "current_version",
                "latest_version",
                "update_available",
                "install_source",
                "suggested_command",
                "executed",
                "checks",
                "warnings",
            ],
        );

        let remove = with_remove_targets_env(|| remove_output_for_test(true, false).unwrap());
        assert_system_envelope(
            &remove,
            "system.remove",
            &[
                "mode",
                "executable",
                "detected_paths",
                "removed_paths",
                "skipped_paths",
                "checks",
                "manual_steps",
                "warnings",
            ],
        );
    });
}

#[test]
fn system_support_commands_text_contract_matrix_has_required_markers() {
    let _guard = ENV_LOCK.lock().unwrap();

    with_temp_user_env(|| {
        let check = check_text_output_for_test(false);
        assert_text_markers_with_summary_mode(
            "check",
            &check,
            "system_check",
            "check",
            &["checks: label=Checks", "fixes_applied:"],
        );
    });

    let analyze = with_analyze_root_fixture(|analyze_root| {
        analyze_text_output_for_test(Some(analyze_root)).unwrap()
    });
    assert_text_markers_with_summary_mode(
        "analyze",
        &analyze,
        "system_analyze",
        "analyze",
        &[
            "root:",
            "top_entries_limit:",
            "total_files:",
            "entries: label=Top entries",
        ],
    );

    with_temp_user_env(|| {
        let status = status_text_output_for_test().unwrap();
        assert_text_markers_with_summary_mode(
            "status",
            &status,
            "system_status",
            "status",
            &["checks: label=Checks", "suggested_actions: count="],
        );

        let touchid = touchid_text_output_for_test(Some("status"), true).unwrap();
        assert_text_markers_with_summary_mode(
            "touchid",
            &touchid,
            "system_touchid",
            "dry_run",
            &["action: status", "action=status", "mode=dry_run"],
        );

        let completion = with_shell_env(Some("/bin/zsh"), || {
            completion_text_output_for_test(None, true).unwrap()
        });
        assert_text_markers_with_summary_mode(
            "completion",
            &completion,
            "system_completion",
            "dry_run",
            &["shell: zsh", "mode=dry_run", "config_path:"],
        );

        let update = with_update_release_env(|| update_text_output_for_test(false, false));
        assert_text_markers_with_summary_mode(
            "update",
            &update,
            "system_update",
            "plan",
            &[
                "channel=stable",
                "suggested_command:",
                "checks: label=Checks",
            ],
        );

        let remove = with_remove_targets_env(|| remove_text_output_for_test(true, false).unwrap());
        assert_text_markers_with_summary_mode(
            "remove",
            &remove,
            "system_remove",
            "dry_run",
            &[
                "executable:",
                "detected_path:",
                "checks: label=Checks",
                "manual_step:",
            ],
        );
    });
}

#[test]
fn system_text_schema_snapshot_matrix_is_stable() {
    let _guard = ENV_LOCK.lock().unwrap();

    let clean = with_clean_path_override(|| clean_text_output_for_test(true, false, None).unwrap());
    assert_text_markers_with_summary_mode(
        "clean",
        &clean,
        "system_clean",
        "dry_run",
        &["risk: high_targets="],
    );

    let purge = with_purge_path_override(|| purge_text_output_for_test(true, false).unwrap());
    assert_text_markers_with_summary_mode(
        "purge",
        &purge,
        "system_purge",
        "dry_run",
        &["Purge (dry-run)"],
    );

    let installer =
        with_installer_path_override(|| installer_text_output_for_test(true, false).unwrap());
    assert_text_markers_with_summary_mode(
        "installer",
        &installer,
        "system_installer",
        "dry_run",
        &["Installer (dry-run)"],
    );

    let uninstall = with_uninstall_path_override(|| {
        uninstall_text_output_for_test(Some("DemoApp.app"), true, false).unwrap()
    });
    assert_text_markers_with_summary_mode(
        "uninstall",
        &uninstall,
        "system_uninstall",
        "dry_run",
        &["Target: DemoApp.app"],
    );

    let optimize = optimize_text_output_for_test(true, false).unwrap();
    assert_text_markers_with_summary_mode(
        "optimize",
        &optimize,
        "system_optimize",
        "dry_run",
        &["Tasks:"],
    );

    let purge_paths = with_purge_path_override(purge_paths_text_for_test);
    assert_text_markers_with_summary_mode(
        "purge_paths",
        &purge_paths,
        "system_paths command=purge",
        "paths",
        &[],
    );

    let installer_paths = with_installer_path_override(installer_paths_text_for_test);
    assert_text_markers_with_summary_mode(
        "installer_paths",
        &installer_paths,
        "system_paths command=installer",
        "paths",
        &[],
    );

    let uninstall_paths = with_uninstall_path_override(uninstall_paths_text_for_test);
    assert_text_markers_with_summary_mode(
        "uninstall_paths",
        &uninstall_paths,
        "system_paths command=uninstall",
        "paths",
        &[],
    );

    with_temp_user_env(|| {
        let check = check_text_output_for_test(false);
        assert_text_markers_with_summary_mode(
            "check",
            &check,
            "system_check",
            "check",
            &["checks: label=Checks"],
        );

        let analyze = with_analyze_root_fixture(|analyze_root| {
            analyze_text_output_for_test(Some(analyze_root)).unwrap()
        });
        assert_text_markers_with_summary_mode(
            "analyze",
            &analyze,
            "system_analyze",
            "analyze",
            &["entries: label=Top entries"],
        );

        let status = status_text_output_for_test().unwrap();
        assert_text_markers_with_summary_mode(
            "status",
            &status,
            "system_status",
            "status",
            &["checks: label=Checks"],
        );

        let touchid = touchid_text_output_for_test(Some("status"), true).unwrap();
        assert_text_markers_with_summary_mode(
            "touchid",
            &touchid,
            "system_touchid",
            "dry_run",
            &["action: status"],
        );

        let completion = with_shell_env(Some("/bin/zsh"), || {
            completion_text_output_for_test(None, true).unwrap()
        });
        assert_text_markers_with_summary_mode(
            "completion",
            &completion,
            "system_completion",
            "dry_run",
            &["shell: zsh"],
        );

        let update = with_update_release_env(|| update_text_output_for_test(false, false));
        assert_text_markers_with_summary_mode(
            "update",
            &update,
            "system_update",
            "plan",
            &["checks: label=Checks"],
        );

        let remove = with_remove_targets_env(|| remove_text_output_for_test(true, false).unwrap());
        assert_text_markers_with_summary_mode(
            "remove",
            &remove,
            "system_remove",
            "dry_run",
            &["checks: label=Checks"],
        );

        let clean_whitelist = clean_whitelist_text_output_for_test().unwrap();
        assert_text_markers(
            "clean_whitelist",
            &clean_whitelist,
            &[
                "summary: kind=system_clean_whitelist",
                "entries: ",
                "defaults_written: ",
            ],
        );

        let optimize_whitelist = optimize_whitelist_text_output_for_test().unwrap();
        assert_text_markers(
            "optimize_whitelist",
            &optimize_whitelist,
            &[
                "summary: kind=system_optimize_whitelist",
                "available_tasks: ",
                "defaults_written: ",
            ],
        );
    });
}

#[test]
fn optimize_apply_runs_post_check_and_reports_remaining_issues() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output =
            optimize_output_with_executor_for_test(false, true, &AlwaysSuccessExecutor).unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.optimize"));
        assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
        assert_eq!(output["data"]["post_check_run"].as_bool(), Some(true));
        assert_eq!(
            output["data"]["post_check_overall_passed"].as_bool(),
            Some(false)
        );
        let actions = output["data"]["post_check_suggested_actions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_actions_include(
            &actions,
            &["preen check --fix", "preen plugin registry-update"],
        );
        let warnings = output["data"]["warnings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let has_post_check_warning = warnings.iter().any(|value| {
            value
                .as_str()
                .unwrap_or_default()
                .contains("post-optimize check")
        });
        assert!(has_post_check_warning);
    });
}

#[test]
fn optimize_apply_filters_recursive_optimize_suggestion_from_post_check() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let state_dir = plugin_install_base_dir_from_env()
            .parent()
            .unwrap()
            .to_path_buf();
        let plugins_dir = state_dir.join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        let generated_at = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let registry_index =
            format!("schema_version = 1\ngenerated_at = \"{generated_at}\"\nentries = []\n");
        fs::write(state_dir.join("registry-index.toml"), registry_index).unwrap();

        let output =
            optimize_output_with_executor_for_test(false, true, &AlwaysSuccessExecutor).unwrap();
        assert_eq!(output["data"]["post_check_run"].as_bool(), Some(true));
        assert_eq!(
            output["data"]["post_check_overall_passed"].as_bool(),
            Some(true)
        );
        let actions = output["data"]["post_check_suggested_actions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(actions.is_empty());
    });
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
        let actions = output["data"]["suggested_actions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_actions_include(
            &actions,
            &["preen check --fix", "preen plugin registry-update"],
        );
    });
}

#[test]
fn check_debug_mode_writes_debug_log() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let debug_log = temp.path().join("check-debug.log");
    let output = with_debug_log_env("PREEN_CHECK_DEBUG_LOG_PATH", &debug_log, || {
        check_output_with_debug_for_test(false, true).unwrap()
    });
    assert_eq!(output["kind"].as_str(), Some("system.check"));
    assert_eq!(
        output["data"]["debug_log_path"].as_str(),
        Some(debug_log.to_string_lossy().as_ref())
    );
    let log = fs::read_to_string(debug_log).unwrap();
    assert!(log.contains("mode=check"));
    assert!(log.contains("overall_passed="));
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
        let actions = output["data"]["suggested_actions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_actions_include(
            &actions,
            &["preen plugin registry-update", "preen optimize --dry-run"],
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
    assert_eq!(
        output["data"]["path"].as_str(),
        output["data"]["root"].as_str()
    );
    assert!(output["data"]["max_depth"].as_u64().is_some());
    assert!(output["data"]["top_entries_limit"].as_u64().unwrap_or(0) >= 1);
    assert!(output["data"]["total_files"].as_u64().unwrap_or(0) >= 2);
    assert_eq!(
        output["data"]["total_size"].as_u64(),
        output["data"]["total_size_bytes"].as_u64()
    );
    assert!(output["data"]["total_size_bytes"].as_u64().unwrap_or(0) >= 640);
    assert!(output["data"]["entries"].as_array().is_some());
    assert!(output["data"]["top_entries"].as_array().is_some());
}

#[test]
fn analyze_debug_mode_writes_debug_log_and_reports_path() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("dir-a")).unwrap();
    fs::write(root.join("dir-a").join("nested.bin"), vec![0_u8; 64]).unwrap();
    let debug_path = root.join("analyze-debug-test.log");

    let output = with_debug_log_env("PREEN_ANALYZE_DEBUG_LOG_PATH", &debug_path, || {
        analyze_output_with_debug_for_test(Some(root), Some(2), true).unwrap()
    });

    assert_eq!(
        output["data"]["debug_log_path"].as_str(),
        Some(debug_path.to_string_lossy().as_ref())
    );
    let debug_content = fs::read_to_string(&debug_path).unwrap();
    assert!(debug_content.contains("max_depth=2"));
    assert!(debug_content.contains("top_entries_limit="));
    assert!(debug_content.contains("warnings="));
}

#[test]
fn analyze_max_depth_override_reports_truncated_dirs() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("a").join("b")).unwrap();
    fs::write(root.join("a").join("b").join("deep.bin"), vec![0_u8; 64]).unwrap();

    let output = analyze_output_with_depth_for_test(Some(root), Some(1)).unwrap();
    assert_eq!(output["data"]["max_depth"].as_u64(), Some(1));
    assert!(output["data"]["truncated_dirs"].as_u64().unwrap_or(0) >= 1);
}

#[cfg(unix)]
#[test]
fn analyze_includes_symlink_entries_without_skip_warning() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::write(root.join("target.bin"), vec![1_u8; 32]).unwrap();
    symlink(root.join("target.bin"), root.join("target.link")).unwrap();

    let output = analyze_output_for_test(Some(root)).unwrap();
    let entries = output["data"]["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let has_symlink = entries.iter().any(|entry| {
        entry["item_type"].as_str() == Some("symlink")
            && entry["name"].as_str() == Some("target.link")
    });
    assert!(has_symlink);

    let warnings = output["data"]["warnings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let has_skip_warning = warnings.iter().any(|warning| {
        warning
            .as_str()
            .unwrap_or_default()
            .contains("analyze skipped symlink")
    });
    assert!(!has_skip_warning);
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
fn analyze_interactive_requires_tty_and_reports_system_code() {
    with_analyze_root_fixture(|analyze_root| {
        let cli = Cli::try_parse_from([
            "preen",
            "analyze",
            analyze_root.to_string_lossy().as_ref(),
            "--interactive",
        ])
        .unwrap();
        let err = run_typed(cli.clone()).unwrap_err();
        assert_eq!(err.kind, CliErrorKind::Unsupported);
        assert_eq!(
            err.detail_code.as_deref(),
            Some("analyze_interactive_tty_required")
        );
        let output = cli.format_error(&err);
        assert!(output.contains("detail_code=analyze_interactive_tty_required"));
        assert!(!output.contains("hint_code="));
    });
}

#[test]
fn analyze_interactive_rejects_json_conflict() {
    let parsed = Cli::try_parse_from(["preen", "analyze", "/tmp", "--interactive", "--json"]);
    assert!(parsed.is_err());
}

#[test]
fn analyze_selection_dedupes_nested_paths_for_trash() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("dir").join("nested")).unwrap();
    fs::write(root.join("dir").join("nested").join("a.bin"), b"1").unwrap();
    fs::write(root.join("dir").join("b.bin"), b"2").unwrap();

    let selected = analyze_selection_for_trash_for_test(
        root,
        &[
            root.join("dir").as_path(),
            root.join("dir").join("nested").as_path(),
        ],
    )
    .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected[0],
        fs::canonicalize(root.join("dir"))
            .unwrap()
            .to_string_lossy()
    );
}

#[test]
fn analyze_uses_env_path_when_arg_missing() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_analyze_root_fixture(|analyze_root| {
        let output = with_env_overrides(
            &[(
                "PREEN_ANALYZE_PATH",
                analyze_root.as_os_str().to_os_string(),
            )],
            || analyze_output_for_test(None).unwrap(),
        );
        assert_eq!(
            output["data"]["root"].as_str(),
            Some(analyze_root.to_string_lossy().as_ref())
        );
    });
}

#[test]
fn analyze_relative_env_path_resolves_against_current_cwd() {
    let _guard = ENV_LOCK.lock().unwrap();
    let cwd = std::env::current_dir().unwrap();
    let output = with_env_overrides(&[("PREEN_ANALYZE_PATH", OsString::from("."))], || {
        analyze_output_for_test(None).unwrap()
    });
    let resolved = PathBuf::from(output["data"]["root"].as_str().unwrap_or_default());
    assert_eq!(
        fs::canonicalize(resolved).unwrap(),
        fs::canonicalize(cwd).unwrap()
    );
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
        assert!(output["data"]["health_score"].as_u64().is_some());
        assert!(output["data"]["state_dir"].as_str().is_some());
        assert!(output["data"]["checks"].as_array().is_some());
        assert!(output["data"]["metrics"].as_object().is_some());
        assert!(output["data"]["suggested_actions"].as_array().is_some());
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
fn status_json_health_score_is_bounded() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = status_output_for_test().unwrap();
        let score = output["data"]["health_score"].as_u64().unwrap_or(101);
        assert!(score <= 100);
    });
}

#[test]
fn status_json_uses_env_overrides_for_extended_metrics() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = with_status_metrics_env(
            &[
                ("PREEN_STATUS_LOAD_1M_MILLI", "1200"),
                ("PREEN_STATUS_LOAD_5M_MILLI", "900"),
                ("PREEN_STATUS_LOAD_15M_MILLI", "700"),
                ("PREEN_STATUS_MEMORY_TOTAL_BYTES", "1000"),
                ("PREEN_STATUS_MEMORY_USED_BYTES", "250"),
                ("PREEN_STATUS_DISK_TOTAL_BYTES", "2000"),
                ("PREEN_STATUS_DISK_AVAILABLE_BYTES", "1500"),
                ("PREEN_STATUS_PROCESS_COUNT", "42"),
                ("PREEN_STATUS_NET_RX_BYTES", "1234"),
                ("PREEN_STATUS_NET_TX_BYTES", "5678"),
            ],
            || status_output_for_test().unwrap(),
        );

        let metrics = &output["data"]["metrics"];
        assert_eq!(metrics["load_avg_1m_milli"].as_u64(), Some(1200));
        assert_eq!(metrics["load_avg_5m_milli"].as_u64(), Some(900));
        assert_eq!(metrics["load_avg_15m_milli"].as_u64(), Some(700));
        assert_eq!(metrics["memory_used_pct"].as_u64(), Some(25));
        assert_eq!(metrics["disk_free_pct"].as_u64(), Some(75));
        assert_eq!(metrics["process_count"].as_u64(), Some(42));
        assert_eq!(metrics["network_rx_bytes"].as_u64(), Some(1234));
        assert_eq!(metrics["network_tx_bytes"].as_u64(), Some(5678));
    });
}

#[test]
fn status_force_json_env_can_disable_auto_json() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_env_overrides(&[("PREEN_STATUS_FORCE_JSON", OsString::from("0"))], || {
        assert!(!status_should_emit_json_for_test(false));
    });
}

#[test]
fn status_force_json_env_can_enable_auto_json() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_env_overrides(&[("PREEN_STATUS_FORCE_JSON", OsString::from("1"))], || {
        assert!(status_should_emit_json_for_test(false));
    });
}

#[test]
fn status_watch_output_contains_expected_frame_count() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = status_watch_output_for_test(3).unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.status.watch"));
        assert_eq!(output["data"]["mode"].as_str(), Some("watch"));
        assert_eq!(output["data"]["ticks"].as_u64(), Some(3));
        assert_eq!(output["data"]["frames"].as_array().unwrap().len(), 3);
    });
}

#[test]
fn status_watch_command_runs_and_stops_with_env_tick_limit() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        with_env_overrides(
            &[
                ("PREEN_STATUS_WATCH_MAX_TICKS", OsString::from("2")),
                ("PREEN_STATUS_FORCE_JSON", OsString::from("1")),
            ],
            || {
                let cli =
                    Cli::try_parse_from(["preen", "status", "--watch", "--interval-sec", "0"])
                        .unwrap();
                let result = run_typed(cli);
                assert!(result.is_ok());
            },
        );
    });
}

#[test]
fn status_watch_interval_requires_watch_flag() {
    let parsed = Cli::try_parse_from(["preen", "status", "--interval-sec", "1"]);
    assert!(parsed.is_err());
}

#[test]
fn status_suggested_actions_include_registry_update_when_registry_missing() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = status_output_for_test().unwrap();
        let actions = output["data"]["suggested_actions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let has_registry_update = actions
            .iter()
            .any(|value| value.as_str() == Some("preen plugin registry-update"));
        assert!(has_registry_update);
    });
}

#[test]
fn status_suggested_actions_include_cleanup_and_optimize_for_pressure() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = with_status_metrics_env(
            &[
                ("PREEN_STATUS_MEMORY_TOTAL_BYTES", "100"),
                ("PREEN_STATUS_MEMORY_USED_BYTES", "95"),
                ("PREEN_STATUS_DISK_TOTAL_BYTES", "100"),
                ("PREEN_STATUS_DISK_AVAILABLE_BYTES", "5"),
                ("PREEN_STATUS_LOAD_1M_MILLI", "10000"),
                ("PREEN_STATUS_PROCESS_COUNT", "42"),
                ("PREEN_STATUS_NET_RX_BYTES", "1234"),
                ("PREEN_STATUS_NET_TX_BYTES", "5678"),
            ],
            || status_output_for_test().unwrap(),
        );

        let actions = output["data"]["suggested_actions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_actions_include(
            &actions,
            &[
                "preen analyze --json",
                "preen clean --dry-run",
                "preen purge --dry-run",
                "preen optimize --dry-run",
            ],
        );
    });
}

#[test]
fn status_suggested_actions_are_unique_under_combined_pressure() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = with_status_metrics_env(
            &[
                ("PREEN_STATUS_MEMORY_TOTAL_BYTES", "100"),
                ("PREEN_STATUS_MEMORY_USED_BYTES", "95"),
                ("PREEN_STATUS_DISK_TOTAL_BYTES", "100"),
                ("PREEN_STATUS_DISK_AVAILABLE_BYTES", "5"),
                ("PREEN_STATUS_LOAD_1M_MILLI", "10000"),
            ],
            || status_output_for_test().unwrap(),
        );
        let actions = output["data"]["suggested_actions"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|item| item.as_str().map(ToOwned::to_owned))
            .collect::<Vec<_>>();
        let unique = actions
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(actions.len(), unique.len());
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
fn touchid_enable_apply_writes_pam_tid_line_when_supported() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let temp = tempfile::tempdir().unwrap();
        let pam = temp.path().join("sudo");
        let pam_local = temp.path().join("sudo_local");
        fs::write(&pam, "# sudo config\n").unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::set_var("PREEN_TOUCHID_FORCE_SUPPORTED", "1");
            std::env::set_var("PREEN_TOUCHID_SUDO_FILE", &pam);
            std::env::set_var("PREEN_TOUCHID_SUDO_LOCAL_FILE", &pam_local);
        }
        let output = touchid_output_for_test(Some("enable"), false).unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::remove_var("PREEN_TOUCHID_FORCE_SUPPORTED");
            std::env::remove_var("PREEN_TOUCHID_SUDO_FILE");
            std::env::remove_var("PREEN_TOUCHID_SUDO_LOCAL_FILE");
        }
        assert_eq!(output["data"]["applied"].as_bool(), Some(true));
        assert_eq!(output["data"]["configured"].as_bool(), Some(true));
        let content = fs::read_to_string(&pam).unwrap();
        assert!(content.contains("pam_tid.so"));
    });
}

#[test]
fn touchid_disable_apply_removes_pam_tid_line_when_supported() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let temp = tempfile::tempdir().unwrap();
        let pam = temp.path().join("sudo");
        let pam_local = temp.path().join("sudo_local");
        fs::write(
            &pam,
            "# sudo config\nauth       sufficient     pam_tid.so\nauth       include        sudo_local\n",
        )
        .unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::set_var("PREEN_TOUCHID_FORCE_SUPPORTED", "1");
            std::env::set_var("PREEN_TOUCHID_SUDO_FILE", &pam);
            std::env::set_var("PREEN_TOUCHID_SUDO_LOCAL_FILE", &pam_local);
        }
        let output = touchid_output_for_test(Some("disable"), false).unwrap();
        // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
        unsafe {
            std::env::remove_var("PREEN_TOUCHID_FORCE_SUPPORTED");
            std::env::remove_var("PREEN_TOUCHID_SUDO_FILE");
            std::env::remove_var("PREEN_TOUCHID_SUDO_LOCAL_FILE");
        }
        assert_eq!(output["data"]["applied"].as_bool(), Some(true));
        assert_eq!(output["data"]["configured"].as_bool(), Some(false));
        let content = fs::read_to_string(&pam).unwrap();
        assert!(!content.contains("pam_tid.so"));
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
        let output = with_completion_env(home.path(), Some("/bin/zsh"), None, || {
            completion_output_for_test(None, true).unwrap()
        });
        assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
        assert_eq!(output["data"]["installed"].as_bool(), Some(false));
        assert_eq!(output["data"]["changed"].as_bool(), Some(false));
        assert!(!home.path().join(".zshrc").exists());
    });
}

#[test]
fn completion_bash_prefers_bash_profile_when_present() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let home = tempfile::tempdir().unwrap();
        let bash_profile = home.path().join(".bash_profile");
        fs::write(&bash_profile, "# existing\n").unwrap();
        let output = with_completion_env(home.path(), None, Some("bash"), || {
            completion_output_for_test(None, false).unwrap()
        });
        assert_eq!(
            output["data"]["config_path"].as_str(),
            Some(bash_profile.to_string_lossy().as_ref())
        );
        assert_eq!(output["data"]["installed"].as_bool(), Some(true));
        assert_eq!(output["data"]["changed"].as_bool(), Some(true));
        let content = fs::read_to_string(&bash_profile).unwrap();
        assert!(content.contains("# Preen shell completion"));
    });
}

#[test]
fn completion_autodetect_uses_override_when_shell_missing() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let home = tempfile::tempdir().unwrap();
        let output = with_completion_env(home.path(), None, Some("fish"), || {
            completion_output_for_test(None, true).unwrap()
        });
        assert_eq!(output["data"]["shell"].as_str(), Some("fish"));
        assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    });
}

#[test]
fn update_json_happy_path_contains_suggested_command() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = with_update_release_env(|| update_output_for_test(false, false).unwrap());
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
fn update_nightly_homebrew_reports_unsupported_source() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = with_update_install_source_env("homebrew", || {
            update_output_for_test(false, true).unwrap()
        });
        assert_eq!(output["kind"].as_str(), Some("system.update"));
        assert_eq!(output["data"]["channel"].as_str(), Some("nightly"));
        assert_eq!(
            system_check_passed_from_json(&output["data"], "update_nightly_supported"),
            Some(false)
        );
        let warnings = output["data"]["warnings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(warnings.iter().any(|value| {
            value
                .as_str()
                .unwrap_or_default()
                .contains("nightly update is supported only for script installs")
        }));
        let command = output["data"]["suggested_command"]
            .as_str()
            .unwrap_or_default();
        assert!(command.contains("install.sh"));
        assert!(command.contains("--nightly"));
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
fn update_nightly_rejects_non_script_install_source() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let cli = Cli::try_parse_from(["preen", "update", "--nightly", "--json"]).unwrap();
        let err =
            with_update_install_source_env("homebrew", || run_typed(cli.clone()).unwrap_err());
        assert_eq!(err.kind, CliErrorKind::Validation);
        assert_eq!(
            err.detail_code.as_deref(),
            Some("update_nightly_unsupported_source")
        );
        let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
        assert_eq!(
            parsed["data"]["detail_code"].as_str(),
            Some("update_nightly_unsupported_source")
        );
    });
}

#[test]
fn update_execute_runs_suggested_command_when_available() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let capture_dir = tempfile::tempdir().unwrap();
        let capture_path = capture_dir.path().join("update-command.txt");
        let output = with_env_overrides(
            &[
                ("PREEN_UPDATE_LATEST_VERSION", OsString::from("9.9.9")),
                ("PREEN_UPDATE_INSTALL_SOURCE", OsString::from("cargo")),
                ("PREEN_UPDATE_EXECUTE_MOCK", OsString::from("success")),
                (
                    "PREEN_UPDATE_EXECUTE_CAPTURE_PATH",
                    capture_path.as_os_str().to_os_string(),
                ),
            ],
            || update_output_with_execute_for_test(false, false, true).unwrap(),
        );
        assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
        assert_eq!(output["data"]["executed"].as_bool(), Some(true));
        let capture = fs::read_to_string(&capture_path).unwrap();
        assert!(capture.contains("cargo install preen-cli"));
    });
}

#[test]
fn update_execute_skips_when_already_latest_without_force() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = with_env_overrides(
            &[
                (
                    "PREEN_UPDATE_LATEST_VERSION",
                    OsString::from(env!("CARGO_PKG_VERSION")),
                ),
                ("PREEN_UPDATE_INSTALL_SOURCE", OsString::from("cargo")),
                ("PREEN_UPDATE_EXECUTE_MOCK", OsString::from("success")),
            ],
            || update_output_with_execute_for_test(false, false, true).unwrap(),
        );
        assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
        assert_eq!(output["data"]["executed"].as_bool(), Some(false));
        let warnings = output["data"]["warnings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(warnings.iter().any(|value| {
            value
                .as_str()
                .unwrap_or_default()
                .contains("already latest; skipped update execution")
        }));
    });
}

#[test]
fn update_execute_failure_maps_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let cli = Cli::try_parse_from(["preen", "update", "--execute", "--json"]).unwrap();
        let err = with_env_overrides(
            &[
                ("PREEN_UPDATE_LATEST_VERSION", OsString::from("9.9.9")),
                ("PREEN_UPDATE_INSTALL_SOURCE", OsString::from("cargo")),
                ("PREEN_UPDATE_EXECUTE_MOCK", OsString::from("fail:boom")),
            ],
            || run_typed(cli.clone()).unwrap_err(),
        );
        assert_eq!(err.kind, CliErrorKind::Internal);
        assert_eq!(err.detail_code.as_deref(), Some("update_execute_failed"));
        let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
        assert_eq!(
            parsed["data"]["detail_code"].as_str(),
            Some("update_execute_failed")
        );
    });
}

#[test]
fn update_suggested_command_matrix_by_source_and_channel() {
    let _guard = ENV_LOCK.lock().unwrap();
    let cases = [
        ("cargo", false, "cargo install preen-cli --locked --force"),
        ("cargo", true, "install.sh | bash -s -- --nightly"),
        ("homebrew", false, "brew upgrade preen"),
        ("homebrew", true, "install.sh | bash -s -- --nightly"),
        ("script", false, "install.sh | bash"),
        ("script", true, "install.sh | bash -s -- --nightly"),
        ("unknown", false, "preen update --force"),
        ("unknown", true, "preen update --nightly --force"),
    ];

    for (source, nightly, marker) in cases {
        let output = with_env_overrides(
            &[("PREEN_UPDATE_INSTALL_SOURCE", OsString::from(source))],
            || update_output_for_test(false, nightly).unwrap(),
        );
        let command = output["data"]["suggested_command"]
            .as_str()
            .unwrap_or_default();
        assert!(
            command.contains(marker),
            "source={source} nightly={nightly} command={command}"
        );
    }
}

#[test]
fn update_version_compare_matrix_covers_true_false_and_none() {
    let _guard = ENV_LOCK.lock().unwrap();
    let current = env!("CARGO_PKG_VERSION");
    let cases = [
        ("9.9.9", Some(true)),
        (current, Some(false)),
        ("invalid", None),
    ];
    for (latest, expected) in cases {
        let output = with_env_overrides(
            &[("PREEN_UPDATE_LATEST_VERSION", OsString::from(latest))],
            || update_output_for_test(false, false).unwrap(),
        );
        let actual = output["data"]["update_available"].as_bool();
        assert_eq!(actual, expected, "latest={latest}");
    }
}

#[test]
fn remove_json_happy_path_dry_run() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = with_remove_paths_env(true, Some("cargo"), |_, _| {
            remove_output_for_test(true, false).unwrap()
        });
        assert_eq!(output["kind"].as_str(), Some("system.remove"));
        assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
        assert!(output["data"]["detected_paths"].as_array().is_some());
        assert!(output["data"]["checks"].as_array().is_some());
        assert!(output["data"]["manual_steps"].as_array().is_some());
    });
}

#[test]
fn remove_unknown_source_includes_executable_manual_step() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = with_update_install_source_env("unknown", || {
            remove_output_for_test(true, false).unwrap()
        });
        let executable = output["data"]["executable"].as_str().unwrap_or_default();
        let manual_steps = output["data"]["manual_steps"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let checks = output["data"]["checks"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(manual_steps.iter().any(|value| {
            let step = value.as_str().unwrap_or_default();
            step.starts_with("rm -f ") && step.contains(executable)
        }));
        assert!(checks.iter().any(|value| {
            value["id"].as_str() == Some("remove_source_detected")
                && value["passed"].as_bool() == Some(false)
        }));
    });
}

#[test]
fn remove_apply_deletes_temp_paths() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        with_remove_paths_env(true, Some("cargo"), |state_path, cache_path| {
            let output = remove_output_for_test(false, true).unwrap();
            assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
            assert!(!state_path.exists());
            assert!(!cache_path.exists());
            assert!(output["data"]["removed_paths"].as_array().is_some());
        });
    });
}

#[test]
fn remove_apply_requires_confirm() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        with_remove_paths_env(false, None, |_, _| {
            let cli = Cli::try_parse_from(["preen", "remove", "--json"]).unwrap();
            let err = run_typed(cli.clone()).unwrap_err();
            assert_eq!(err.kind, CliErrorKind::Validation);
            assert_eq!(
                err.detail_code.as_deref(),
                Some("remove_confirmation_required")
            );
            let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
            assert_eq!(
                parsed["data"]["detail_code"].as_str(),
                Some("remove_confirmation_required")
            );
        });
    });
}

#[test]
fn remove_command_runs_without_error() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        with_remove_paths_env(false, None, |_, _| {
            let cli = Cli::try_parse_from(["preen", "remove", "--dry-run", "--json"]).unwrap();
            let result = run_typed(cli);
            assert!(result.is_ok());
        });
    });
}

#[test]
fn remove_rejects_dry_run_with_confirm_conflict() {
    let parsed = Cli::try_parse_from(["preen", "remove", "--dry-run", "--confirm"]);
    assert!(parsed.is_err());
}

#[test]
fn remove_rejects_relative_override_paths() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let cache_root = tempfile::tempdir().unwrap();
        let cache_path = cache_root.path().join("cache");
        fs::create_dir_all(&cache_path).unwrap();
        let cli = Cli::try_parse_from(["preen", "remove", "--dry-run", "--json"]).unwrap();
        let err = with_env_overrides(
            &[
                ("PREEN_REMOVE_STATE_DIR", OsString::from("relative/state")),
                ("PREEN_REMOVE_CACHE_DIR", cache_path.into_os_string()),
            ],
            || run_typed(cli.clone()).unwrap_err(),
        );
        assert_eq!(err.kind, CliErrorKind::Validation);
        assert_eq!(
            err.detail_code.as_deref(),
            Some("remove_path_scope_violation")
        );
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
    let preview_list = temp.path().join("uninstall-list.txt");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(app_dir.join("Info.plist"), b"demo").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_UNINSTALL_PATHS", temp.path().as_os_str());
        std::env::set_var(
            "PREEN_UNINSTALL_PREVIEW_LIST_PATH",
            preview_list.as_os_str(),
        );
    }

    let output = uninstall_output_for_test(Some("DemoApp"), true, false).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.uninstall"));
    assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    assert_eq!(output["data"]["target"].as_str(), Some("DemoApp"));
    assert_eq!(output["data"]["scan_depth"].as_u64(), Some(3));
    assert!(output["data"]["target_count"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(
        output["data"]["preview_list_path"].as_str(),
        Some(preview_list.to_string_lossy().as_ref())
    );
    assert!(
        fs::read_to_string(preview_list)
            .unwrap()
            .contains("DemoApp.app")
    );

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_UNINSTALL_PATHS");
        std::env::remove_var("PREEN_UNINSTALL_PREVIEW_LIST_PATH");
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
fn uninstall_debug_mode_writes_debug_log() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let app_dir = temp.path().join("DemoApp.app");
    let debug_log = temp.path().join("uninstall-debug.log");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(app_dir.join("Info.plist"), b"demo").unwrap();
    let output = with_env_overrides(
        &[
            (
                "PREEN_UNINSTALL_PATHS",
                temp.path().as_os_str().to_os_string(),
            ),
            (
                "PREEN_UNINSTALL_DEBUG_LOG_PATH",
                debug_log.as_os_str().to_os_string(),
            ),
        ],
        || uninstall_output_with_debug_for_test(Some("DemoApp"), true, false, true).unwrap(),
    );
    assert_eq!(
        output["data"]["debug_log_path"].as_str(),
        Some(debug_log.to_string_lossy().as_ref())
    );
    let log = fs::read_to_string(debug_log).unwrap();
    assert!(log.contains("target=DemoApp"));
    assert!(log.contains("scan_depth=3"));
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
        std::env::set_var("PREEN_PURGE_MIN_AGE_DAYS", "0");
    }

    let output = purge_output_for_test(true, false).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.purge"));
    assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    assert!(output["data"]["target_count"].as_u64().unwrap_or(0) >= 1);

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_PURGE_PATHS");
        std::env::remove_var("PREEN_PURGE_MIN_AGE_DAYS");
    }
}

#[test]
fn purge_dry_run_skips_recent_artifacts_by_default_age_policy() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("app");
    let artifact = project.join("node_modules");
    fs::create_dir_all(&artifact).unwrap();
    fs::write(artifact.join("a.js"), b"1234").unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_PURGE_PATHS", temp.path().as_os_str());
        std::env::remove_var("PREEN_PURGE_MIN_AGE_DAYS");
    }

    let output = purge_output_for_test(true, false).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.purge"));
    assert_eq!(output["data"]["target_count"].as_u64(), Some(0));
    assert!(output["data"]["skipped_recent"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(output["data"]["min_age_days"].as_i64(), Some(7));

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_PURGE_PATHS");
        std::env::remove_var("PREEN_PURGE_MIN_AGE_DAYS");
    }
}

#[test]
fn purge_debug_mode_writes_debug_log() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("app");
    let artifact = project.join("target");
    let debug_log = temp.path().join("purge-debug.log");
    fs::create_dir_all(&artifact).unwrap();
    fs::write(artifact.join("x.bin"), b"1234").unwrap();
    let output = with_env_overrides(
        &[
            ("PREEN_PURGE_PATHS", temp.path().as_os_str().to_os_string()),
            ("PREEN_PURGE_MIN_AGE_DAYS", OsString::from("0")),
            (
                "PREEN_PURGE_DEBUG_LOG_PATH",
                debug_log.as_os_str().to_os_string(),
            ),
        ],
        || purge_output_with_debug_for_test(true, false, true).unwrap(),
    );
    assert_eq!(output["kind"].as_str(), Some("system.purge"));
    assert_eq!(
        output["data"]["debug_log_path"].as_str(),
        Some(debug_log.to_string_lossy().as_ref())
    );
    assert!(debug_log.exists());
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
        std::env::set_var("PREEN_PURGE_MIN_AGE_DAYS", "0");
    }

    let output = purge_output_for_test(false, true).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.purge"));
    assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
    assert!(output["data"]["affected_items"].as_u64().unwrap_or(0) >= 1);
    assert!(!artifact.exists());

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_PURGE_PATHS");
        std::env::remove_var("PREEN_PURGE_MIN_AGE_DAYS");
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
    let preview_list = temp.path().join("installer-list.txt");
    fs::write(&installer, vec![0u8; 11 * 1024 * 1024]).unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_INSTALLER_PATHS", temp.path().as_os_str());
        std::env::set_var(
            "PREEN_INSTALLER_PREVIEW_LIST_PATH",
            preview_list.as_os_str(),
        );
    }

    let output = installer_output_for_test(true, false).unwrap();
    assert_eq!(output["kind"].as_str(), Some("system.installer"));
    assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    assert_eq!(output["data"]["scan_depth"].as_u64(), Some(2));
    assert!(output["data"]["target_count"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(
        output["data"]["preview_list_path"].as_str(),
        Some(preview_list.to_string_lossy().as_ref())
    );
    let preview_text = fs::read_to_string(preview_list).unwrap();
    assert!(preview_text.contains("Setup.pkg"));

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_INSTALLER_PATHS");
        std::env::remove_var("PREEN_INSTALLER_PREVIEW_LIST_PATH");
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
fn installer_debug_writes_log_when_enabled() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let installer = temp.path().join("archive.pkg");
    let debug_log = temp.path().join("installer-debug.log");
    fs::write(&installer, vec![0u8; 11 * 1024 * 1024]).unwrap();
    let output = with_env_overrides(
        &[
            (
                "PREEN_INSTALLER_PATHS",
                temp.path().as_os_str().to_os_string(),
            ),
            (
                "PREEN_INSTALLER_DEBUG_LOG_PATH",
                debug_log.as_os_str().to_os_string(),
            ),
        ],
        || installer_output_with_debug_for_test(true, false, true).unwrap(),
    );
    assert_eq!(
        output["data"]["debug_log_path"].as_str(),
        Some(debug_log.to_string_lossy().as_ref())
    );
    let log = fs::read_to_string(debug_log).unwrap();
    assert!(log.contains("scan_depth=2"));
    assert!(log.contains("target_count=1"));
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
fn purge_json_maps_command_timeout_detail_code_without_plugin_hints() {
    let parsed = purge_error_json_for_forced_executor(ActionExecutionError::CommandTimeout {
        command: "purge command".to_string(),
        timeout_sec: 9,
    });
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "internal");
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "purge_command_timeout"
    );
    assert!(parsed["data"]["hint_code"].is_null());
    assert!(parsed["data"]["hint_action"].is_null());
    assert!(parsed["data"]["hint_message"].is_null());
}

#[test]
fn optimize_json_maps_command_non_zero_detail_code_without_plugin_hints() {
    let parsed = optimize_error_json_for_forced_executor(ActionExecutionError::CommandNonZero {
        command: "optimize command".to_string(),
        code: Some(7),
    });
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "internal");
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "optimize_command_non_zero"
    );
    assert!(parsed["data"]["hint_code"].is_null());
    assert!(parsed["data"]["hint_action"].is_null());
    assert!(parsed["data"]["hint_message"].is_null());
}

#[test]
fn installer_json_maps_command_timeout_detail_code_without_plugin_hints() {
    let parsed = installer_error_json_for_forced_executor(ActionExecutionError::CommandTimeout {
        command: "installer command".to_string(),
        timeout_sec: 11,
    });
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "internal");
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "installer_command_timeout"
    );
    assert!(parsed["data"]["hint_code"].is_null());
    assert!(parsed["data"]["hint_action"].is_null());
    assert!(parsed["data"]["hint_message"].is_null());
}

#[test]
fn uninstall_json_maps_command_denied_detail_code_without_plugin_hints() {
    let parsed = uninstall_error_json_for_forced_executor(ActionExecutionError::CommandDenied {
        command: "uninstall command".to_string(),
    });
    assert_eq!(parsed["kind"].as_str().unwrap(), "error");
    assert_eq!(parsed["data"]["error_kind"].as_str().unwrap(), "internal");
    assert_eq!(
        parsed["data"]["detail_code"].as_str().unwrap(),
        "uninstall_command_denied"
    );
    assert!(parsed["data"]["hint_code"].is_null());
    assert!(parsed["data"]["hint_action"].is_null());
    assert!(parsed["data"]["hint_message"].is_null());
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
        vec!["preen", "clean", "--whitelist", "--json"],
        vec!["preen", "clean", "--dry-run", "--debug", "--json"],
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
        vec![
            "preen",
            "uninstall",
            "DemoApp",
            "--dry-run",
            "--debug",
            "--json",
        ],
        vec!["preen", "uninstall", "DemoApp", "--confirm", "--json"],
        vec!["preen", "uninstall", "--paths", "--json"],
        vec!["preen", "optimize", "--dry-run", "--json"],
        vec!["preen", "optimize", "--dry-run", "--debug", "--json"],
        vec!["preen", "optimize", "--confirm", "--json"],
        vec!["preen", "optimize", "--whitelist", "--json"],
        vec!["preen", "analyze", "/tmp", "--json"],
        vec!["preen", "analyze", "/tmp", "--debug", "--json"],
        vec!["preen", "analyze", "/tmp", "--max-depth", "3", "--json"],
        vec!["preen", "analyze", "/tmp", "--interactive"],
        vec!["preen", "status", "--json"],
        vec![
            "preen",
            "status",
            "--watch",
            "--interval-sec",
            "1",
            "--json",
        ],
        vec!["preen", "purge", "--dry-run", "--json"],
        vec!["preen", "purge", "--dry-run", "--debug", "--json"],
        vec!["preen", "purge", "--confirm", "--json"],
        vec!["preen", "purge", "--paths", "--json"],
        vec!["preen", "installer", "--dry-run", "--json"],
        vec!["preen", "installer", "--dry-run", "--debug", "--json"],
        vec!["preen", "installer", "--confirm", "--json"],
        vec!["preen", "installer", "--paths", "--json"],
        vec!["preen", "check", "--fix", "--json"],
        vec!["preen", "check", "--debug", "--json"],
        vec!["preen", "touchid", "enable", "--dry-run", "--json"],
        vec!["preen", "completion", "zsh", "--dry-run", "--json"],
        vec!["preen", "update", "--force", "--nightly", "--json"],
        vec!["preen", "update", "--execute", "--json"],
        vec!["preen", "remove", "--dry-run", "--json"],
        vec!["preen", "remove", "--confirm", "--json"],
    ];
    for args in cases {
        Cli::try_parse_from(args).unwrap();
    }
}

#[test]
fn top_level_system_commands_short_flags_parse() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["preen", "clean", "-n"],
        vec!["preen", "clean", "--whitelist"],
        vec!["preen", "uninstall", "DemoApp", "-n"],
        vec!["preen", "uninstall", "DemoApp", "--debug"],
        vec!["preen", "optimize", "-n"],
        vec!["preen", "optimize", "--debug"],
        vec!["preen", "optimize", "--whitelist"],
        vec!["preen", "analyze", "/tmp", "--debug"],
        vec!["preen", "purge", "-n"],
        vec!["preen", "purge", "--debug"],
        vec!["preen", "installer", "-n"],
        vec!["preen", "installer", "--debug"],
        vec!["preen", "check", "--debug"],
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
fn plugin_verbose_option_supports_single_and_all_flows() {
    assert!(
        Cli::try_parse_from([
            "preen",
            "plugin",
            "preflight",
            "preen-rs.homebrew@1.0.0",
            "--verbose",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from(["preen", "plugin", "test", "preen-rs.homebrew", "--verbose",]).is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "preen",
            "plugin",
            "install",
            "preen-rs.homebrew@1.0.0",
            "--verbose",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "preen",
            "plugin",
            "update",
            "preen-rs.homebrew",
            "--verbose",
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["preen", "plugin", "preflight", "--all", "--verbose"]).is_ok());
    assert!(Cli::try_parse_from(["preen", "plugin", "test", "--all", "--verbose"]).is_ok());
}

#[test]
fn plugin_list_and_search_option_matrix_parses() {
    assert!(
        Cli::try_parse_from([
            "preen", "plugin", "list", "--query", "homebrew", "--source", "registry", "--sort",
            "version", "--desc",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "preen", "plugin", "search", "brew", "--sort", "pack-id", "--offset", "5", "--limit",
            "10", "--desc",
        ])
        .is_ok()
    );
}

#[test]
fn plugin_progress_line_format_is_stable() {
    let line = progress_line_for_test("plugin.install", "verify_signature", "preen-rs.homebrew");
    assert_eq!(
        line,
        "progress: command=plugin.install stage=verify_signature subject=preen-rs.homebrew"
    );
}

#[test]
fn top_level_system_command_option_matrix_rejects_conflicts() {
    let invalid_cases: &[&[&str]] = &[
        &["preen", "clean", "--dry-run", "--confirm"],
        &["preen", "clean", "--whitelist", "--confirm"],
        &["preen", "clean", "--whitelist", "--dry-run"],
        &["preen", "clean", "--whitelist", "--strategy", "trash"],
        &["preen", "uninstall", "DemoApp", "--dry-run", "--confirm"],
        &["preen", "uninstall", "DemoApp", "--paths"],
        &["preen", "uninstall", "--paths", "--dry-run"],
        &["preen", "optimize", "--dry-run", "--confirm"],
        &["preen", "optimize", "--whitelist", "--dry-run"],
        &["preen", "optimize", "--whitelist", "--confirm"],
        &["preen", "optimize", "--whitelist", "--debug"],
        &["preen", "purge", "--dry-run", "--confirm"],
        &["preen", "purge", "--paths", "--confirm"],
        &["preen", "installer", "--dry-run", "--confirm"],
        &["preen", "installer", "--paths", "--dry-run"],
        &["preen", "touchid", "invalid-action", "--dry-run"],
        &["preen", "completion", "invalid-shell", "--dry-run"],
        &["preen", "analyze", "/tmp", "--interactive", "--json"],
        &["preen", "status", "--interval-sec", "1"],
    ];

    for args in invalid_cases {
        assert!(
            Cli::try_parse_from(*args).is_err(),
            "expected parse error for args: {args:?}"
        );
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
fn optimize_whitelist_rejects_dry_run_confirm_or_debug_conflicts() {
    let with_dry_run = Cli::try_parse_from(["preen", "optimize", "--whitelist", "--dry-run"]);
    assert!(with_dry_run.is_err());
    let with_confirm = Cli::try_parse_from(["preen", "optimize", "--whitelist", "--confirm"]);
    assert!(with_confirm.is_err());
    let with_debug = Cli::try_parse_from(["preen", "optimize", "--whitelist", "--debug"]);
    assert!(with_debug.is_err());
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
fn system_option_matrix_accepts_valid_flag_combinations() {
    let valid_cases = [
        vec!["preen", "clean", "--dry-run"],
        vec!["preen", "clean", "--confirm"],
        vec!["preen", "clean", "--whitelist"],
        vec!["preen", "clean", "--dry-run", "--debug"],
        vec!["preen", "optimize", "--dry-run"],
        vec!["preen", "optimize", "--dry-run", "--debug"],
        vec!["preen", "optimize", "--confirm"],
        vec!["preen", "optimize", "--whitelist"],
        vec!["preen", "purge", "--dry-run"],
        vec!["preen", "purge", "--dry-run", "--debug"],
        vec!["preen", "purge", "--confirm"],
        vec!["preen", "purge", "--paths"],
        vec!["preen", "installer", "--dry-run"],
        vec!["preen", "installer", "--dry-run", "--debug"],
        vec!["preen", "installer", "--confirm"],
        vec!["preen", "installer", "--paths"],
        vec!["preen", "uninstall", "Demo.app", "--dry-run"],
        vec!["preen", "uninstall", "Demo.app", "--dry-run", "--debug"],
        vec!["preen", "uninstall", "Demo.app", "--confirm"],
        vec!["preen", "uninstall", "--paths"],
        vec!["preen", "analyze", "/tmp", "--max-depth", "2"],
        vec!["preen", "analyze", "/tmp", "--debug"],
        vec!["preen", "analyze", "/tmp", "--interactive"],
        vec!["preen", "status"],
        vec!["preen", "status", "--watch", "--interval-sec", "1"],
        vec!["preen", "check", "--fix"],
        vec!["preen", "check", "--debug"],
        vec!["preen", "touchid", "status", "--dry-run"],
        vec!["preen", "completion", "zsh", "--dry-run"],
        vec!["preen", "update", "--force", "--nightly"],
        vec!["preen", "update", "--execute"],
        vec!["preen", "remove", "--dry-run"],
        vec!["preen", "remove", "--confirm"],
    ];

    for args in valid_cases {
        let parsed = Cli::try_parse_from(args.clone());
        assert!(
            parsed.is_ok(),
            "expected valid system option combination, got parse error: {args:?}"
        );
    }
}

#[test]
fn system_option_matrix_rejects_conflicting_flags() {
    let invalid_cases = [
        vec!["preen", "clean", "--dry-run", "--confirm"],
        vec!["preen", "clean", "--whitelist", "--confirm"],
        vec!["preen", "clean", "--whitelist", "--dry-run"],
        vec!["preen", "clean", "--whitelist", "--strategy", "delete"],
        vec!["preen", "optimize", "--dry-run", "--confirm"],
        vec!["preen", "optimize", "--whitelist", "--dry-run"],
        vec!["preen", "optimize", "--whitelist", "--confirm"],
        vec!["preen", "optimize", "--whitelist", "--debug"],
        vec!["preen", "purge", "--paths", "--dry-run"],
        vec!["preen", "purge", "--paths", "--confirm"],
        vec!["preen", "installer", "--paths", "--dry-run"],
        vec!["preen", "installer", "--paths", "--confirm"],
        vec!["preen", "uninstall", "Demo.app", "--paths"],
        vec!["preen", "uninstall", "--paths", "--dry-run"],
        vec!["preen", "uninstall", "--paths", "--confirm"],
        vec!["preen", "analyze", "/tmp", "--interactive", "--json"],
        vec!["preen", "status", "--interval-sec", "1"],
        vec!["preen", "remove", "--dry-run", "--confirm"],
    ];

    for args in invalid_cases {
        let parsed = Cli::try_parse_from(args.clone());
        assert!(
            parsed.is_err(),
            "expected conflicting system flags to fail parsing: {args:?}"
        );
    }
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
fn json_error_output_is_suppressed_when_report_already_emitted_for_verify() {
    let json_cli =
        Cli::try_parse_from(["preen", "plugin", "verify", "test.pack", "--json"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Verification,
        detail_code: Some("verify_manifest_hash_drift".to_string()),
        message: "plugin verify failed for test.pack".to_string(),
    };
    assert!(!should_emit_formatted_error(&json_cli, &err));
}

#[test]
fn json_error_output_is_suppressed_when_report_already_emitted_for_verify_os_target_failure() {
    let json_cli =
        Cli::try_parse_from(["preen", "plugin", "verify", "test.pack", "--json"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Validation,
        detail_code: Some("verify_os_target_failed".to_string()),
        message: "rule pack not compatible with this OS".to_string(),
    };
    assert!(!should_emit_formatted_error(&json_cli, &err));
}

#[test]
fn json_error_output_is_suppressed_when_report_already_emitted_for_test_all() {
    let json_cli = Cli::try_parse_from(["preen", "plugin", "test", "--all", "--json"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Verification,
        detail_code: Some("test_all_failed".to_string()),
        message: "1 plugin test checks failed".to_string(),
    };
    assert!(!should_emit_formatted_error(&json_cli, &err));
}

#[test]
fn json_error_output_is_suppressed_when_report_already_emitted_for_test_single() {
    let json_cli = Cli::try_parse_from(["preen", "plugin", "test", "test.pack", "--json"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Verification,
        detail_code: Some("test_manifest_hash_drift".to_string()),
        message: "plugin test failed for test.pack".to_string(),
    };
    assert!(!should_emit_formatted_error(&json_cli, &err));
}

#[test]
fn format_error_json_for_test_all_failed_includes_aggregate_hint_metadata() {
    let json_cli = Cli::try_parse_from(["preen", "plugin", "test", "--all", "--json"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Verification,
        detail_code: Some("test_all_failed".to_string()),
        message: "1 plugin test checks failed".to_string(),
    };
    let parsed: Value = serde_json::from_str(&json_cli.format_error(&err)).unwrap();
    assert_eq!(parsed["kind"].as_str(), Some("error"));
    assert_eq!(parsed["data"]["error_kind"].as_str(), Some("verification"));
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("test_all_failed")
    );
    assert_eq!(
        parsed["data"]["hint_code"].as_str(),
        Some("aggregate_failed")
    );
    assert_eq!(
        parsed["data"]["hint_action"].as_str(),
        Some("inspect_per_plugin_failure_rows")
    );
    assert!(parsed["data"]["hint_message"].as_str().is_some());
}

#[test]
fn json_error_output_is_suppressed_when_report_already_emitted_for_preflight_all() {
    let json_cli =
        Cli::try_parse_from(["preen", "plugin", "preflight", "--all", "--json"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Verification,
        detail_code: Some("preflight_all_failed".to_string()),
        message: "1 plugin preflight checks failed".to_string(),
    };
    assert!(!should_emit_formatted_error(&json_cli, &err));
}

#[test]
fn json_error_output_is_kept_when_no_report_was_emitted() {
    let json_cli =
        Cli::try_parse_from(["preen", "plugin", "verify", "test.pack", "--json"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Validation,
        detail_code: Some("verify_pack_load_failed".to_string()),
        message: "load failed".to_string(),
    };
    assert!(should_emit_formatted_error(&json_cli, &err));
}

#[test]
fn text_error_output_is_never_suppressed() {
    let plain_cli = Cli::try_parse_from(["preen", "plugin", "verify", "test.pack"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Verification,
        detail_code: Some("verify_manifest_hash_drift".to_string()),
        message: "plugin verify failed for test.pack".to_string(),
    };
    assert!(should_emit_formatted_error(&plain_cli, &err));
}

#[test]
fn format_error_json_includes_registry_hint_fields() {
    let json_cli = Cli::try_parse_from(["preen", "plugin", "registry-update", "--json"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Verification,
        detail_code: Some("registry_signature_verify_failed".to_string()),
        message: "registry signature verification failed: SignatureInvalid(\"manifest certificate is missing\")".to_string(),
    };
    let json_out = json_cli.format_error(&err);
    let parsed: Value = serde_json::from_str(&json_out).unwrap();
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("registry_signature_verify_failed")
    );
    assert_eq!(
        parsed["data"]["hint_code"].as_str(),
        Some("trust_or_signature_failed")
    );
    assert_eq!(
        parsed["data"]["hint_action"].as_str(),
        Some("check_sigstore_identity_and_trust_policy")
    );
    assert!(parsed["data"]["hint_message"].as_str().is_some());
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
fn format_error_uses_locale_and_hint_for_source_checkout_detail_code_in_de() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_LANG", "de-DE");
    }
    let plain_cli = Cli::try_parse_from(["preen", "plugin", "search"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Internal,
        detail_code: Some("install_source_fetch_failed".to_string()),
        message: "source fetch failed".to_string(),
    };
    let out = plain_cli.format_error(&err);
    assert!(out.contains("detail_code=install_source_fetch_failed"));
    assert!(out.contains("hint_code=source_checkout_failed"));
    assert!(out.contains("hint_action=validate_git_url_and_pinned_rev"));
    assert!(out.contains("message=Git-Checkout fehlgeschlagen."));
    assert!(out.contains("hint_message=Git-Checkout fehlgeschlagen."));
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_LANG");
    }
}

#[test]
fn format_error_json_uses_locale_for_source_checkout_hint_message() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_LANG", "de-DE");
    }
    let json_cli = Cli::try_parse_from(["preen", "plugin", "search", "--json"]).unwrap();
    let err = CliError {
        kind: CliErrorKind::Internal,
        detail_code: Some("preflight_source_checkout_failed".to_string()),
        message: "source checkout failed".to_string(),
    };
    let out = json_cli.format_error(&err);
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("preflight_source_checkout_failed")
    );
    assert_eq!(
        parsed["data"]["hint_code"].as_str(),
        Some("source_checkout_failed")
    );
    assert_eq!(
        parsed["data"]["hint_action"].as_str(),
        Some("validate_git_url_and_pinned_rev")
    );
    assert!(
        parsed["data"]["hint_message"]
            .as_str()
            .unwrap()
            .contains("Git-Checkout")
    );
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
fn format_error_localizes_prefixed_system_detail_codes_in_de() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::set_var("PREEN_LANG", "de-DE");
    }
    let cli = Cli::try_parse_from(["preen", "status"]).unwrap();

    let cases = [
        (
            "purge_confirmation_required",
            "Purge-Anwenden benoetigt --confirm.",
        ),
        (
            "purge_command_timeout",
            "Purge-Befehl hat das Zeitlimit ueberschritten.",
        ),
        (
            "installer_path_scope_violation",
            "Ausgewaehlter Installer Pfad liegt ausserhalb",
        ),
        (
            "installer_command_timeout",
            "Installer-Befehl hat das Zeitlimit ueberschritten.",
        ),
        (
            "uninstall_command_timeout",
            "Uninstall-Befehl hat das Zeitlimit ueberschritten.",
        ),
        (
            "uninstall_command_denied",
            "Uninstall-Befehl wurde durch Allowlist abgelehnt.",
        ),
        (
            "optimize_no_tasks",
            "Optimize hat auf diesem Betriebssystem keine unterstuetzten Aufgaben.",
        ),
        (
            "optimize_command_non_zero",
            "Optimize-Befehl endete mit einem Fehlerstatus.",
        ),
        (
            "analyze_root_not_found",
            "Analyze-Wurzel wurde nicht gefunden.",
        ),
        (
            "status_state_dir_unavailable",
            "State-Verzeichnis fuer Status ist nicht verfuegbar.",
        ),
        (
            "completion_shell_unknown",
            "Shell fuer Completion konnte nicht erkannt werden.",
        ),
        (
            "update_nightly_unsupported_source",
            "Update Nightly-Update wird nur fuer Script-Installationen unterstuetzt.",
        ),
        (
            "remove_path_resolve_failed",
            "Remove-Pfadauflosung ist fehlgeschlagen.",
        ),
    ];

    for (detail_code, expected_text) in cases {
        let err = CliError {
            kind: CliErrorKind::Validation,
            detail_code: Some(detail_code.to_string()),
            message: "original fallback message".to_string(),
        };
        let out = cli.format_error(&err);
        assert!(out.contains(&format!("detail_code={detail_code}")));
        assert!(
            out.contains(expected_text),
            "missing localized text for {detail_code}: {out}"
        );
        assert!(
            !out.contains("hint_code="),
            "system error should not include plugin hint"
        );
    }

    // SAFETY: test holds ENV_LOCK to avoid concurrent env mutation.
    unsafe {
        std::env::remove_var("PREEN_LANG");
    }
}

#[test]
fn format_error_json_for_system_prefixed_codes_omits_plugin_hint_fields() {
    let cli = Cli::try_parse_from(["preen", "status", "--json"]).unwrap();
    let detail_codes = [
        "clean_confirmation_required",
        "purge_command_timeout",
        "purge_path_scope_violation",
        "installer_command_timeout",
        "installer_command_non_zero",
        "uninstall_command_denied",
        "uninstall_command_non_zero",
        "optimize_command_denied",
        "optimize_command_non_zero",
        "analyze_root_not_directory",
        "status_state_dir_unavailable",
        "completion_read_failed",
        "remove_execution_failed",
    ];

    for detail_code in detail_codes {
        let err = CliError {
            kind: CliErrorKind::Validation,
            detail_code: Some(detail_code.to_string()),
            message: "original fallback message".to_string(),
        };
        let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
        assert_eq!(parsed["kind"].as_str(), Some("error"));
        assert_eq!(parsed["data"]["detail_code"].as_str(), Some(detail_code));
        assert!(parsed["data"]["hint_code"].is_null());
        assert!(parsed["data"]["hint_action"].is_null());
        assert!(parsed["data"]["hint_message"].is_null());
    }
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
    assert_eq!(err.detail_code.as_deref(), Some("install_spec_invalid"));
    assert!(err.message.contains("missing @<tag|commit>"));
}

#[test]
fn run_typed_rejects_registry_install_with_invalid_pack_id() {
    let cli = Cli::try_parse_from(["preen", "plugin", "install", "../evil@1.0.0"]).unwrap();
    let err = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(err.detail_code.as_deref(), Some("install_spec_invalid"));
    assert!(err.message.contains("invalid pack_id"));
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
    assert_eq!(
        err.detail_code.as_deref(),
        Some("install_source_clone_failed")
    );
}

#[test]
fn git_filter_unsupported_detection_recognizes_common_messages() {
    assert!(is_git_filter_unsupported_error_for_test(
        "fatal: the server does not support filter"
    ));
    assert!(is_git_filter_unsupported_error_for_test(
        "git command failed in repo: fetch --filter=blob:none: fatal: invalid filter-spec 'blob:none'"
    ));
    assert!(is_git_filter_unsupported_error_for_test(
        "error: unknown option --filter"
    ));
}

#[test]
fn git_filter_unsupported_detection_ignores_unrelated_clone_errors() {
    assert!(!is_git_filter_unsupported_error_for_test(
        "git command failed: clone --filter=blob:none --depth 1 --no-checkout https://github.com/org/missing.git /tmp/x: fatal: repository not found"
    ));
    assert!(!is_git_filter_unsupported_error_for_test(
        "git command failed in repo: fetch --depth 1 origin v1.0.0: fatal: couldn't find remote ref v1.0.0"
    ));
}

#[test]
fn map_clone_error_detail_code_identifies_clone_fetch_checkout_resolve_stages() {
    assert_eq!(
        map_clone_error_detail_code_for_test(
            "install",
            "__preen_kind:internal__git command failed: clone --depth 1 --no-checkout https://example/repo /tmp/repo: fatal: repository not found"
        ),
        "install_source_clone_failed"
    );
    assert_eq!(
        map_clone_error_detail_code_for_test(
            "install",
            "__preen_kind:internal__git command failed in repo: fetch --depth 1 origin v1.0.0: fatal: couldn't find remote ref v1.0.0"
        ),
        "install_source_fetch_failed"
    );
    assert_eq!(
        map_clone_error_detail_code_for_test(
            "install",
            "__preen_kind:internal__git command failed in repo: checkout --detach FETCH_HEAD: error: pathspec 'FETCH_HEAD' did not match any file(s) known to git"
        ),
        "install_source_checkout_failed"
    );
    assert_eq!(
        map_clone_error_detail_code_for_test(
            "preflight",
            "__preen_kind:internal__git rev-parse failed"
        ),
        "preflight_source_git_resolve_failed"
    );
}

#[test]
fn map_clone_error_detail_code_falls_back_for_unknown_scope_or_message() {
    assert_eq!(
        map_clone_error_detail_code_for_test(
            "install",
            "__preen_kind:internal__unexpected failure"
        ),
        "install_clone_failed"
    );
    assert_eq!(
        map_clone_error_detail_code_for_test(
            "preflight",
            "__preen_kind:internal__unexpected failure"
        ),
        "preflight_clone_failed"
    );
    assert_eq!(
        map_clone_error_detail_code_for_test(
            "unknown",
            "__preen_kind:internal__unexpected failure"
        ),
        "install_clone_failed"
    );
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

    let (code, _, priority) = hint_for_detail_code_for_test("install_action_api_unsupported");
    assert_eq!(code, "action_api_unsupported");
    assert_eq!(priority, 1);

    let (code, action, priority) = hint_for_detail_code_for_test("verify_action_type_unsupported");
    assert_eq!(code, "action_type_unsupported");
    assert_eq!(action, "upgrade_plugin_or_runtime_supported_action_types");
    assert_eq!(priority, 1);

    let (code, _, priority) = hint_for_detail_code_for_test("install_source_resolve_failed");
    assert_eq!(code, "registry_or_source_resolve_failed");
    assert_eq!(priority, 2);

    let (code, action, priority) =
        hint_for_detail_code_for_test("registry_signature_verify_failed");
    assert_eq!(code, "trust_or_signature_failed");
    assert_eq!(action, "check_sigstore_identity_and_trust_policy");
    assert_eq!(priority, 0);

    let (code, action, priority) = hint_for_detail_code_for_test("registry_source_fetch_failed");
    assert_eq!(code, "registry_or_source_resolve_failed");
    assert_eq!(action, "refresh_registry_or_validate_pack_id_and_version");
    assert_eq!(priority, 2);
}

#[test]
fn run_typed_install_local_git_verification_failure_has_install_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{}", repo.display(), rev);
        let cli = Cli::try_parse_from(["preen", "plugin", "install", &spec]).unwrap();
        let err = run_typed_with_verifier_for_test(cli, &AlwaysFailVerifier).unwrap_err();
        assert_eq!(err.kind, CliErrorKind::Verification);
        assert_eq!(
            err.detail_code.as_deref(),
            Some("install_signature_or_trust_failed")
        );
    });
}

#[test]
fn install_plugin_in_dir_local_git_old_tag_resolves_to_tag_commit() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo_with_old_tag(&repo);
        let expected_commit = git_rev_parse(&repo, &rev);

        let lockfile = tmp.path().join("preen-plugins.lock");
        let install_dir = tmp.path().join("installed-plugins");
        let spec = format!("file://{}@{}", repo.display(), rev);

        let locked =
            install_plugin_in_dir_for_test(&spec, Some(&lockfile), &install_dir, &AlwaysOkVerifier)
                .unwrap();
        assert_eq!(
            locked.resolved_rev.as_deref(),
            Some(expected_commit.as_str())
        );

        let checked_out = git_rev_parse(&install_dir.join("test.pack"), "HEAD");
        assert_eq!(checked_out, expected_commit);

        let lock = load_lockfile_at(&lockfile).unwrap();
        assert_eq!(lock.plugins.len(), 1);
        assert_eq!(
            lock.plugins[0].resolved_rev.as_deref(),
            Some(expected_commit.as_str())
        );
    });
}

#[test]
fn run_typed_install_registry_source_resolve_failure_has_install_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let cli =
            Cli::try_parse_from(["preen", "plugin", "install", "preen-rs.homebrew@1.0.0"]).unwrap();
        let err = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap_err();
        assert_eq!(
            err.detail_code.as_deref(),
            Some("install_source_resolve_failed")
        );
    });
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
fn verify_command_uses_verify_prefixed_detail_code_on_signature_failure() {
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

        let verify = Cli::try_parse_from([
            "preen",
            "plugin",
            "verify",
            "test.pack",
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--json",
        ])
        .unwrap();
        let err =
            run_typed_with_verifier_for_test(verify.clone(), &AlwaysFailVerifier).unwrap_err();
        assert_eq!(err.kind, CliErrorKind::Verification);
        assert_eq!(
            err.detail_code.as_deref(),
            Some("verify_signature_or_trust_failed")
        );

        let parsed: Value = serde_json::from_str(&verify.format_error(&err)).unwrap();
        assert_eq!(
            parsed["data"]["detail_code"].as_str(),
            Some("verify_signature_or_trust_failed")
        );
    });
}

#[test]
fn install_local_git_old_tag_sets_resolved_rev_in_lockfile() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let tag = init_preflight_git_repo_with_old_tag(&repo);
        let expected_commit = git_rev_parse(&repo, &tag);
        let lockfile = tmp.path().join("plugins.lock");
        let spec = format!("file://{}@{}", repo.to_string_lossy(), tag);

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

        let lock = load_lockfile_at(&lockfile).unwrap();
        assert_eq!(lock.plugins.len(), 1);
        assert_eq!(lock.plugins[0].rev, "v0.0.1");
        assert_eq!(
            lock.plugins[0].resolved_rev.as_deref(),
            Some(expected_commit.as_str())
        );

        let checked_out = git_rev_parse(
            &plugin_install_base_dir_from_env().join("test.pack"),
            "HEAD",
        );
        assert_eq!(checked_out, expected_commit);
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
fn update_local_git_old_tag_repairs_tampered_resolved_rev_to_pinned_commit() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let tag = init_preflight_git_repo_with_old_tag(&repo);
        let tag_commit = git_rev_parse(&repo, &tag);
        let branch_head = git_rev_parse(&repo, "HEAD");
        assert_ne!(tag_commit, branch_head);

        let lockfile = tmp.path().join("plugins.lock");
        let spec = format!("file://{}@{}", repo.to_string_lossy(), tag);

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
        lock.plugins[0].resolved_rev = Some(branch_head.clone());
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
        assert_eq!(repaired.plugins.len(), 1);
        assert_eq!(repaired.plugins[0].rev, "v0.0.1");
        assert_eq!(
            repaired.plugins[0].resolved_rev.as_deref(),
            Some(tag_commit.as_str())
        );

        let checked_out = git_rev_parse(
            &plugin_install_base_dir_from_env().join("test.pack"),
            "HEAD",
        );
        assert_eq!(checked_out, tag_commit);
    });
}

#[test]
fn install_rolls_back_new_plugin_dir_when_lockfile_save_fails() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{rev}", repo.to_string_lossy());
        let install_dir = tmp.path().join("installed");
        let blocked_parent = tmp.path().join("blocked-parent-file");
        fs::write(&blocked_parent, "blocked").unwrap();
        let lockfile = blocked_parent.join("plugins.lock");

        let err =
            install_plugin_in_dir_for_test(&spec, Some(&lockfile), &install_dir, &AlwaysOkVerifier)
                .unwrap_err();
        let tagged = CliError::from(err);
        assert_eq!(tagged.kind, CliErrorKind::Io);
        assert_eq!(
            tagged.detail_code.as_deref(),
            Some("install_lockfile_save_failed")
        );
        assert!(
            !install_dir.join("test.pack").exists(),
            "new plugin dir must be rolled back on lockfile save failure"
        );
    });
}

#[test]
fn install_restores_existing_plugin_dir_when_lockfile_save_fails() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{rev}", repo.to_string_lossy());
        let install_dir = tmp.path().join("installed");
        let existing_pack_dir = install_dir.join("test.pack");
        fs::create_dir_all(&existing_pack_dir).unwrap();
        let sentinel = existing_pack_dir.join("sentinel.txt");
        fs::write(&sentinel, "keep-me").unwrap();

        let blocked_parent = tmp.path().join("blocked-parent-file");
        fs::write(&blocked_parent, "blocked").unwrap();
        let lockfile = blocked_parent.join("plugins.lock");

        let err =
            install_plugin_in_dir_for_test(&spec, Some(&lockfile), &install_dir, &AlwaysOkVerifier)
                .unwrap_err();
        let tagged = CliError::from(err);
        assert_eq!(tagged.kind, CliErrorKind::Io);
        assert_eq!(
            tagged.detail_code.as_deref(),
            Some("install_lockfile_save_failed")
        );
        assert!(sentinel.exists(), "existing plugin dir must be restored");
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep-me");
    });
}

#[test]
fn update_plugin_registry_source_resolves_latest_version() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let old_tag = init_preflight_git_repo_with_old_tag(&repo);
        let old_rev = git_rev_parse(&repo, &old_tag);
        let manifest_path = repo.join("manifest.toml");
        let manifest = fs::read_to_string(&manifest_path).unwrap();
        let updated_manifest = manifest.replacen("version = \"0.1.0\"", "version = \"0.2.0\"", 1);
        fs::write(&manifest_path, updated_manifest).unwrap();
        run_git_in(&repo, &["add", "manifest.toml"]);
        run_git_in_no_sign(&repo, &["commit", "-m", "bump manifest version"]);
        let latest_rev = git_rev_parse(&repo, "HEAD");
        let index = tmp.path().join("registry-index.toml");
        let sig = tmp.path().join("registry-index.toml.sig");
        let cache = tmp.path().join("cache-index.toml");
        let lockfile = tmp.path().join("plugins.lock");
        let install_dir = tmp.path().join("installed");
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let repo_url = file_source_url(&repo);
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
repo_url = "{repo_url}"
latest_version = "0.2.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{old_rev}"
  [[entries.versions]]
  version = "0.2.0"
  rev = "{latest_rev}"
"#,
            ),
        )
        .unwrap();
        write_registry_signature(&sig);
        apply_registry_freshness_env(&cache, "warn", None);
        run_registry_update_cli_with_verifier(&index, &sig, &AlwaysOkVerifier).unwrap();
        install_plugin_in_dir_for_test(
            "test.pack@0.1.0",
            Some(&lockfile),
            &install_dir,
            &AlwaysOkVerifier,
        )
        .unwrap();

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

        let updated = load_lockfile_at(&lockfile).unwrap();
        assert_eq!(updated.plugins.len(), 1);
        assert_eq!(updated.plugins[0].source, "registry");
        assert_eq!(updated.plugins[0].version, "0.2.0");
        assert_eq!(updated.plugins[0].rev, latest_rev);
    });
}

#[test]
fn update_plugin_registry_source_rejects_manifest_version_mismatch() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let old_tag = init_preflight_git_repo_with_old_tag(&repo);
        let old_rev = git_rev_parse(&repo, &old_tag);
        let latest_rev = git_rev_parse(&repo, "HEAD");
        let index = tmp.path().join("registry-index.toml");
        let sig = tmp.path().join("registry-index.toml.sig");
        let cache = tmp.path().join("cache-index.toml");
        let lockfile = tmp.path().join("plugins.lock");
        let install_dir = tmp.path().join("installed");
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let repo_url = file_source_url(&repo);
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
repo_url = "{repo_url}"
latest_version = "0.2.0"
  [[entries.versions]]
  version = "0.1.0"
  rev = "{old_rev}"
  [[entries.versions]]
  version = "0.2.0"
  rev = "{latest_rev}"
"#,
            ),
        )
        .unwrap();
        write_registry_signature(&sig);
        apply_registry_freshness_env(&cache, "warn", None);
        run_registry_update_cli_with_verifier(&index, &sig, &AlwaysOkVerifier).unwrap();
        install_plugin_in_dir_for_test(
            "test.pack@0.1.0",
            Some(&lockfile),
            &install_dir,
            &AlwaysOkVerifier,
        )
        .unwrap();

        let update = Cli::try_parse_from([
            "preen",
            "plugin",
            "update",
            "test.pack",
            "--lockfile",
            lockfile.to_str().unwrap(),
        ])
        .unwrap();
        let err = run_typed_with_verifier_for_test(update, &AlwaysOkVerifier).unwrap_err();
        assert_eq!(err.kind, CliErrorKind::Validation);
        assert_eq!(err.detail_code.as_deref(), Some("install_pack_load_failed"));
        assert!(err.message.contains("registry version mismatch"));
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
fn plugin_remove_rejects_invalid_pack_id() {
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
        "remove",
        "../evil",
        "--lockfile",
        lockfile.to_str().unwrap(),
    ])
    .unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert!(err.message.contains("invalid pack_id"));
}

#[test]
fn run_typed_install_invalid_lockfile_maps_install_lockfile_load_failed() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{rev}", repo.to_string_lossy());
        let lockfile = tmp.path().join("plugins.lock");
        fs::write(&lockfile, "not valid toml").unwrap();

        let cli = Cli::try_parse_from([
            "preen",
            "plugin",
            "install",
            &spec,
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--json",
        ])
        .unwrap();
        let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysOkVerifier).unwrap_err();
        assert_eq!(err.kind, CliErrorKind::Validation);
        assert_eq!(
            err.detail_code.as_deref(),
            Some("install_lockfile_load_failed")
        );

        let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
        assert_eq!(parsed["kind"].as_str(), Some("error"));
        assert_eq!(parsed["data"]["error_kind"].as_str(), Some("validation"));
        assert_eq!(
            parsed["data"]["detail_code"].as_str(),
            Some("install_lockfile_load_failed")
        );
        assert_eq!(
            parsed["data"]["hint_code"].as_str(),
            Some("lockfile_io_failed")
        );
    });
}

#[test]
fn run_typed_install_lockfile_directory_parent_maps_install_lockfile_save_failed() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{rev}", repo.to_string_lossy());

        let blocked_parent = tmp.path().join("blocked-parent");
        fs::write(&blocked_parent, "not a directory").unwrap();
        let lockfile = blocked_parent.join("plugins.lock");

        let cli = Cli::try_parse_from([
            "preen",
            "plugin",
            "install",
            &spec,
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--json",
        ])
        .unwrap();
        let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysOkVerifier).unwrap_err();
        assert_eq!(err.kind, CliErrorKind::Io);
        assert_eq!(
            err.detail_code.as_deref(),
            Some("install_lockfile_save_failed")
        );

        let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
        assert_eq!(parsed["kind"].as_str(), Some("error"));
        assert_eq!(parsed["data"]["error_kind"].as_str(), Some("io"));
        assert_eq!(
            parsed["data"]["detail_code"].as_str(),
            Some("install_lockfile_save_failed")
        );
        assert_eq!(
            parsed["data"]["hint_code"].as_str(),
            Some("lockfile_io_failed")
        );
    });
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
    clear_registry_trust_env();
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
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_identity_invalid")
    );
    assert!(err.message.contains("registry identity must equal"));
}

#[test]
fn run_typed_registry_update_rejects_invalid_issuer() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_registry_trust_env();
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
    assert_eq!(err.detail_code.as_deref(), Some("registry_issuer_invalid"));
    assert!(err.message.contains("registry issuer must be"));
}

#[test]
fn run_typed_registry_update_missing_source_has_detail_code_and_hint() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_registry_trust_env();
    let cli = Cli::try_parse_from(["preen", "plugin", "registry-update"]).unwrap();
    let err = run_typed(cli.clone()).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(err.detail_code.as_deref(), Some("registry_source_missing"));

    let out = cli.format_error(&err);
    assert!(out.contains("detail_code=registry_source_missing"));
    assert!(out.contains("hint_code=invalid_spec"));
}

#[test]
fn registry_source_detail_code_uses_remote_for_http_and_local_for_file() {
    let code = registry_source_detail_code_for_test(
        "https://example.com/registry-index.toml",
        "registry_source_fetch_failed",
        "registry_source_read_failed",
    );
    assert_eq!(code, "registry_source_fetch_failed");

    let code = registry_source_detail_code_for_test(
        "file:///tmp/registry-index.toml",
        "registry_source_fetch_failed",
        "registry_source_read_failed",
    );
    assert_eq!(code, "registry_source_read_failed");
}

#[test]
fn registry_fetch_404_message_can_be_mapped_to_specific_detail_code() {
    let encoded = map_error_with_detail_code_for_test(
        "__preen_kind:network__registry fetch failed with status 404 Not Found",
        CliErrorKind::Network,
        "registry_source_fetch_failed",
    );
    let err = CliError::from(encoded);
    assert_eq!(err.kind, CliErrorKind::Network);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_source_fetch_failed")
    );
    assert!(err.message.contains("status 404"));
}

#[test]
fn registry_signature_fetch_404_message_can_be_mapped_to_specific_detail_code() {
    let encoded = map_error_with_detail_code_for_test(
        "__preen_kind:network__registry fetch failed with status 404 Not Found",
        CliErrorKind::Network,
        "registry_signature_fetch_failed",
    );
    let err = CliError::from(encoded);
    assert_eq!(err.kind, CliErrorKind::Network);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_signature_fetch_failed")
    );
    assert!(err.message.contains("status 404"));
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
    write_homebrew_registry_index(&index, &now);
    write_registry_signature(&sig);

    apply_registry_freshness_env(&cache, "warn", None);
    let cli = make_registry_update_cli(&index, &sig);
    run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap();

    let written = fs::read_to_string(&cache).unwrap();
    assert!(written.contains("pack_id = \"preen-rs.homebrew\""));
}

#[test]
fn run_typed_registry_update_then_preflight_registry_spec_success() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    let preflight_cli =
        Cli::try_parse_from(["preen", "plugin", "preflight", "test.pack@0.1.0"]).unwrap();
    let result = run_typed_with_verifier_for_test(preflight_cli, &AlwaysOkVerifier);
    assert!(result.is_ok());
}

#[test]
fn registry_update_then_install_and_verify_registry_spec_success() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    let locked = fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    assert_eq!(locked.pack_id, "test.pack");
    assert_eq!(locked.version, "0.1.0");
    assert!(
        fixture
            .install_dir
            .join("test.pack")
            .join("manifest.toml")
            .exists()
    );

    let lock = load_lockfile_at(&fixture.lockfile).unwrap();
    assert_eq!(lock.plugins.len(), 1);
    assert_eq!(lock.plugins[0].pack_id, "test.pack");
    assert_eq!(lock.plugins[0].version, "0.1.0");

    let verify_text = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
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
        Some(&fixture.lockfile),
        &fixture.install_dir,
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
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let manifest_path = fixture.install_dir.join("test.pack").join("manifest.toml");
    let mut manifest = fs::read_to_string(&manifest_path).unwrap();
    manifest.push_str("\n# tampered\n");
    fs::write(&manifest_path, manifest).unwrap();

    let err = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
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
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let err = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
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
fn registry_update_install_then_verify_missing_manifest_maps_verify_pack_load_failed() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    fs::remove_file(fixture.install_dir.join("test.pack").join("manifest.toml")).unwrap();

    let raw = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap_err();
    let err = CliError::from(raw);
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(err.detail_code.as_deref(), Some("verify_pack_load_failed"));

    let cli = Cli::try_parse_from(["preen", "plugin", "verify", "test.pack", "--json"]).unwrap();
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(parsed["kind"].as_str(), Some("error"));
    assert_eq!(parsed["data"]["error_kind"].as_str(), Some("validation"));
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("verify_pack_load_failed")
    );
    assert_eq!(
        parsed["data"]["hint_code"].as_str(),
        Some("pack_load_failed")
    );
}

#[test]
fn registry_update_install_then_verify_fails_on_version_drift_with_stable_hint() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let mut lock = load_lockfile_at(&fixture.lockfile).unwrap();
    lock.plugins[0].version = "0.1.1".to_string();
    save_lockfile_at(&fixture.lockfile, &lock).unwrap();

    let raw = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap_err();
    assert_verify_error_has_detail_and_hint(
        raw,
        CliErrorKind::Verification,
        "verify_version_drift",
        "version_drift",
    );
}

#[test]
fn registry_update_install_then_verify_fails_on_resolved_rev_drift_with_stable_hint() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let mut lock = load_lockfile_at(&fixture.lockfile).unwrap();
    lock.plugins[0].resolved_rev = Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string());
    save_lockfile_at(&fixture.lockfile, &lock).unwrap();

    let raw = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap_err();
    assert_verify_error_has_detail_and_hint(
        raw,
        CliErrorKind::Verification,
        "verify_resolved_rev_drift",
        "resolved_rev_drift",
    );
}

#[test]
fn registry_update_install_then_verify_fails_on_signature_hash_drift_with_stable_hint() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let signature_path = fixture.install_dir.join("test.pack").join("manifest.sig");
    let mut signature = fs::read_to_string(&signature_path).unwrap();
    signature.push_str("\n# tampered\n");
    fs::write(&signature_path, signature).unwrap();

    let raw = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap_err();
    assert_verify_error_has_detail_and_hint(
        raw,
        CliErrorKind::Verification,
        "verify_signature_hash_drift",
        "signature_hash_drift",
    );
}

#[test]
fn registry_update_install_then_verify_fails_on_action_api_with_stable_hint() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let manifest_path = fixture.install_dir.join("test.pack").join("manifest.toml");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    let mutated = manifest.replacen("action_api = 1", "action_api = 2", 1);
    assert_ne!(manifest, mutated);
    fs::write(&manifest_path, mutated).unwrap();

    let raw = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap_err();
    assert_verify_error_has_detail_and_hint(
        raw,
        CliErrorKind::Validation,
        "verify_action_api_unsupported",
        "action_api_unsupported",
    );
}

#[test]
fn registry_update_install_then_verify_fails_on_unsupported_action_type_with_stable_hint() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();
    set_installed_rule_action_type(
        &fixture.install_dir,
        "{ Other = \"CustomUnsupportedAction\" }",
    );

    let raw = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap_err();
    assert_verify_error_has_detail_and_hint(
        raw,
        CliErrorKind::Validation,
        "verify_action_type_unsupported",
        "action_type_unsupported",
    );
}

#[test]
fn registry_update_install_then_verify_fails_on_os_target_with_stable_hint() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let manifest_path = fixture.install_dir.join("test.pack").join("manifest.toml");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    let replacement = if std::env::consts::OS == "macos" {
        "os_targets = [\"Linux\"]"
    } else {
        "os_targets = [\"Macos\"]"
    };
    let mutated = manifest.replacen("os_targets = [\"Linux\", \"Macos\"]", replacement, 1);
    assert_ne!(manifest, mutated);
    fs::write(&manifest_path, mutated).unwrap();

    let raw = plugin_verify_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap_err();
    assert_verify_error_has_detail_and_hint(
        raw,
        CliErrorKind::Validation,
        "verify_os_target_failed",
        "os_target_failed",
    );
}

#[test]
fn registry_update_install_then_test_detects_manifest_tamper() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let manifest_path = fixture.install_dir.join("test.pack").join("manifest.toml");
    let mut manifest = fs::read_to_string(&manifest_path).unwrap();
    manifest.push_str("\n# tampered\n");
    fs::write(&manifest_path, manifest).unwrap();

    let text = plugin_test_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
        false,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap();
    assert!(text.contains("summary: kind=test pack_id=test.pack overall_passed=false"));
    assert!(text.contains("drift: field=manifest_hash"));

    let json = plugin_test_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
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
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let signature_path = fixture.install_dir.join("test.pack").join("manifest.sig");
    let mut signature = fs::read_to_string(&signature_path).unwrap();
    signature.push_str("\n# tampered\n");
    fs::write(&signature_path, signature).unwrap();

    let json = plugin_test_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
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
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let mut lock = load_lockfile_at(&fixture.lockfile).unwrap();
    lock.plugins[0].resolved_rev = Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string());
    save_lockfile_at(&fixture.lockfile, &lock).unwrap();

    let text = plugin_test_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
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
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let mut lock = load_lockfile_at(&fixture.lockfile).unwrap();
    lock.plugins[0].version = "0.1.1".to_string();
    save_lockfile_at(&fixture.lockfile, &lock).unwrap();

    let json = plugin_test_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
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
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let json = plugin_test_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
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
    assert!(parsed["data"]["trust_verified"].as_bool().unwrap());
    assert_eq!(
        check_passed_from_json(&parsed["data"], "signature_verified"),
        Some(false)
    );
    assert_eq!(
        check_passed_from_json(&parsed["data"], "trust_verified"),
        Some(true)
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
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();

    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let manifest_path = fixture.install_dir.join("test.pack").join("manifest.toml");
    let mut manifest = fs::read_to_string(&manifest_path).unwrap();
    manifest.push_str("\n# tampered\n");
    fs::write(&manifest_path, manifest).unwrap();

    let json = plugin_test_all_for_test(
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        false,
        &AlwaysOkVerifier,
    )
    .unwrap();
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
fn registry_update_install_then_test_all_action_api_drift_has_specific_failure_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();

    let manifest_path = fixture.install_dir.join("test.pack").join("manifest.toml");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    let mutated = manifest.replacen("action_api = 1", "action_api = 2", 1);
    assert_ne!(manifest, mutated);
    fs::write(&manifest_path, mutated).unwrap();

    let text = plugin_test_all_for_test(
        Some(&fixture.lockfile),
        &fixture.install_dir,
        false,
        false,
        &AlwaysOkVerifier,
    )
    .unwrap();
    assert!(text.contains("hint_code=action_api_unsupported"));

    let json = plugin_test_all_for_test(
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        false,
        &AlwaysOkVerifier,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kind"].as_str(), Some("plugin.test_all"));
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    let failures = parsed["data"]["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["pack_id"].as_str(), Some("test.pack"));
    assert_eq!(failures[0]["error_kind"].as_str(), Some("verification"));
    assert_eq!(
        failures[0]["detail_code"].as_str(),
        Some("test_action_api_unsupported")
    );
}

#[test]
fn registry_update_install_then_test_marks_unsupported_action_type_as_action_api_failure() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();
    set_installed_rule_action_type(
        &fixture.install_dir,
        "{ Other = \"CustomUnsupportedAction\" }",
    );

    let json = plugin_test_for_test(
        "test.pack",
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        "en-US",
        &AlwaysOkVerifier,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("test_action_type_unsupported")
    );
    assert_eq!(
        check_passed_from_json(&parsed["data"], "action_api_verified"),
        Some(false)
    );
}

#[test]
fn registry_update_install_then_test_all_unsupported_action_type_has_specific_failure_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    let fixture = RegistryRepoFixture::new();
    fixture.prepare_registry(&AlwaysOkVerifier).unwrap();
    fixture.install_test_pack(&AlwaysOkVerifier).unwrap();
    set_installed_rule_action_type(
        &fixture.install_dir,
        "{ Other = \"CustomUnsupportedAction\" }",
    );

    let json = plugin_test_all_for_test(
        Some(&fixture.lockfile),
        &fixture.install_dir,
        true,
        false,
        &AlwaysOkVerifier,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kind"].as_str(), Some("plugin.test_all"));
    assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
    let failures = parsed["data"]["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["pack_id"].as_str(), Some("test.pack"));
    assert_eq!(
        failures[0]["detail_code"].as_str(),
        Some("test_action_type_unsupported")
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
    write_homebrew_registry_index(&index, &now);
    write_registry_signature(&sig);

    apply_registry_freshness_env(&cache, "warn", None);

    let cli = make_registry_update_cli(&index, &sig);
    let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysFailVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Verification);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_signature_verify_failed")
    );
    assert!(
        err.message
            .contains("registry signature verification failed")
    );
    let text = cli.format_error(&err);
    assert!(text.contains("hint_code=trust_or_signature_failed"));
    assert!(!cache.exists());
}

#[test]
fn run_typed_registry_update_local_source_invalid_bundle_contract_has_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    write_homebrew_registry_index(&index, &now);
    fs::write(&sig, "not-json").unwrap();

    apply_registry_freshness_env(&cache, "warn", None);

    let cli = make_registry_update_cli(&index, &sig);
    let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Verification);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_signature_verify_failed")
    );
    assert!(err.message.contains("invalid sigstore bundle json"));
    let text = cli.format_error(&err);
    assert!(text.contains("hint_code=trust_or_signature_failed"));
    assert!(!cache.exists());
}

#[test]
fn run_typed_registry_update_local_source_index_parse_failure_has_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");

    fs::write(&index, "this is not valid toml").unwrap();
    write_registry_signature(&sig);
    apply_registry_freshness_env(&cache, "warn", None);

    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &file_source_url(&index),
        "--signature-source",
        &file_source_url(&sig),
        "--identity",
        REGISTRY_SIGN_IDENTITY,
        "--issuer",
        REGISTRY_SIGN_ISSUER,
        "--json",
    ])
    .unwrap();
    let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_index_parse_failed")
    );
    assert!(!cache.exists());

    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(parsed["kind"].as_str(), Some("error"));
    assert_eq!(parsed["data"]["error_kind"].as_str(), Some("validation"));
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("registry_index_parse_failed")
    );
    assert_eq!(
        parsed["data"]["hint_code"].as_str(),
        Some("pack_load_failed")
    );
}

#[test]
fn run_typed_registry_update_local_source_signature_read_failure_has_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("registry-index.toml");
    let missing_sig = tmp.path().join("missing-registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    write_homebrew_registry_index(&index, &now);
    apply_registry_freshness_env(&cache, "warn", None);

    let cli = Cli::try_parse_from([
        "preen",
        "plugin",
        "registry-update",
        "--source",
        &file_source_url(&index),
        "--signature-source",
        &file_source_url(&missing_sig),
        "--identity",
        REGISTRY_SIGN_IDENTITY,
        "--issuer",
        REGISTRY_SIGN_ISSUER,
        "--json",
    ])
    .unwrap();
    let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Io);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_signature_read_failed")
    );
    assert!(!cache.exists());

    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(parsed["kind"].as_str(), Some("error"));
    assert_eq!(parsed["data"]["error_kind"].as_str(), Some("io"));
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("registry_signature_read_failed")
    );
    assert_eq!(
        parsed["data"]["hint_code"].as_str(),
        Some("registry_or_source_resolve_failed")
    );
}

#[test]
fn run_typed_registry_update_local_source_missing_cert_failure_has_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    write_homebrew_registry_index(&index, &now);
    write_registry_signature(&sig);

    apply_registry_freshness_env(&cache, "warn", None);

    let cli = make_registry_update_cli(&index, &sig);
    let err = run_typed_with_verifier_for_test(cli, &MissingCertVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Verification);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_signature_verify_failed")
    );
    assert!(!cache.exists());
}

#[test]
fn run_typed_registry_update_local_source_identity_mismatch_has_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("registry-index.toml");
    let sig = tmp.path().join("registry-index.toml.sig");
    let cache = tmp.path().join("cache-index.toml");

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    write_homebrew_registry_index(&index, &now);
    write_registry_signature(&sig);

    apply_registry_freshness_env(&cache, "warn", None);

    let cli = make_registry_update_cli(&index, &sig);
    let err = run_typed_with_verifier_for_test(cli, &UntrustedIdentityVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Trust);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_signature_verify_failed")
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
    write_homebrew_registry_index(&index, &old);
    write_registry_signature(&sig);

    apply_registry_freshness_env(&cache, "error", Some("30"));

    let cli = make_registry_update_cli(&index, &sig);
    let err = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_freshness_failed")
    );
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
    write_homebrew_registry_index(&index, &old);
    write_registry_signature(&sig);

    apply_registry_freshness_env(&cache, "warn", Some("30"));

    let cli = make_registry_update_cli_with_strict_mode(&index, &sig, true);
    let err = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("registry_freshness_failed")
    );
    assert!(err.message.contains("stale"));
    assert!(!cache.exists());
}

#[test]
fn run_typed_preflight_local_git_success_with_injected_verifier() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{}", repo.display(), rev);
        let cli = Cli::try_parse_from(["preen", "plugin", "preflight", &spec]).unwrap();
        let result = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier);
        assert!(result.is_ok());
    });
}

#[test]
fn run_typed_preflight_local_git_rejects_unsupported_action_type() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("plugin-repo");
    let _ = init_preflight_git_repo(&repo);
    let rev = set_repo_rule_action_type(&repo, "{ Other = \"CustomUnsupportedAction\" }");
    let spec = format!("file://{}@{}", repo.display(), rev);
    let cli = Cli::try_parse_from(["preen", "plugin", "preflight", &spec, "--json"]).unwrap();
    let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysOkVerifier).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Validation);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("preflight_action_type_unsupported")
    );
    assert!(err.message.contains("unsupported action types"));
    let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
    assert_eq!(parsed["kind"].as_str(), Some("error"));
    assert_eq!(parsed["data"]["error_kind"].as_str(), Some("validation"));
    assert_eq!(
        parsed["data"]["detail_code"].as_str(),
        Some("preflight_action_type_unsupported")
    );
    assert_eq!(
        parsed["data"]["hint_code"].as_str(),
        Some("action_type_unsupported")
    );
}

#[test]
fn run_typed_preflight_local_git_verification_failure() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{}", repo.display(), rev);
        let cli = Cli::try_parse_from(["preen", "plugin", "preflight", &spec, "--json"]).unwrap();
        let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysFailVerifier).unwrap_err();
        assert_eq!(err.kind, CliErrorKind::Verification);
        assert_eq!(
            err.detail_code.as_deref(),
            Some("preflight_signature_or_trust_failed")
        );
        let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
        assert_eq!(parsed["kind"].as_str(), Some("error"));
        assert_eq!(parsed["data"]["error_kind"].as_str(), Some("verification"));
        assert_eq!(
            parsed["data"]["detail_code"].as_str(),
            Some("preflight_signature_or_trust_failed")
        );
        assert_eq!(
            parsed["data"]["hint_code"].as_str(),
            Some("trust_or_signature_failed")
        );
    });
}

#[test]
fn run_typed_preflight_local_git_old_tag_success_with_injected_verifier() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo_with_old_tag(&repo);
        let spec = format!("file://{}@{}", repo.display(), rev);
        let cli = Cli::try_parse_from(["preen", "plugin", "preflight", &spec]).unwrap();
        let result = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier);
        assert!(result.is_ok());
    });
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
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
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
                    trusted_identity: "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0".to_string(),
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

        let json =
            plugin_preflight_all_for_test(Some(&lockfile), true, false, &AlwaysOkVerifier).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["kind"].as_str().unwrap(), "plugin.preflight_all");
        assert!(!parsed["data"]["overall_passed"].as_bool().unwrap());
        assert_eq!(parsed["data"]["failed"].as_u64(), Some(1));
        let failures = parsed["data"]["failures"].as_array().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures[0]["detail_code"].as_str(),
            Some("preflight_source_clone_failed")
        );
    });
}

#[test]
fn preflight_all_json_includes_signature_or_trust_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
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
                trusted_identity: "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0".to_string(),
            }],
        };
        save_lockfile_at(&lockfile, &lock).unwrap();

        let json = plugin_preflight_all_for_test(Some(&lockfile), true, false, &AlwaysFailVerifier)
            .unwrap();
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
    });
}

#[test]
fn preflight_all_text_failure_first_and_verbose_modes() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
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
                    trusted_identity: "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0".to_string(),
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

        let text = plugin_preflight_all_for_test(Some(&lockfile), false, false, &AlwaysOkVerifier)
            .unwrap();
        assert!(text.contains("summary: kind=preflight_all"));
        assert!(text.contains("failure: spec=file:///definitely/missing/repo@deadbeef"));
        assert!(text.contains("passed_results_hidden: 1"));
        assert!(!text.contains("summary: kind=preflight overall_passed=true"));

        let verbose_text =
            plugin_preflight_all_for_test(Some(&lockfile), false, true, &AlwaysOkVerifier).unwrap();
        assert!(verbose_text.contains("summary: kind=preflight_all"));
        assert!(verbose_text.contains("summary: kind=preflight overall_passed=true"));
        assert!(!verbose_text.contains("passed_results_hidden:"));
    });
}

#[test]
fn plugin_test_all_text_failure_first_and_verbose_modes() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo(&repo);
        let install_dir = tmp.path().join("plugins");
        fs::create_dir_all(&install_dir).unwrap();
        let lockfile = tmp.path().join("preen-plugins.lock");

        let installed = install_plugin_in_dir_for_test(
            &format!("file://{}@{}", repo.display(), rev),
            Some(&lockfile),
            &install_dir,
            &AlwaysOkVerifier,
        )
        .unwrap();
        let mut lock = load_lockfile_at(&lockfile).unwrap();
        lock.plugins.push(LockedPlugin {
            pack_id: "missing.pack".to_string(),
            source: "git".to_string(),
            url: "file:///definitely/missing/repo".to_string(),
            rev: "deadbeef".to_string(),
            resolved_rev: None,
            version: "0.1.0".to_string(),
            manifest_hash: "sha256:deadbeef".to_string(),
            signature: "sha256:cafebabe".to_string(),
            trusted_identity: installed.trusted_identity,
        });
        save_lockfile_at(&lockfile, &lock).unwrap();

        let text = plugin_test_all_for_test(
            Some(&lockfile),
            &install_dir,
            false,
            false,
            &AlwaysOkVerifier,
        )
        .unwrap();
        assert!(text.contains("summary: kind=test_all"));
        assert!(text.contains("failure: pack_id=missing.pack"));
        assert!(text.contains("detail_code=none"));
        assert!(text.contains("hint_code=unknown_failure"));
        assert!(text.contains("hint_action=collect_logs_and_retry"));
        assert!(text.contains("passed_results_hidden: 1"));
        assert!(!text.contains("summary: kind=test pack_id=test.pack overall_passed=true"));

        let verbose_text = plugin_test_all_for_test(
            Some(&lockfile),
            &install_dir,
            false,
            true,
            &AlwaysOkVerifier,
        )
        .unwrap();
        assert!(verbose_text.contains("summary: kind=test_all"));
        assert!(verbose_text.contains("summary: kind=test pack_id=test.pack overall_passed=true"));
        assert!(!verbose_text.contains("passed_results_hidden:"));
    });
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
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{}", repo.display(), rev);
        let cli = Cli::try_parse_from(["preen", "plugin", "test", &spec]).unwrap();
        let result = run_typed_with_verifier_for_test(cli, &AlwaysOkVerifier);
        assert!(result.is_ok());
    });
}

#[test]
fn run_typed_test_local_git_spec_verification_failure_has_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{}", repo.display(), rev);
        let cli = Cli::try_parse_from(["preen", "plugin", "test", &spec, "--json"]).unwrap();
        let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysFailVerifier).unwrap_err();
        assert_eq!(err.kind, CliErrorKind::Verification);
        assert_eq!(
            err.detail_code.as_deref(),
            Some("preflight_signature_or_trust_failed")
        );
        let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
        assert_eq!(parsed["kind"].as_str(), Some("error"));
        assert_eq!(parsed["data"]["error_kind"].as_str(), Some("verification"));
        assert_eq!(
            parsed["data"]["detail_code"].as_str(),
            Some("preflight_signature_or_trust_failed")
        );
        assert_eq!(
            parsed["data"]["hint_code"].as_str(),
            Some("trust_or_signature_failed")
        );
    });
}

#[test]
fn run_typed_preflight_maps_invalid_trust_policy_to_prefixed_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        with_invalid_trust_allowlist(|| {
            let tmp = tempfile::tempdir().unwrap();
            let repo = tmp.path().join("plugin-repo");
            let rev = init_preflight_git_repo(&repo);
            let spec = format!("file://{}@{}", repo.display(), rev);
            let cli =
                Cli::try_parse_from(["preen", "plugin", "preflight", &spec, "--json"]).unwrap();

            let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysOkVerifier).unwrap_err();
            assert_eq!(err.kind, CliErrorKind::Validation);
            assert_eq!(
                err.detail_code.as_deref(),
                Some("preflight_trust_policy_invalid")
            );

            let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
            assert_eq!(
                parsed["data"]["detail_code"].as_str(),
                Some("preflight_trust_policy_invalid")
            );
            assert_eq!(
                parsed["data"]["hint_code"].as_str(),
                Some("trust_policy_invalid")
            );
        });
    });
}

#[test]
fn run_typed_install_maps_invalid_trust_policy_to_prefixed_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        with_invalid_trust_allowlist(|| {
            let tmp = tempfile::tempdir().unwrap();
            let repo = tmp.path().join("plugin-repo");
            let rev = init_preflight_git_repo(&repo);
            let spec = format!("file://{}@{}", repo.display(), rev);
            let lockfile = tmp.path().join("plugins.lock");
            let cli = Cli::try_parse_from([
                "preen",
                "plugin",
                "install",
                &spec,
                "--lockfile",
                lockfile.to_str().unwrap(),
                "--json",
            ])
            .unwrap();

            let err = run_typed_with_verifier_for_test(cli.clone(), &AlwaysOkVerifier).unwrap_err();
            assert_eq!(err.kind, CliErrorKind::Validation);
            assert_eq!(
                err.detail_code.as_deref(),
                Some("install_trust_policy_invalid")
            );

            let parsed: Value = serde_json::from_str(&cli.format_error(&err)).unwrap();
            assert_eq!(
                parsed["data"]["detail_code"].as_str(),
                Some("install_trust_policy_invalid")
            );
            assert_eq!(
                parsed["data"]["hint_code"].as_str(),
                Some("trust_policy_invalid")
            );
        });
    });
}

#[test]
fn run_typed_verify_maps_invalid_trust_policy_to_prefixed_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{}", repo.display(), rev);
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

        with_invalid_trust_allowlist(|| {
            let verify = Cli::try_parse_from([
                "preen",
                "plugin",
                "verify",
                "test.pack",
                "--lockfile",
                lockfile.to_str().unwrap(),
                "--json",
            ])
            .unwrap();

            let err =
                run_typed_with_verifier_for_test(verify.clone(), &AlwaysOkVerifier).unwrap_err();
            assert_eq!(err.kind, CliErrorKind::Validation);
            assert_eq!(
                err.detail_code.as_deref(),
                Some("verify_trust_policy_invalid")
            );

            let parsed: Value = serde_json::from_str(&verify.format_error(&err)).unwrap();
            assert_eq!(
                parsed["data"]["detail_code"].as_str(),
                Some("verify_trust_policy_invalid")
            );
            assert_eq!(
                parsed["data"]["hint_code"].as_str(),
                Some("trust_policy_invalid")
            );
        });
    });
}

#[test]
fn run_typed_test_maps_invalid_trust_policy_to_prefixed_detail_code() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("plugin-repo");
        let rev = init_preflight_git_repo(&repo);
        let spec = format!("file://{}@{}", repo.display(), rev);
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

        with_invalid_trust_allowlist(|| {
            let test = Cli::try_parse_from([
                "preen",
                "plugin",
                "test",
                "test.pack",
                "--lockfile",
                lockfile.to_str().unwrap(),
                "--json",
            ])
            .unwrap();

            let err =
                run_typed_with_verifier_for_test(test.clone(), &AlwaysOkVerifier).unwrap_err();
            assert_eq!(err.kind, CliErrorKind::Validation);
            assert_eq!(
                err.detail_code.as_deref(),
                Some("test_trust_policy_invalid")
            );

            let parsed: Value = serde_json::from_str(&test.format_error(&err)).unwrap();
            assert_eq!(
                parsed["data"]["detail_code"].as_str(),
                Some("test_trust_policy_invalid")
            );
            assert_eq!(
                parsed["data"]["hint_code"].as_str(),
                Some("trust_policy_invalid")
            );
        });
    });
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

fn runtime_plan_relative_path_error() -> RuntimeExecutionError {
    RuntimeExecutionError::Plan(PlanError::SafetyRejected(SafetyViolation::RelativePath {
        path: "relative/path".to_string(),
    }))
}

fn runtime_plan_blocked_path_error() -> RuntimeExecutionError {
    RuntimeExecutionError::Plan(PlanError::SafetyRejected(SafetyViolation::BlockedPath {
        path: "/usr/local".to_string(),
    }))
}

fn runtime_plan_confirmation_required_error() -> RuntimeExecutionError {
    RuntimeExecutionError::Plan(PlanError::ConfirmationRequired {
        rule_id: "rule-1".to_string(),
    })
}

fn runtime_plan_rule_not_in_manifest_error() -> RuntimeExecutionError {
    RuntimeExecutionError::Plan(PlanError::RuleNotInManifest {
        rule_id: "rule-1".to_string(),
    })
}

#[test]
fn runtime_error_detail_code_prefix_matrix_for_all_system_runtime_commands() {
    let prefixes = ["clean", "purge", "installer", "uninstall", "optimize"];
    let cases = [
        ("relative_path", runtime_plan_relative_path_error()),
        ("blocked_path", runtime_plan_blocked_path_error()),
        (
            "confirmation_required",
            runtime_plan_confirmation_required_error(),
        ),
        (
            "rule_not_in_manifest",
            runtime_plan_rule_not_in_manifest_error(),
        ),
        (
            "unsupported_action",
            RuntimeExecutionError::Execute(ActionExecutionError::UnsupportedAction {
                action: "unknown".to_string(),
            }),
        ),
        (
            "execution_failed",
            RuntimeExecutionError::Execute(ActionExecutionError::Failed {
                message: "boom".to_string(),
            }),
        ),
        (
            "command_denied",
            RuntimeExecutionError::Execute(ActionExecutionError::CommandDenied {
                command: "echo".to_string(),
            }),
        ),
        (
            "command_timeout",
            RuntimeExecutionError::Execute(ActionExecutionError::CommandTimeout {
                command: "echo".to_string(),
                timeout_sec: 5,
            }),
        ),
        (
            "command_non_zero",
            RuntimeExecutionError::Execute(ActionExecutionError::CommandNonZero {
                command: "echo".to_string(),
                code: Some(3),
            }),
        ),
    ];

    for prefix in prefixes {
        for (suffix, error) in &cases {
            let detail =
                runtime_error_detail_code_for_prefix_for_test(prefix, error.clone()).unwrap();
            assert_eq!(detail, format!("{prefix}_{suffix}"));
        }
    }
}

#[test]
fn runtime_error_detail_code_for_prefix_returns_none_for_unknown_prefix() {
    let detail = runtime_error_detail_code_for_prefix_for_test(
        "unknown",
        RuntimeExecutionError::Execute(ActionExecutionError::Failed {
            message: "boom".to_string(),
        }),
    );
    assert!(detail.is_none());
}

#[test]
fn runtime_error_detail_code_maps_delete_dir_failed_message() {
    let detail = runtime_error_detail_code_for_prefix_for_test(
        "purge",
        RuntimeExecutionError::Execute(ActionExecutionError::Failed {
            message: "delete dir failed: /tmp/demo: permission denied".to_string(),
        }),
    )
    .unwrap();
    assert_eq!(detail, "purge_delete_dir_failed");
}

#[test]
fn runtime_error_detail_code_maps_delete_file_failed_message() {
    let detail = runtime_error_detail_code_for_prefix_for_test(
        "uninstall",
        RuntimeExecutionError::Execute(ActionExecutionError::Failed {
            message: "delete file failed: /tmp/demo.txt: permission denied".to_string(),
        }),
    )
    .unwrap();
    assert_eq!(detail, "uninstall_delete_file_failed");
}

#[test]
fn runtime_error_detail_code_maps_clean_trash_failed_message() {
    let detail = runtime_error_detail_code_for_prefix_for_test(
        "clean",
        RuntimeExecutionError::Execute(ActionExecutionError::Failed {
            message: "trash failed: /tmp/demo: not supported".to_string(),
        }),
    )
    .unwrap();
    assert_eq!(detail, "clean_trash_failed");
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
rev = "381d2c7b496b0efce4ef8be8f89a74b0ba40c647"
version = "0.1.0"
manifest_hash = "sha256:deadbeef"
signature = "sha256:cafebabe"
trusted_identity = "https://github.com/Preen-rs/test"

[[plugins]]
pack_id = "dup.pack"
source = "git"
url = "https://github.com/Preen-rs/test2"
rev = "b2a4a429f1ef8bf7662274b6dc2621f2a03a369f"
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
            rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
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
            rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
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
            rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
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
        allowlist = [
          "https://github.com/Preen-rs/test/.github/workflows/release.yml@refs/tags/v0.1.0",
          "https://github.com/Preen-rs/preen-registry/.github/workflows/sign-index.yml@refs/heads/main"
        ]
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

#[test]
fn trust_policy_rejects_empty_allowlist() {
    let input = r#"
        allowlist = []
        require_signed = true
    "#;
    let err = trust_policy_from_str(input).unwrap_err();
    assert!(err.contains("allowlist must contain at least one identity"));
}

#[test]
fn trust_policy_rejects_invalid_identity_format() {
    let input = r#"
        allowlist = ["not-an-identity"]
        require_signed = true
    "#;
    let err = trust_policy_from_str(input).unwrap_err();
    assert!(err.contains("invalid sigstore identity format"));
}
