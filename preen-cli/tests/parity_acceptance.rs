use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use clap::Parser;
use preen_cli::{
    Cli, CliErrorKind, run_typed, status_watch_output_for_test, update_output_with_execute_for_test,
};
use serde::Deserialize;
use serde_json::Value;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Deserialize)]
struct CasesFile {
    schema_version: u32,
    cases: Vec<CaseRow>,
}

#[derive(Debug, Deserialize)]
struct CaseRow {
    id: String,
}

fn fixture_ids(path: &str) -> BTreeSet<String> {
    let raw = fs::read_to_string(path).expect("read cases fixture");
    let parsed: CasesFile = toml::from_str(&raw).expect("parse cases fixture");
    assert_eq!(parsed.schema_version, 1);
    parsed.cases.into_iter().map(|row| row.id).collect()
}

fn with_env_state_overrides<T>(overrides: &[(&str, Option<OsString>)], f: impl FnOnce() -> T) -> T {
    let previous: Vec<(&str, Option<OsString>)> = overrides
        .iter()
        .map(|(key, _)| (*key, std::env::var_os(key)))
        .collect();

    // SAFETY: acceptance tests mutate process env under a global lock.
    unsafe {
        for (key, value) in overrides {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
    let out = f();
    // SAFETY: acceptance tests mutate process env under a global lock.
    unsafe {
        for (key, value) in previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
    out
}

fn with_temp_user_env<T>(f: impl FnOnce() -> T) -> T {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    let xdg = temp.path().join("xdg");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&xdg).expect("create xdg");
    with_env_state_overrides(
        &[
            ("HOME", Some(home.into_os_string())),
            ("XDG_CONFIG_HOME", Some(xdg.into_os_string())),
        ],
        f,
    )
}

#[test]
fn analyze_cases_fixture_declares_expected_matrix() {
    let ids = fixture_ids("tests/fixtures/analyze/cases.toml");
    let expected = BTreeSet::from([
        "interactive_json_conflict".to_string(),
        "interactive_tty_required".to_string(),
        "selection_dedupes_nested_paths".to_string(),
    ]);
    assert_eq!(ids, expected);
}

#[test]
fn status_cases_fixture_declares_expected_matrix() {
    let ids = fixture_ids("tests/fixtures/status/cases.toml");
    let expected = BTreeSet::from([
        "force_json_env_override".to_string(),
        "watch_interval_requires_watch".to_string(),
        "watch_json_frames".to_string(),
    ]);
    assert_eq!(ids, expected);
}

#[test]
fn update_cases_fixture_declares_expected_matrix() {
    let ids = fixture_ids("tests/fixtures/update/cases.toml");
    let expected = BTreeSet::from([
        "execute_failure_detail_code".to_string(),
        "execute_skips_when_latest".to_string(),
        "execute_success".to_string(),
    ]);
    assert_eq!(ids, expected);
}

#[test]
fn parity_analyze_interactive_requires_tty() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("cache")).unwrap();
    let cli = Cli::try_parse_from([
        "preen",
        "analyze",
        temp.path().join("cache").to_string_lossy().as_ref(),
        "--interactive",
    ])
    .unwrap();
    let err = run_typed(cli).unwrap_err();
    assert_eq!(err.kind, CliErrorKind::Unsupported);
    assert_eq!(
        err.detail_code.as_deref(),
        Some("analyze_interactive_tty_required")
    );
}

#[test]
fn parity_status_watch_outputs_multiple_frames() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = status_watch_output_for_test(2).unwrap();
        assert_eq!(output["kind"].as_str(), Some("system.status.watch"));
        assert_eq!(output["data"]["ticks"].as_u64(), Some(2));
        assert_eq!(output["data"]["frames"].as_array().unwrap().len(), 2);
    });
}

#[test]
fn parity_update_execute_success_and_failure_paths() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let success = with_env_state_overrides(
            &[
                ("PREEN_UPDATE_LATEST_VERSION", Some(OsString::from("9.9.9"))),
                ("PREEN_UPDATE_INSTALL_SOURCE", Some(OsString::from("cargo"))),
                ("PREEN_UPDATE_EXECUTE_MOCK", Some(OsString::from("success"))),
            ],
            || update_output_with_execute_for_test(false, false, true).unwrap(),
        );
        assert_eq!(success["data"]["executed"].as_bool(), Some(true));

        let fail_cli = Cli::try_parse_from(["preen", "update", "--execute", "--json"]).unwrap();
        let fail = with_env_state_overrides(
            &[
                ("PREEN_UPDATE_LATEST_VERSION", Some(OsString::from("9.9.9"))),
                ("PREEN_UPDATE_INSTALL_SOURCE", Some(OsString::from("cargo"))),
                (
                    "PREEN_UPDATE_EXECUTE_MOCK",
                    Some(OsString::from("fail:boom")),
                ),
            ],
            || run_typed(fail_cli.clone()).unwrap_err(),
        );
        assert_eq!(fail.kind, CliErrorKind::Internal);
        assert_eq!(fail.detail_code.as_deref(), Some("update_execute_failed"));
        let parsed: Value = serde_json::from_str(&fail_cli.format_error(&fail)).unwrap();
        assert_eq!(
            parsed["data"]["detail_code"].as_str(),
            Some("update_execute_failed")
        );
    });
}

#[test]
fn parity_update_execute_skips_when_latest_without_force() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_temp_user_env(|| {
        let output = with_env_state_overrides(
            &[
                (
                    "PREEN_UPDATE_LATEST_VERSION",
                    Some(OsString::from(env!("CARGO_PKG_VERSION"))),
                ),
                ("PREEN_UPDATE_INSTALL_SOURCE", Some(OsString::from("cargo"))),
                ("PREEN_UPDATE_EXECUTE_MOCK", Some(OsString::from("success"))),
            ],
            || update_output_with_execute_for_test(false, false, true).unwrap(),
        );
        assert_eq!(output["data"]["executed"].as_bool(), Some(false));
        let warnings = output["data"]["warnings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(warnings.iter().any(|warning| {
            warning
                .as_str()
                .unwrap_or_default()
                .contains("already latest; skipped update execution")
        }));
    });
}

#[test]
fn parity_status_watch_interval_requires_watch_parse_error() {
    let parsed = Cli::try_parse_from(["preen", "status", "--interval-sec", "1"]);
    assert!(parsed.is_err());
}

#[test]
fn fixture_files_exist_for_parity_matrix() {
    for path in [
        "tests/fixtures/analyze/cases.toml",
        "tests/fixtures/status/cases.toml",
        "tests/fixtures/update/cases.toml",
    ] {
        assert!(Path::new(path).exists(), "missing fixture file: {path}");
    }
}
