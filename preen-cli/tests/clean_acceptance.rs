use std::fs;

use preen_cli::{clean_output_for_test, enforce_clean_scope_for_test};
use serde::Deserialize;

mod support;
use support::clean_fixture::{CleanEnvGuard, CleanFixture};

#[derive(Debug, Deserialize)]
struct CleanCasesFile {
    schema_version: u32,
    cases: Vec<CleanCase>,
}

#[derive(Debug, Deserialize)]
struct CleanCase {
    id: String,
}

#[test]
fn clean_cases_fixture_declares_expected_matrix() {
    let raw = fs::read_to_string("tests/fixtures/clean/cases.toml").expect("read cases fixture");
    let file: CleanCasesFile = toml::from_str(&raw).expect("parse cases fixture");
    assert_eq!(file.schema_version, 1);
    let mut ids = file.cases.into_iter().map(|c| c.id).collect::<Vec<_>>();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "apply_confirm_delete",
            "apply_requires_confirm",
            "dry_run_json_happy_path",
            "empty_selection",
            "scope_symlink_safety",
            "selection_limit",
            "strategy_trash",
        ]
    );
}

#[test]
fn clean_dry_run_json_happy_path() {
    let fixture = CleanFixture::with_files(&[("a.txt", b"123"), ("b.txt", b"1234")]);
    let _env = CleanEnvGuard::set(&fixture.root, None);

    let output = clean_output_for_test(true, false, None).expect("clean output");
    assert_eq!(output["schema_version"].as_u64(), Some(1));
    assert_eq!(output["kind"].as_str(), Some("system.clean"));
    assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    assert_eq!(output["data"]["strategy"].as_str(), Some("delete"));
    assert!(output["data"]["target_count"].as_u64().unwrap_or(0) > 0);
    assert!(
        !output["data"]["preview_paths"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        output["data"]["risk_summary"]["requires_confirmation"].as_bool(),
        Some(false)
    );
}

#[test]
fn clean_apply_requires_confirm() {
    let fixture = CleanFixture::with_files(&[("a.txt", b"123")]);
    let _env = CleanEnvGuard::set(&fixture.root, None);

    let err = clean_output_for_test(false, false, None).expect_err("confirm should be required");
    assert!(err.contains("clean_confirmation_required"));
}

#[test]
fn clean_apply_confirm_delete_strategy() {
    let fixture = CleanFixture::with_files(&[("a.txt", b"123"), ("b.txt", b"1234")]);
    let file_a = fixture.root.join("a.txt");
    let file_b = fixture.root.join("b.txt");
    let _env = CleanEnvGuard::set(&fixture.root, None);

    let output = clean_output_for_test(false, true, Some("delete")).expect("clean output");
    assert_eq!(output["kind"].as_str(), Some("system.clean"));
    assert_eq!(output["data"]["mode"].as_str(), Some("apply"));
    assert_eq!(output["data"]["strategy"].as_str(), Some("delete"));
    assert!(output["data"]["affected_items"].as_u64().unwrap_or(0) > 0);
    assert!(!file_a.exists() || !file_b.exists());
}

#[test]
fn clean_dry_run_trash_strategy() {
    let fixture = CleanFixture::with_files(&[("a.txt", b"123")]);
    let _env = CleanEnvGuard::set(&fixture.root, None);

    let output = clean_output_for_test(true, false, Some("trash")).expect("clean output");
    assert_eq!(output["kind"].as_str(), Some("system.clean"));
    assert_eq!(output["data"]["mode"].as_str(), Some("dry_run"));
    assert_eq!(output["data"]["strategy"].as_str(), Some("trash"));
    assert!(output["data"]["affected_items"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn clean_selection_limit_respected() {
    let fixture = CleanFixture::with_files(&[("a.txt", b"123"), ("b.txt", b"1234567")]);
    let file_a = fixture.root.join("a.txt");
    let file_b = fixture.root.join("b.txt");
    let _env = CleanEnvGuard::set(&fixture.root, Some("1"));

    let output = clean_output_for_test(false, true, Some("delete")).expect("clean output");
    assert_eq!(output["kind"].as_str(), Some("system.clean"));
    assert_eq!(output["data"]["target_count"].as_u64(), Some(1));
    assert_eq!(output["data"]["affected_items"].as_u64(), Some(1));
    let remaining = usize::from(file_a.exists()) + usize::from(file_b.exists());
    assert_eq!(remaining, 1);
}

#[test]
fn clean_scope_symlink_safety() {
    let fixture = CleanFixture::with_files(&[("a.txt", b"123")]);
    let link = fixture.create_symlink_to_outside("link.txt", b"outside");
    let roots = vec![fixture.root.to_string_lossy().to_string()];
    let selected = vec![link.to_string_lossy().to_string()];
    let err = enforce_clean_scope_for_test(&selected, &roots).expect_err("symlink should fail");
    assert!(err.contains("clean_symlink_not_allowed"));
}

#[test]
fn clean_empty_selection_reports_warning() {
    let fixture = CleanFixture::empty();
    let _env = CleanEnvGuard::set_with_strategy(&fixture.root, None, "trash");

    let output = clean_output_for_test(true, false, None).expect("clean output");
    assert_eq!(output["kind"].as_str(), Some("system.clean"));
    assert_eq!(output["data"]["target_count"].as_u64(), Some(0));
    assert_eq!(output["data"]["strategy"].as_str(), Some("trash"));
    let warnings = output["data"]["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].as_str(), Some("no cleanable items selected"));
}
