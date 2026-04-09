use std::fs;
use std::path::{Path, PathBuf};

fn workspace_path(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    for part in parts {
        path.push(part);
    }
    path
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

fn assert_sequence_in_order(text: &str, sequence: &[&str], label: &str) {
    let mut cursor = 0usize;
    for segment in sequence {
        let Some(relative) = text[cursor..].find(segment) else {
            panic!("missing expected segment in {label}: {segment}");
        };
        cursor += relative + segment.len();
    }
}

#[test]
fn release_workflow_keeps_signed_asset_contract() {
    let workflow_path = workspace_path(&[".github", "workflows", "release.yml"]);
    let workflow = read(&workflow_path);
    for expected in [
        "name: Release Binaries (Signed)",
        "push:",
        "tags:",
        "- \"v*\"",
        "x86_64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "ASSET_BASENAME=\"preen-cli-${VERSION}-${TARGET}\"",
        "${ASSET}.sha256",
        "--bundle \"${ASSET}.sigstore.json\"",
        "--bundle \"${ASSET}.sha256.sigstore.json\"",
        "IDENTITY=\"https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@refs/tags/${TAG}\"",
        "--certificate-oidc-issuer \"$ISSUER\"",
        "gh release upload \"$TAG\"",
    ] {
        assert!(
            workflow.contains(expected),
            "release workflow is missing expected segment: {expected}"
        );
    }
    assert_sequence_in_order(
        &workflow,
        &[
            "Build preen-cli",
            "Package release artifact",
            "Sign artifacts (keyless)",
            "Verify just-generated signatures",
            "Upload signed assets to release",
        ],
        "release workflow",
    );
}

#[test]
fn release_runbook_docs_match_fresh_machine_verification_flow() {
    let checklist_path = workspace_path(&["docs", "BINARY_RELEASE_CHECKLIST.md"]);
    let pipeline_path = workspace_path(&["docs", "RELEASE_PIPELINE.md"]);
    let checklist = read(&checklist_path);
    let pipeline = read(&pipeline_path);

    for expected in [
        "x86_64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "preen-cli-<version>-<target>.tar.gz",
        "preen-cli-<version>-<target>.tar.gz.sha256",
        "preen-cli-<version>-<target>.tar.gz.sigstore.json",
        "preen-cli-<version>-<target>.tar.gz.sha256.sigstore.json",
        "sha256sum -c \"${ASSET}.sha256\"",
        "cosign verify-blob",
        "--bundle \"${ASSET}.sigstore.json\"",
        "https://github.com/Preen-rs/preen/.github/workflows/release.yml@refs/tags/v${VERSION}",
        "https://token.actions.githubusercontent.com",
        "tar -xzf \"${ASSET}\"",
        "./preen-cli --help",
    ] {
        assert!(
            checklist.contains(expected),
            "binary release checklist is missing expected segment: {expected}"
        );
    }

    assert_sequence_in_order(
        &checklist,
        &[
            "## 2) Create release tag",
            "## 3) Validate GitHub workflow result",
            "## 4) Validate release assets",
            "## 5) Verify one artifact locally (required)",
            "## 6) Post-release smoke test (recommended)",
        ],
        "binary release checklist",
    );

    for expected in [
        "Trigger:",
        "push` tag matching `v*`",
        "x86_64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "*.sigstore.json",
        "https://github.com/Preen-rs/preen/.github/workflows/release.yml@refs/tags/v*",
        "https://token.actions.githubusercontent.com",
        "cosign verify-blob",
    ] {
        assert!(
            pipeline.contains(expected),
            "release pipeline doc is missing expected segment: {expected}"
        );
    }
}
