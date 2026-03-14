use std::fs;
use std::path::{Path, PathBuf};

use preen_core::plugin_loader::load_rule_pack_from_dir;
use preen_core::plugin_registry::RegistryIndex;

fn workspace_path(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    for part in parts {
        path.push(part);
    }
    path
}

fn template_repo_path(name: &str) -> Option<PathBuf> {
    let worktree = workspace_path(&[".template-worktrees", name]);
    if worktree.exists() {
        return Some(worktree);
    }
    let legacy = workspace_path(&["templates", name]);
    if legacy.exists() {
        return Some(legacy);
    }
    None
}

fn must_exist(path: &Path) {
    assert!(path.exists(), "missing required path: {}", path.display());
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

fn collect_paths(root: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(root).unwrap_or_else(|e| panic!("failed to read dir {}: {e}", root.display()));
    for entry in entries {
        let entry =
            entry.unwrap_or_else(|e| panic!("failed to read entry in {}: {e}", root.display()));
        let path = entry.path();
        out.push(path.clone());
        if path.is_dir() {
            collect_paths(&path, out);
        }
    }
}

#[test]
fn base_template_contains_required_files() {
    let Some(root) = template_repo_path("preen-rulepack") else {
        return;
    };
    must_exist(&root.join("manifest.toml"));
    must_exist(&root.join("manifest.sig"));
    must_exist(&root.join("manifest.cert"));
    must_exist(&root.join("README.md"));
    must_exist(&root.join("CONTRIBUTING.md"));
    must_exist(&root.join("LICENSE"));
    must_exist(&root.join("rules").join("sample-cache.toml"));
    must_exist(&root.join("scripts").join("validate_pack.py"));
    must_exist(&root.join(".github").join("workflows").join("validate.yml"));
    must_exist(
        &root
            .join(".github")
            .join("workflows")
            .join("release-manual.yml"),
    );
}

#[test]
fn base_template_keeps_manifest_placeholders() {
    let Some(root) = template_repo_path("preen-rulepack") else {
        return;
    };
    let manifest_path = root.join("manifest.toml");
    let manifest = read(&manifest_path);
    for placeholder in [
        "{{PACK_ID}}",
        "{{PACK_NAME}}",
        "{{PACK_VERSION}}",
        "{{PACK_DESCRIPTION}}",
        "{{AUTHOR}}",
        "{{HOMEPAGE}}",
        "{{OS_TARGET}}",
        "{{SIGNING_IDENTITY}}",
    ] {
        assert!(
            manifest.contains(placeholder),
            "manifest template is missing placeholder {placeholder}"
        );
    }
}

#[test]
fn base_template_has_release_guardrails() {
    let Some(root) = template_repo_path("preen-rulepack") else {
        return;
    };
    let workflow_path = root
        .join(".github")
        .join("workflows")
        .join("release-manual.yml");
    let workflow = read(&workflow_path);
    for expected in [
        "workflow_dispatch:",
        "inputs:",
        "version:",
        "Validate version format",
        "Ensure tag does not exist",
        "Update manifest version and signing identity",
        "Generate manifest signature artifacts",
        "Create and push tag",
        "Create GitHub release",
        "release-manual.yml@refs/heads/main",
    ] {
        assert!(
            workflow.contains(expected),
            "release workflow is missing expected segment: {expected}"
        );
    }
}

#[test]
fn base_template_validate_workflow_targets_pr_and_main() {
    let Some(root) = template_repo_path("preen-rulepack") else {
        return;
    };
    let workflow_path = root.join(".github").join("workflows").join("validate.yml");
    let workflow = read(&workflow_path);
    assert!(workflow.contains("pull_request:"));
    assert!(workflow.contains("branches: [main]"));
    assert!(workflow.contains("python3 scripts/validate_pack.py"));
}

#[test]
fn homebrew_rulepack_template_loads_successfully() {
    let Some(pack_dir) = template_repo_path("preen-rulepack-homebrew") else {
        return;
    };
    let loaded = load_rule_pack_from_dir(&pack_dir).expect("homebrew template should load");
    assert_eq!(loaded.manifest.pack_id, "preen-rs.homebrew");
    assert_eq!(loaded.rules.len(), 2);
}

#[test]
fn homebrew_template_signing_identity_uses_release_manual_main_ref() {
    let Some(pack_dir) = template_repo_path("preen-rulepack-homebrew") else {
        return;
    };
    let loaded = load_rule_pack_from_dir(&pack_dir).expect("homebrew template should load");
    let signing = loaded
        .manifest
        .signing
        .expect("homebrew template should define [signing]");
    assert_eq!(
        signing.identity.as_deref(),
        Some(
            "https://github.com/Preen-rs/preen-rulepack-homebrew/.github/workflows/release-manual.yml@refs/heads/main"
        )
    );
}

#[test]
fn homebrew_template_has_non_placeholder_signature_artifacts() {
    let Some(root) = template_repo_path("preen-rulepack-homebrew") else {
        return;
    };
    let signature = read(&root.join("manifest.sig")).trim().to_string();
    let certificate = read(&root.join("manifest.cert")).trim().to_string();
    assert!(!signature.is_empty(), "homebrew manifest.sig is empty");
    assert!(!certificate.is_empty(), "homebrew manifest.cert is empty");
    assert_ne!(signature, "REPLACE_WITH_SIGSTORE_SIGNATURE");
    assert_ne!(certificate, "REPLACE_WITH_SIGSTORE_CERTIFICATE");
}

#[test]
fn registry_template_contains_required_files() {
    let Some(root) = template_repo_path("preen-registry") else {
        return;
    };
    must_exist(&root.join("registry-index.toml"));
    must_exist(&root.join("README.md"));
    must_exist(&root.join("LICENSE"));
    must_exist(&root.join("scripts").join("validate_index.py"));
    must_exist(&root.join("scripts").join("update_registry_entry.py"));
    must_exist(&root.join("scripts").join("registry_admin.py"));
    must_exist(
        &root
            .join(".github")
            .join("workflows")
            .join("validate-index.yml"),
    );
    must_exist(
        &root
            .join(".github")
            .join("workflows")
            .join("sign-index.yml"),
    );
}

#[test]
fn registry_template_index_parses_and_uses_release_manual_rulepack_identities() {
    let Some(root) = template_repo_path("preen-registry") else {
        return;
    };
    let index_path = root.join("registry-index.toml");
    let content = read(&index_path);
    let index = content
        .parse::<RegistryIndex>()
        .expect("registry template index should parse");
    assert!(
        !index.entries.is_empty(),
        "registry template index should not be empty"
    );
    for entry in index.entries {
        assert!(
            entry.repo_url.starts_with("https://github.com/"),
            "registry entry repo_url should be GitHub URL"
        );
        for version in entry.versions {
            if let Some(identity) = version.trusted_identity {
                assert!(
                    identity.contains("/.github/workflows/release-manual.yml@refs/heads/main"),
                    "registry trusted identity should target release-manual.yml on main"
                );
            }
        }
    }
}

#[test]
fn templates_do_not_contain_embedded_git_or_cache_artifacts() {
    let root = workspace_path(&[".template-worktrees"]);
    if !root.exists() {
        return;
    }
    let mut paths = Vec::new();
    collect_paths(&root, &mut paths);
    for path in paths {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        assert_ne!(
            name,
            ".DS_Store",
            "templates must not contain .DS_Store: {}",
            path.display()
        );
        assert_ne!(
            name,
            "__pycache__",
            "templates must not contain __pycache__: {}",
            path.display()
        );
    }
}
