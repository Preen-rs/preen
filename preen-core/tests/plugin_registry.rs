use preen_core::plugin_registry::{RegistryError, RegistryIndex};

#[test]
fn registry_index_parses_and_resolves() {
    let input = r#"
schema_version = 1
generated_at = "2026-02-06T00:00:00Z"

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"

  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"

  [[entries.versions]]
  version = "1.1.0"
  rev = "def456"
"#;
    let index = input.parse::<RegistryIndex>().unwrap();
    let resolved = index.resolve("preen-rs.homebrew", Some("1.2.0")).unwrap();
    assert_eq!(
        resolved.url,
        "https://github.com/Preen-rs/preen-rulepack-homebrew"
    );
    assert_eq!(resolved.rev, "abc123");
}

#[test]
fn registry_duplicate_pack_id_fails() {
    let input = r#"
schema_version = 1

[[entries]]
pack_id = "dup"
name = "A"
description = "A"
repo_url = "https://example.com/a"
latest_version = "1.0.0"
  [[entries.versions]]
  version = "1.0.0"
  rev = "a"

[[entries]]
pack_id = "dup"
name = "B"
description = "B"
repo_url = "https://example.com/b"
latest_version = "1.0.0"
  [[entries.versions]]
  version = "1.0.0"
  rev = "b"
"#;
    let err = input.parse::<RegistryIndex>().unwrap_err();
    assert!(matches!(err, RegistryError::DuplicatePackId { .. }));
}

#[test]
fn registry_invalid_pack_id_format_fails() {
    let input = r#"
schema_version = 1

[[entries]]
pack_id = "Bad.pack"
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#;
    let err = input.parse::<RegistryIndex>().unwrap_err();
    assert!(matches!(err, RegistryError::InvalidPackId { .. }));
}

#[test]
fn registry_pack_id_path_traversal_fails() {
    let input = r#"
schema_version = 1

[[entries]]
pack_id = "../homebrew"
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#;
    let err = input.parse::<RegistryIndex>().unwrap_err();
    assert!(matches!(err, RegistryError::InvalidPackId { .. }));
}

#[test]
fn registry_version_not_found() {
    let input = r#"
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
    let index = input.parse::<RegistryIndex>().unwrap();
    let err = index
        .resolve("preen-rs.homebrew", Some("9.9.9"))
        .unwrap_err();
    assert!(matches!(err, RegistryError::VersionNotFound { .. }));
}

#[test]
fn registry_pack_not_found() {
    let input = r#"
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
    let index = input.parse::<RegistryIndex>().unwrap();
    let err = index
        .resolve("preen-rs.missing", Some("1.2.0"))
        .unwrap_err();
    assert!(matches!(err, RegistryError::PackNotFound { .. }));
}

#[test]
fn registry_resolve_uses_latest_when_version_omitted() {
    let input = r#"
schema_version = 1

[[entries]]
pack_id = "preen-rs.homebrew"
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.1.0"
  rev = "def456"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#;
    let index = input.parse::<RegistryIndex>().unwrap();
    let resolved = index.resolve("preen-rs.homebrew", None).unwrap();
    assert_eq!(resolved.version, "1.2.0");
    assert_eq!(resolved.rev, "abc123");
}

#[test]
fn registry_schema_version_unsupported() {
    let input = r#"
schema_version = 99

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
    let err = input.parse::<RegistryIndex>().unwrap_err();
    assert!(matches!(
        err,
        RegistryError::SchemaVersionUnsupported {
            found: 99,
            expected: 1
        }
    ));
}

#[test]
fn registry_missing_required_field_fails() {
    let input = r#"
schema_version = 1

[[entries]]
pack_id = ""
name = "Homebrew"
description = "Cleanup pack"
repo_url = "https://github.com/Preen-rs/preen-rulepack-homebrew"
latest_version = "1.2.0"
  [[entries.versions]]
  version = "1.2.0"
  rev = "abc123"
"#;
    let err = input.parse::<RegistryIndex>().unwrap_err();
    assert!(matches!(err, RegistryError::MissingField { .. }));
}
