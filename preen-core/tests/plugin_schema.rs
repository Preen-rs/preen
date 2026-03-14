use preen_core::ItemCategory;
use preen_core::plugin::{ActionSpec, ActionType, RiskLevel};
use preen_core::plugin::{
    Manifest, MatchMode, MatchSpec, RuleFile, ValidationError, validate_ruleset,
};
use preen_core::rules::ScanStrategy;

#[test]
fn manifest_parses_and_validates() {
    let input = r#"
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

    let manifest = input.parse::<Manifest>().unwrap();
    assert_eq!(manifest.pack_id, "test.pack");
}

#[test]
fn manifest_duplicate_rule_id_fails() {
    let input = r#"
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

        [[rules]]
        id = "rule-1"
        name = "Rule 1 dup"
        rule_file = "rules/rule-2.toml"
    "#;

    let err = input.parse::<Manifest>().unwrap_err();
    assert!(matches!(err, ValidationError::DuplicateRuleId { .. }));
}

#[test]
fn ruleset_missing_ref_fails() {
    let input = r#"
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
    let manifest = input.parse::<Manifest>().unwrap();

    let rule = RuleFile {
        schema_version: 1,
        id: "other".to_string(),
        name: "Other".to_string(),
        category: ItemCategory::Cache,
        risk: RiskLevel::Low,
        enabled: true,
        matcher: MatchSpec {
            mode: MatchMode::Paths,
            paths: vec!["/tmp".to_string()],
            strategy: Some(ScanStrategy::Shallow),
            command: vec![],
            parser: None,
        },
        action: ActionSpec {
            action_type: ActionType::TrashPaths,
            paths: vec!["/tmp".to_string()],
            command: vec![],
            mode: None,
            timeout_sec: None,
            allow_globs: false,
            max_items: None,
            package_manager: None,
            project_types: vec![],
            params: Default::default(),
        },
    };

    let err = validate_ruleset(&manifest, &[rule]).unwrap_err();
    assert!(matches!(err, ValidationError::RuleRefMissing { .. }));
}

#[test]
fn core_compat_mismatch_fails() {
    let input = r#"
        schema_version = 1
        pack_id = "test.pack"
        name = "Test Pack"
        version = "0.1.0"
        description = "desc"
        author = "me"
        license = "MIT"
        core_compat = ">=1.0.0,<2.0.0"
        action_api = 1
        os_targets = ["Linux"]
        capabilities = ["FsRead"]

        [[rules]]
        id = "rule-1"
        name = "Rule 1"
        rule_file = "rules/rule-1.toml"
    "#;
    let manifest = input.parse::<Manifest>().unwrap();
    let err = manifest.validate_with_core_version("0.1.0").unwrap_err();
    assert!(matches!(err, ValidationError::InvalidCoreCompat { .. }));
}

#[test]
fn rule_invalid_match_fails() {
    let rule = RuleFile {
        schema_version: 1,
        id: "rule-1".to_string(),
        name: "Rule 1".to_string(),
        category: ItemCategory::Cache,
        risk: RiskLevel::Low,
        enabled: true,
        matcher: MatchSpec {
            mode: MatchMode::Paths,
            paths: vec![],
            strategy: Some(ScanStrategy::Shallow),
            command: vec![],
            parser: None,
        },
        action: ActionSpec {
            action_type: ActionType::TrashPaths,
            paths: vec!["/tmp".to_string()],
            command: vec![],
            mode: None,
            timeout_sec: None,
            allow_globs: false,
            max_items: None,
            package_manager: None,
            project_types: vec![],
            params: Default::default(),
        },
    };

    let err = rule.validate_basic().unwrap_err();
    assert!(matches!(err, ValidationError::InvalidMatchSpec { .. }));
}

#[test]
fn rule_invalid_action_fails() {
    let rule = RuleFile {
        schema_version: 1,
        id: "rule-1".to_string(),
        name: "Rule 1".to_string(),
        category: ItemCategory::Cache,
        risk: RiskLevel::Low,
        enabled: true,
        matcher: MatchSpec {
            mode: MatchMode::Paths,
            paths: vec!["/tmp".to_string()],
            strategy: Some(ScanStrategy::Shallow),
            command: vec![],
            parser: None,
        },
        action: ActionSpec {
            action_type: ActionType::TrashPaths,
            paths: vec![],
            command: vec![],
            mode: None,
            timeout_sec: None,
            allow_globs: false,
            max_items: None,
            package_manager: None,
            project_types: vec![],
            params: Default::default(),
        },
    };

    let err = rule.validate_basic().unwrap_err();
    assert!(matches!(err, ValidationError::InvalidActionSpec { .. }));
}
