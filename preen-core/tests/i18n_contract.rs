use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_yaml::Value;

fn locale_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("locales")
}

fn workspace_docs_file(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root is missing")
        .join(path)
}

fn read_locale_files() -> BTreeMap<String, PathBuf> {
    let mut locales = BTreeMap::new();
    for entry in fs::read_dir(locale_dir()).expect("failed to read locale directory") {
        let entry = entry.expect("failed to read locale file entry");
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if ext != "yml" && ext != "yaml" {
            continue;
        }
        let locale = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("invalid locale filename")
            .to_string();
        locales.insert(locale, path);
    }
    locales
}

fn parse_yaml(path: &Path) -> Value {
    let content = fs::read_to_string(path).expect("failed to read locale file");
    serde_yaml::from_str::<Value>(&content).expect("failed to parse locale yaml")
}

fn flatten_keys(value: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Mapping(map) => {
            for (key, nested) in map {
                let key = key
                    .as_str()
                    .expect("non-string keys are not supported in locale files");
                let next = if prefix.is_empty() {
                    key.to_string()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_keys(nested, &next, out);
            }
        }
        _ => {
            out.insert(prefix.to_string());
        }
    }
}

fn validate_leaf_values(locale: &str, value: &Value, prefix: &str, errors: &mut Vec<String>) {
    match value {
        Value::Mapping(map) => {
            for (key, nested) in map {
                let key = key
                    .as_str()
                    .expect("non-string keys are not supported in locale files");
                let next = if prefix.is_empty() {
                    key.to_string()
                } else {
                    format!("{prefix}.{key}")
                };
                validate_leaf_values(locale, nested, &next, errors);
            }
        }
        Value::String(text) => {
            if text.trim().is_empty() {
                errors.push(format!(
                    "{locale}: empty localized string at key `{prefix}`"
                ));
            }
        }
        Value::Number(_) if prefix == "_version" => {}
        other => {
            errors.push(format!(
                "{locale}: invalid leaf type at key `{prefix}`: expected string, got {other:?}"
            ));
        }
    }
}

fn locale_keyset(path: &Path) -> BTreeSet<String> {
    let value = parse_yaml(path);
    let mut keys = BTreeSet::new();
    flatten_keys(&value, "", &mut keys);
    keys
}

fn documented_plugin_keyset() -> BTreeSet<String> {
    let doc_path = workspace_docs_file("docs/PLUGIN_I18N_CONTRACT.md");
    let doc = fs::read_to_string(doc_path).expect("failed to read PLUGIN_I18N_CONTRACT.md");
    let start = "<!-- CONTRACT_KEYS_START -->";
    let end = "<!-- CONTRACT_KEYS_END -->";
    let (_, rest) = doc
        .split_once(start)
        .expect("missing CONTRACT_KEYS_START marker");
    let (body, _) = rest
        .split_once(end)
        .expect("missing CONTRACT_KEYS_END marker");
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn locale_files_have_matching_keysets_against_en_us() {
    let locales = read_locale_files();
    assert!(
        locales.contains_key("en-US"),
        "baseline locale en-US.yml is required"
    );
    let baseline = locale_keyset(locales.get("en-US").unwrap());
    for (locale, path) in locales {
        let keys = locale_keyset(&path);
        let missing: Vec<_> = baseline.difference(&keys).cloned().collect();
        let extra: Vec<_> = keys.difference(&baseline).cloned().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "locale key mismatch for {locale}: missing={missing:?} extra={extra:?}"
        );
    }
}

#[test]
fn locale_leaf_values_are_non_empty_strings() {
    let locales = read_locale_files();
    let mut errors = Vec::new();
    for (locale, path) in locales {
        let parsed = parse_yaml(&path);
        validate_leaf_values(&locale, &parsed, "", &mut errors);
    }
    assert!(
        errors.is_empty(),
        "locale value contract failed:\n{}",
        errors.join("\n")
    );
}

#[test]
fn documented_plugin_keys_match_locale_keys() {
    let locales = read_locale_files();
    let baseline_path = locales
        .get("en-US")
        .expect("baseline locale en-US.yml is required");
    let actual: BTreeSet<String> = locale_keyset(baseline_path)
        .into_iter()
        .filter(|key| key.starts_with("plugin."))
        .collect();
    let documented = documented_plugin_keyset();
    let missing_in_doc: Vec<_> = actual.difference(&documented).cloned().collect();
    let missing_in_locale: Vec<_> = documented.difference(&actual).cloned().collect();
    assert!(
        missing_in_doc.is_empty() && missing_in_locale.is_empty(),
        "plugin i18n doc mismatch: missing_in_doc={missing_in_doc:?} missing_in_locale={missing_in_locale:?}"
    );
}
