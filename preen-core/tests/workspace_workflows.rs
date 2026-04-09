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
fn workspace_ci_workflow_has_matrix_and_required_gate() {
    let workflow_path = workspace_path(&[".github", "workflows", "ci.yml"]);
    let workflow = read(&workflow_path);

    for expected in [
        "concurrency:",
        "group: ci-${{ github.workflow }}-${{ github.ref }}",
        "cancel-in-progress: true",
        "name: Check (ubuntu-latest)",
        "name: Test (${{ matrix.runner }})",
        "strategy:",
        "fail-fast: false",
        "matrix:",
        "- ubuntu-latest",
        "- macos-14",
        "name: Required Checks",
        "if: always()",
        "needs:",
        "CHECK_RESULT:",
        "TEST_RESULT:",
        "required checks failed:",
    ] {
        assert!(
            workflow.contains(expected),
            "workspace ci workflow is missing expected segment: {expected}"
        );
    }

    assert_sequence_in_order(
        &workflow,
        &[
            "check:",
            "test:",
            "required-checks:",
            "name: Validate upstream job results",
        ],
        "workspace ci workflow",
    );
}

#[test]
fn workspace_ci_workflow_pins_checkout_action() {
    let workflow_path = workspace_path(&[".github", "workflows", "ci.yml"]);
    let workflow = read(&workflow_path);
    assert!(
        workflow.contains("actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"),
        "workspace ci workflow must pin actions/checkout by commit hash"
    );
}
