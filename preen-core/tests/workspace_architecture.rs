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

#[test]
fn ui_crates_do_not_depend_on_each_other() {
    let tui_manifest = read(&workspace_path(&["preen-tui", "Cargo.toml"]));
    let gui_manifest = read(&workspace_path(&["preen-gui", "Cargo.toml"]));

    for forbidden in ["preen-gui", "preen_gui"] {
        assert!(
            !tui_manifest.contains(forbidden),
            "preen-tui must not depend on preen-gui ({forbidden})"
        );
    }

    for forbidden in ["preen-tui", "preen_tui"] {
        assert!(
            !gui_manifest.contains(forbidden),
            "preen-gui must not depend on preen-tui ({forbidden})"
        );
    }
}

#[test]
fn ui_crates_depend_on_shared_core_contracts() {
    let tui_manifest = read(&workspace_path(&["preen-tui", "Cargo.toml"]));
    let gui_manifest = read(&workspace_path(&["preen-gui", "Cargo.toml"]));

    assert!(
        tui_manifest.contains("preen-core"),
        "preen-tui must consume preen-core contracts"
    );
    assert!(
        gui_manifest.contains("preen-core"),
        "preen-gui must consume preen-core contracts"
    );
}
