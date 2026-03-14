#!/usr/bin/env bash
set -euo pipefail

cargo check --workspace --all-targets
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
