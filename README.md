# Preen: The Ultimate System Cleaner and Optimizer

**Preen** is a high-performance, cross-platform system maintenance and optimization tool, built with **Rust**. It is designed to be a modern, open-source alternative to proprietary tools like CleanMyMac, offering a powerful core logic accessible via both a fast Terminal User Interface (TUI) and a user-friendly Graphical User Interface (GUI).

## 🚀 Features (Planned)

*   **Deep System Scan**: Identify and safely remove caches, logs, and temporary files across macOS and Linux.
*   **Application Uninstaller**: Completely remove applications and all associated files.
*   **Disk Usage Analyzer**: Interactive, visual analysis of disk space consumption.
*   **System Monitor**: Real-time monitoring of CPU, memory, and network usage.
*   **Project Cleanup**: Smartly purge build artifacts like `node_modules` and Rust `target` directories.

## 🏗️ Architecture

Preen is built on a robust **Core-first** architecture using a **Cargo Workspace** and the **Hexagonal Architecture (Ports and Adapters)** pattern. This ensures maximum performance, testability, and separation of concerns.

| Crate | Role | Interface | Status |
| :--- | :--- | :--- | :--- |
| `preen-core` | Core Logic / Domain | Library | In Development |
| `preen-os` | OS Abstraction / Adapter | Library | In Development |
| `preen-tui` | Terminal User Interface | Binary | **Phase 1 Focus** |
| `preen-gui` | Graphical User Interface | Binary | Phase 2 Focus |

## 🛠️ Development

This project is a **Mono-repo** managed by a Cargo Workspace.

### Prerequisites

*   Rust stable toolchain
*   `cargo`

### Build and Run

To check the entire workspace:

```bash
cargo check --all
```

To run the TUI application (Phase 1 focus):

```bash
cargo run --package preen-tui
```

## 📝 License

Preen is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
