# preen-gui

This crate provides the **Graphical User Interface (GUI)** for the Preen system cleaner.

It is the focus of **Phase 2** of the Preen project development. It acts as a **Driver** in the Hexagonal Architecture, sending `Command`s to the `preen-core` and rendering the visual interface based on the `Event`s received.

## Technology (Planned)

The GUI will be built using a modern, cross-platform Rust GUI framework to ensure a native look and feel on both macOS and Linux.

- **Framework**: [Iced](https://iced.rs/) or [Tauri](https://tauri.app/) (To be decided based on final requirements).

## Usage

To run the GUI application from the workspace root:

```bash
cargo run --package preen-gui
```
