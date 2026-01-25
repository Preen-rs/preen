# preen-tui

This crate provides the **Terminal User Interface (TUI)** for the Preen system cleaner.

It is the primary focus of **Phase 1** of the Preen project development. It acts as the **Driver** in the Hexagonal Architecture, sending `Command`s to the `preen-core` and rendering the UI based on the `Event`s received.

## Technology

*   **Framework**: [Ratatui](https://ratatui.rs/) (Planned)
*   **Backend**: [Crossterm](https://github.com/crossterm-rs/crossterm) (Planned)

## Usage

To run the TUI application from the workspace root:

```bash
cargo run --package preen-tui
```
