# preen-core

This crate contains the **core business logic** and **domain models** for the Preen system cleaner and optimizer.

It is designed to be completely platform-agnostic and UI-agnostic, adhering to the principles of the Hexagonal Architecture.

## Key Components

*   **Domain Models**: Defines the data structures used throughout the application (e.g., `ScanResult`, `CleanableItem`, `SystemStats`).
*   **Ports**: Defines the necessary traits (`FileSystemPort`, `SystemMonitorPort`) that must be implemented by the `preen-os` adapter to interact with the operating system.
*   **Application Services**: Contains the use-case logic (e.g., `CleanerService`, `ScannerService`).
*   **Messaging Protocol**: Defines the `Command` (UI -> Core) and `Event` (Core -> UI) enums for asynchronous communication.

## Usage

This is a library crate intended to be used by the `preen-os`, `preen-tui`, and `preen-gui` crates within the main Preen workspace.

```toml
[dependencies]
preen-core = { path = "../preen-core" }
```
