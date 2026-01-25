# preen-os

This crate serves as the **Operating System Abstraction Layer (OSAL)** for the Preen project.

It is responsible for implementing the **Ports** defined in `preen-core` with platform-specific code (e.g., calling macOS-specific APIs or reading Linux configuration files). This separation ensures that the core logic remains clean and portable.

## Role in Architecture

In the Hexagonal Architecture, `preen-os` acts as the **Adapter** that connects the Core to the external world (the Operating System).

*   **Input**: Receives requests from `preen-core` via the `FileSystemPort` trait.
*   **Output**: Executes the necessary system calls and returns the results back to the Core.

## Implementation Details (Planned)

*   **Conditional Compilation**: Uses `#[cfg(target_os = "macos")]` and `#[cfg(target_os = "linux")]` to include the correct platform-specific code.
*   **Dependencies**: Will rely on crates like `sysinfo` or platform-specific FFI bindings for low-level access.

## Usage

This is a library crate intended to be used by `preen-core` (or directly by the binaries if needed) within the main Preen workspace.

```toml
[dependencies]
preen-os = { path = "../preen-os" }
```
