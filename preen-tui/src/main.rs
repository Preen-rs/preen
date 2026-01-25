use preen_core::Command;

fn main() {
    println!("Preen TUI is starting up... (Core Command: {:?})", Command::StartScan { path: std::path::PathBuf::from("/home") });
}
