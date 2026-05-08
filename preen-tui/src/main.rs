mod app;
mod i18n;
mod model;
mod plugin_status;
mod ui;
mod worker;

fn main() -> std::process::ExitCode {
    match app::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("preen-tui error: {error}");
            std::process::ExitCode::from(1)
        }
    }
}
