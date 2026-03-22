use clap::Parser;

fn main() {
    let cli = preen_cli::Cli::parse();
    if let Err(err) = preen_cli::run_typed(cli.clone()) {
        if preen_cli::should_emit_formatted_error(&cli, &err) {
            eprintln!("{}", cli.format_error(&err));
        }
        std::process::exit(1);
    }
}
