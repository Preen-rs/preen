use clap::Parser;

fn main() {
    let cli = preen_cli::Cli::parse();
    if let Err(err) = preen_cli::run_typed(cli.clone()) {
        eprintln!("{}", cli.format_error(&err));
        std::process::exit(1);
    }
}
