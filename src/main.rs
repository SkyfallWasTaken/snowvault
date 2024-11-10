mod commands;
use clap::Parser;
use commands::{Cli, Command};

mod vault;

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Command::New => {
            vault::new_vault();
        }
    }
}
