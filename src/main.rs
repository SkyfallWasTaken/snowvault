mod commands;
use clap::Parser;
use color_eyre::Result;

use commands::{Cli, Command};

mod vault;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::New => commands::new::cmd()?,
    }

    Ok(())
}
