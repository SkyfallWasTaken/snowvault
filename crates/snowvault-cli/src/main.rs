mod commands;
use clap::Parser;
use color_eyre::Result;

use commands::{Cli, Command};

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();
    match &cli.command {
        Command::New { path } => commands::new::cmd(path)?,
        Command::Open { path } => commands::open::cmd(path)?,
    }

    Ok(())
}
