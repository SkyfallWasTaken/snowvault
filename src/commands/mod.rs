use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub mod mount;
pub mod new;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a new vault
    New {
        /// Path to the vault
        path: PathBuf,
    },

    /// Mounts a vault
    Mount {
        /// Path to the vault
        path: PathBuf,
    },
}
