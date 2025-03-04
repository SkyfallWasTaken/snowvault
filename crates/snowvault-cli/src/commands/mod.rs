use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub mod add;
pub mod new;
pub mod open;

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

    /// Opens a vault
    Open {
        /// Path to the vault
        path: PathBuf,
    },

    /// Adds an entry to a vault
    Add {
        /// Path to the vault
        path: PathBuf,

        /// Name of the entry
        name: String,
    },
}
