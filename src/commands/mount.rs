use std::path::PathBuf;

use crate::vault::{Vault, MIN_PASSWORD_LENGTH};
use color_eyre::Result;
use const_format::formatcp;
use dialoguer::{theme::ColorfulTheme, Password};
use secrecy::SecretString;

pub fn cmd(path: &PathBuf) -> Result<()> {
    let password: SecretString = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()?
        .into();
    let vault = Vault::load_from_file(path, &password)?;
    dbg!(vault.meta);

    Ok(())
}
