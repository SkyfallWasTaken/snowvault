use std::path::PathBuf;

use crate::vault::{Vault, MIN_PASSWORD_LENGTH};
use color_eyre::Result;
use const_format::formatcp;
use dialoguer::{theme::ColorfulTheme, Password};
use secrecy::SecretString;

pub fn cmd(path: &PathBuf) -> Result<()> {
    let password: SecretString = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .with_confirmation("Repeat password", "Error: the passwords don't match.")
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.chars().count() > MIN_PASSWORD_LENGTH {
                Ok(())
            } else {
                Err(formatcp!(
                    "Password must be longer than {MIN_PASSWORD_LENGTH} characters."
                ))
            }
        })
        .interact()?
        .into();

    let vault = Vault::new_from_password(path, &password)?;

    Ok(())
}
