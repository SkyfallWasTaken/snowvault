use std::path::Path;

use color_eyre::Result;
use const_format::formatcp;
use dialoguer::{theme::ColorfulTheme, Password};
use secrecy::SecretString;
use snowvault::{Vault, MIN_PASSWORD_LENGTH};

pub fn cmd(path: &Path) -> Result<()> {
    let password: SecretString = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .with_confirmation("Repeat password", "Error: the passwords don't match.")
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.chars().count() >= MIN_PASSWORD_LENGTH {
                Ok(())
            } else {
                Err(formatcp!(
                    "Password must be at least {MIN_PASSWORD_LENGTH} characters."
                ))
            }
        })
        .interact()?
        .into();

    Vault::new_from_password(path.to_path_buf(), &password)?;

    Ok(())
}
