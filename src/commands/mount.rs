use std::path::Path;

use crate::vault::Vault;
use color_eyre::Result;
use dialoguer::{theme::ColorfulTheme, Password};
use secrecy::SecretString;

pub fn cmd(path: &Path) -> Result<()> {
    let password: SecretString = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()?
        .into();
    let vault = Vault::load_from_file(path, &password)?;
    dbg!(vault);

    Ok(())
}
