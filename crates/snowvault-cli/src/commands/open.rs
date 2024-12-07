use std::path::Path;

use color_eyre::Result;
use dialoguer::{theme::ColorfulTheme, Password};
use secrecy::SecretString;
use snowvault::Vault;

pub fn cmd(path: &Path) -> Result<()> {
    let password: SecretString = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()?
        .into();
    let vault = Vault::load_from_file(path, &password)?;
    dbg!(vault);

    Ok(())
}
