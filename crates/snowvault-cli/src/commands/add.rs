use std::path::Path;

use color_eyre::Result;
use dialoguer::{theme::ColorfulTheme, Input, Password};
use secrecy::SecretString;
use snowvault::{Vault, VaultEntry};

pub fn cmd(path: &Path, name: &String) -> Result<()> {
    let password: SecretString = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Vault password")
        .interact()?
        .into();
    let mut vault = Vault::load_from_file(path, &password)?;

    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Username")
        .interact_text()?;
    let password: String = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()?;
    vault.add_entry(VaultEntry::Login {
        name: name.clone(),
        uris: vec![],
        username: Some(username),
        password: Some(password),
    })?;

    vault.save()?;

    Ok(())
}
