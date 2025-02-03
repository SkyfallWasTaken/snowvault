use std::path::Path;

use color_eyre::Result;
use dialoguer::{theme::ColorfulTheme, Password};
use secrecy::SecretString;
use snowvault::{Vault, VaultEntry};

pub fn cmd(path: &Path) -> Result<()> {
    let password: SecretString = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()?
        .into();
    let vault = Vault::load_from_file(path, &password)?;

    for entry in vault.entries {
        match entry {
            VaultEntry::Login {
                name,
                uris,
                username,
                password,
            } => {
                println!("Name: {}", name);
                //println!("URIs: {:?}", uris);
                if let Some(username) = username {
                    println!("Username: {:?}", username);
                }
                if let Some(password) = password {
                    println!("Password: {:?}", password);
                }
            }
            VaultEntry::Note { name, content } => {
                println!("Name: {}", name);
                println!("Content: {:?}", content);
            }
        }
        println!();
    }

    Ok(())
}
