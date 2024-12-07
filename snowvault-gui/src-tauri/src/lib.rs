use std::path::PathBuf;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use eyre::Result;
use secrecy::SecretString;
use snowvault::Vault;

#[tauri::command]
fn load_from_file(path: &str, password: &str) -> Result<Vault> {
    let path = PathBuf::from(path);
    let password = SecretString::new(password.into());
    let vault = Vault::load_from_file(&path, &password)?;
    Ok(vault)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![load_from_file])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
