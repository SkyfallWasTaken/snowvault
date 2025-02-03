#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// hide console window on Windows in release
use eframe::egui;
use egui_modal::Modal;
use rfd::FileDialog;
use secrecy::SecretString;
use snowvault::Vault;
use std::path::PathBuf;

fn main() -> eframe::Result {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([320.0, 240.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Snowvault",
        options,
        Box::new(|_cc| Ok(Box::<SnowvaultApp>::default())),
    )
}

enum State {
    NoVault,
    PasswordModal {
        path: PathBuf,
        creating: bool,
        error: Option<String>,
        password: String,
    },
    VaultOpen(Vault),
}

struct SnowvaultApp {
    state: State,
}

impl Default for SnowvaultApp {
    fn default() -> Self {
        Self {
            state: State::NoVault,
        }
    }
}

impl eframe::App for SnowvaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Snowvault");

            match &mut self.state {
                State::NoVault => {
                    ui.label("No vault");
                    ui.horizontal(|ui| {
                        if ui.button("Open").clicked() {
                            let path = FileDialog::new()
                                .add_filter("Snowvault File", &["snow"])
                                .pick_file();
                            if let Some(path) = path {
                                self.state = State::PasswordModal {
                                    path,
                                    creating: false,
                                    error: None,
                                    password: String::new(),
                                };
                            }
                        }
                        if ui.button("Create").clicked() {
                            let path = FileDialog::new()
                                .add_filter("Snowvault File", &["snow"])
                                .save_file();
                            if let Some(path) = path {
                                self.state = State::PasswordModal {
                                    path,
                                    creating: true,
                                    error: None,
                                    password: String::new(),
                                };
                            }
                        }
                    });                
                },
                State::PasswordModal {
                    path,
                    creating,
                    error,
                    password,
                } => {
                    let modal = Modal::new(ctx, "password_modal");

                    modal.show(|ui| {
                        modal.title(ui, "Enter password");
                        modal.frame(ui, |ui| {
                            let body_text = if *creating {
                                "Create a password to encrypt the vault. This will be required to open the vault in the future."
                            } else {
                                "Enter the password to open the vault."
                            };
                            modal.body(ui, body_text);
                            ui.text_edit_singleline(&mut *password);
                        });
                
                        let button_text = if *creating {
                            "Create"
                        } else {
                            "Decrypt"
                        };
                        modal.buttons(ui, |ui| {
                            // After clicking, the modal is automatically closed
                            if modal.button(ui, button_text).clicked() {
                                let vault = Vault::load_from_file(path, &SecretString::new(password.clone().into_boxed_str()));
                                match vault {
                                    Ok(vault) => {
                                        self.state = State::VaultOpen(vault);
                                    }
                                    Err(err) => {
                                        *error = Some(err.to_string());
                                    }
                                }
                            };
                        });
                    });   
                },
                _ => todo!(),
            }
        });
    }
}
