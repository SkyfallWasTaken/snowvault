use iced::{
    border,
    widget::{button, column, container, scrollable, text, text_input, Column, Container},
    Length, Padding, Theme,
};
use rfd::FileDialog;
use secrecy::{ExposeSecret, SecretString};
use snowvault::{Vault, VaultEntry};

#[derive(Default)]
struct Application {
    vault: Option<Result<Vault, snowvault::Error>>,
    password: SecretString,
}

#[derive(Debug, Clone)]
enum Message {
    OpenVault,
    NewVault,
    PasswordInputUpdated(String),
    EntryAdded,
}

impl Application {
    fn update(&mut self, message: Message) {
        match message {
            Message::OpenVault => {
                let file = FileDialog::new()
                    .add_filter("Snowvault File", &["vault"])
                    .set_directory("/")
                    .pick_file();
                if let Some(file) = file {
                    self.vault = Some(Vault::load_from_file(&file, &self.password));
                }
            }
            Message::NewVault => {
                let file = FileDialog::new()
                    .add_filter("Snowvault File", &["vault"])
                    .set_directory("/")
                    .save_file();
                if let Some(file) = file {
                    self.vault = Some(Vault::new_from_password(file, &self.password));
                }
            }

            Message::PasswordInputUpdated(password) => {
                self.password = SecretString::from(password);
            }

            Message::EntryAdded => {
                let entry = VaultEntry::Login {
                    name: "Example".to_string(),
                    username: Some("example".to_string()),
                    password: Some("password".to_string()),
                    uris: vec![],
                };
                self.vault
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .add_entry(entry)
                    .unwrap(); // FIXME: Handle error
            }
        }
    }

    fn view(&self) -> Container<Message> {
        let mut new_vault = button("New Vault").width(Length::Fill);
        let mut open_vault = button("Open Vault").width(Length::Fill);

        if !self.password.expose_secret().is_empty() {
            new_vault = new_vault.on_press(Message::NewVault);
            open_vault = open_vault.on_press(Message::OpenVault);
        }

        container(
            column![
                column![new_vault, open_vault].spacing(8),
                match &self.vault {
                    Some(Ok(vault)) => {
                        let entries = vault.entries.iter().map(|entry| match entry {
                            VaultEntry::Login { name, .. } => {
                                column![text("Login"), text(name.clone()),].into()
                            }
                            VaultEntry::Note { name, .. } => {
                                column![text("Note"), text(name.clone()),].into()
                            }
                        });

                        /* Column::new()
                        .push(Button::new("Add Entry").on_press(Message::EntryAdded))
                        .push(
                            Scrollable::new(Column::with_children(entries).spacing(8))
                                .width(Length::Fill),
                        )
                        .width(Length::Fill)
                        .padding(iced::Padding::from(20))
                        .spacing(8) */

                        column![
                            button("Add Entry").on_press(Message::EntryAdded),
                            scrollable(Column::with_children(entries).spacing(8))
                                .width(Length::Fill)
                        ]
                    }
                    Some(Err(err)) => column![
                        text("Error opening vault"),
                        text(err.to_string()),
                        text_input("Password", self.password.expose_secret())
                            .secure(true)
                            .on_input(Message::PasswordInputUpdated),
                    ],
                    None => column![
                        text("No vault opened"),
                        text_input("Password", self.password.expose_secret())
                            .secure(true)
                            .on_input(Message::PasswordInputUpdated),
                    ],
                }
            ]
            .spacing(12),
        )
        .padding(Padding::from([20, 24]))
        .center_x(Length::Fill)
        .style(|_| container::Style {
            border: border::rounded(16),
            ..Default::default()
        })
    }

    #[allow(clippy::unused_self)] // Iced requires this method to take &self
    const fn theme(&self) -> Theme {
        Theme::CatppuccinMocha
    }
}

fn main() -> iced::Result {
    iced::application("Snowvault", Application::update, Application::view)
        .theme(Application::theme)
        .run()
}
