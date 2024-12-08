use iced::widget::{button, column, row, text, text_input, Column};
use rfd::FileDialog;
use secrecy::{ExposeSecret, SecretString};
use snowvault::Vault;

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
            Message::NewVault => todo!(),

            Message::PasswordInputUpdated(password) => {
                self.password = SecretString::from(password);
            }
        }
    }

    fn view(&self) -> Column<Message> {
        let mut new_vault = button("New Vault");
        let mut open_vault = button("Open Vault");

        if !self.password.expose_secret().is_empty() {
            new_vault = new_vault.on_press(Message::NewVault);
            open_vault = open_vault.on_press(Message::OpenVault);
        }

        column![
            row![new_vault, open_vault].spacing(8),
            match &self.vault {
                Some(Ok(vault)) => column![text("Vault opened"), text(format!("{:?}", vault)),],
                Some(Err(err)) => column![
                    text("Error opening vault"),
                    text(err.to_string()),
                    text_input("Password", &self.password.expose_secret())
                        .secure(true)
                        .on_input(Message::PasswordInputUpdated),
                ],
                None => column![
                    text("No vault opened"),
                    text_input("Password", &self.password.expose_secret())
                        .secure(true)
                        .on_input(Message::PasswordInputUpdated),
                ],
            }
        ]
    }
}

fn main() -> iced::Result {
    iced::run("Snowvault", Application::update, Application::view)
}
