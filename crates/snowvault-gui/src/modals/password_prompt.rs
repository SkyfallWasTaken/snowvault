use iced::{
    border,
    theme::Palette,
    widget::{column, container, text, text_input},
    Element,
};

use crate::font::BOLD;

pub fn password_prompt<'a, Message: 'a + Clone>() -> Element<'a, Message> {
    container(
        column![
            text("Enter your password").size(26).font(BOLD),
            text_input("Password", "").padding([16, 12])
        ]
        .spacing(12),
    )
    .style(|_| container::Style {
        background: Some(Palette::CATPPUCCIN_MOCHA.background.into()),
        border: border::rounded(8),
        ..container::Style::default()
    })
    .padding([24, 32])
    .into()
}
