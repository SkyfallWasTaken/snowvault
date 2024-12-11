use iced::{
    widget::{center, container, mouse_area, opaque, stack},
    Color, Element,
};

mod password_prompt;

#[derive(Debug, Clone)]
pub enum ModalType {
    PasswordPrompt,
}

pub fn modal<'a, Message>(
    base: impl Into<Element<'a, Message>>,
    content: impl Into<Element<'a, Message>>,
    on_blur: Message,
) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    stack![
        base.into(),
        opaque(
            mouse_area(center(opaque(content)).style(|_theme| {
                container::Style {
                    background: Some(
                        Color {
                            a: 0.8,
                            ..Color::BLACK
                        }
                        .into(),
                    ),
                    ..container::Style::default()
                }
            }))
            .on_press(on_blur)
        )
    ]
    .into()
}

pub fn get_modal<'a, Message: 'a + Clone>(modal_type: &ModalType) -> Element<'a, Message> {
    match modal_type {
        ModalType::PasswordPrompt => password_prompt::password_prompt(),
    }
}
