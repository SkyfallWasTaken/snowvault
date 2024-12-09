use serde::Serialize;

#[derive(thiserror::Error, Debug, Serialize)]
pub enum Error {
    #[error("failed to decode hex value - file might be corrupt?")]
    HexDecodeError,

    #[error("failed to read/write to file")]
    IoError,

    #[error("failed to encrypt/decrypt value - file might be corrupt?")]
    AesGcmError,

    #[error("argon2 error")]
    Argon2Error,

    #[error("failed to serialize toml")]
    TomlSerError,

    #[error("failed to deserialize toml - file may be corrupt?")]
    TomlDeError,

    #[error("invalid key length. this is a bug.")]
    InvalidKeyLength,

    #[error("invalid password")]
    InvalidPassword,

    #[error("failed to get utf-8 string from decrypted ciphertext")]
    Utf8Error,

    #[error("vault has not been opened, so master key hasn't been initialized. this is a bug.")]
    NoMasterKey,
}

impl From<argon2::Error> for Error {
    fn from(_: argon2::Error) -> Self {
        Self::Argon2Error
    }
}

impl From<hex::FromHexError> for Error {
    fn from(_: hex::FromHexError) -> Self {
        Self::HexDecodeError
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::IoError
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(_: aes_gcm::Error) -> Self {
        Self::AesGcmError
    }
}

impl From<toml::ser::Error> for Error {
    fn from(_: toml::ser::Error) -> Self {
        Self::TomlSerError
    }
}

impl From<toml::de::Error> for Error {
    fn from(_: toml::de::Error) -> Self {
        Self::TomlDeError
    }
}
