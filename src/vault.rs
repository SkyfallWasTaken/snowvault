use argon2::Argon2;
use color_eyre::{eyre::eyre, Result};
use rand::{rngs::ThreadRng, Rng};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

const SALT_SIZE: usize = 16; // As recommended by the Argon2 docs
const KEY_SIZE: usize = 256; // We use AES-256, so we need a 256-bit key

pub struct Vault {
    pub meta: VaultMeta,
    rng: ThreadRng,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    pub salt: String,
    pub key_len: usize,
    pub master_key: Vec<u8>, // Assert that this is valid length!
}

impl Vault {
    pub fn new_from_password(password: SecretString) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let salt: [u8; SALT_SIZE] = rng.gen();
        let mut output_key_material = [0u8; KEY_SIZE];
        Argon2::default()
            .hash_password_into(
                password.expose_secret().as_bytes(),
                &salt,
                &mut output_key_material,
            )
            .map_err(|_| eyre!("failed to generate master key"))?;

        Ok(Self {
            meta: VaultMeta {
                salt: hex::encode(salt),
                key_len: 32,
                master_key: output_key_material.to_vec(),
            },
            rng,
        })
    }
}
