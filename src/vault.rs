use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use color_eyre::{
    eyre::{eyre, Context},
    Result,
};
use rand::{rngs::ThreadRng, Rng};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SALT_SIZE: usize = 16; // As recommended by the Argon2 docs
const KEY_SIZE: usize = 256; // We use AES-256, so we need a 256-bit key
const META_FILENAME: &str = "vault.snow";
pub const MIN_PASSWORD_LENGTH: usize = 6;

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    pub meta: VaultMeta,
    pub path: PathBuf,
    enc_entries: Vec<EncVaultEntry>,
    #[serde(skip)]
    pub entries: Vec<VaultEntry>,
    #[serde(skip)]
    rng: ThreadRng,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncVaultEntry {
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum VaultEntry {
    Note {
        name: String,
        content: Option<String>,
    },
    Login {
        name: String,
        uris: Vec<String>,
        username: Option<String>,
        password: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    pub salt: String,
    pub key_len: usize,
    #[serde(skip)]
    pub master_key: Option<SecretSlice<u8>>,
    pub master_key_hash: String,
}

impl Vault {
    pub fn new_from_password(path: &PathBuf, password: &SecretString) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let salt: [u8; SALT_SIZE] = rng.gen();
        let mut output_key_material = SecretSlice::new(Box::new([0u8; KEY_SIZE]));
        Argon2::default()
            .hash_password_into(
                password.expose_secret().as_bytes(),
                &salt,
                output_key_material.expose_secret_mut(),
            )
            .map_err(|_| eyre!("failed to generate master key"))?;
        let salt = hex::encode(salt);
        let meta = VaultMeta {
            salt: salt.clone(),
            key_len: KEY_SIZE,
            master_key: Some(output_key_material.clone()),
            master_key_hash: hex::encode(
                Sha256::new()
                    .chain_update(output_key_material.expose_secret())
                    .chain_update(salt.as_bytes())
                    .finalize(),
            ),
        };
        let vault = Self {
            meta,
            rng,
            path: path.clone(),
            enc_entries: Vec::new(),
            entries: Vec::new(),
        };

        let toml: String = toml::to_string(&vault).wrap_err("failed to serialize vault")?;
        std::fs::write(path, toml)?;

        Ok(vault)
    }

    pub fn load_from_file(path: &Path, password: &SecretString) -> Result<Self> {
        let mut file = File::open(path).wrap_err("failed to open archive file")?;

        let mut vault_contents = String::new();
        file.read_to_string(&mut vault_contents)
            .wrap_err("failed to read archive file")?;
        let mut vault: Vault = toml::from_str(&vault_contents)?;
        let salt = hex::decode(vault.meta.salt.clone()).wrap_err("failed to decode salt")?;
        let mut output_key_material = SecretSlice::new(Box::new([0u8; KEY_SIZE]));
        Argon2::default()
            .hash_password_into(
                password.expose_secret().as_bytes(),
                &salt,
                output_key_material.expose_secret_mut(),
            )
            .map_err(|_| eyre!("failed to generate master key when opening archive"))?;
        vault.meta.master_key = Some(output_key_material.clone());
        let master_key_hash = hex::encode(
            Sha256::new()
                .chain_update(output_key_material.expose_secret())
                .chain_update(vault.meta.salt.as_bytes())
                .finalize(),
        );
        if master_key_hash != vault.meta.master_key_hash {
            return Err(eyre!("invalid password"));
        }
        vault.rng = rand::thread_rng();

        let cipher = Aes256Gcm::new_from_slice(output_key_material.expose_secret())
            .map_err(|_| eyre!("invalid key length"))?;
        for entry in &vault.enc_entries {
            let nonce_vec = hex::decode(entry.nonce.clone())?;
            let nonce = Nonce::from_slice(&nonce_vec);
            let plaintext = cipher
                .decrypt(nonce, entry.ciphertext.as_ref())
                .map_err(|e| eyre!("decryption error: {}", e))?;
            let entry: VaultEntry = toml::from_str(std::str::from_utf8(&plaintext)?)?;
            vault.entries.push(entry);
        }

        Ok(vault)
    }

    pub fn add_entry(&mut self, entry: VaultEntry, key: &SecretSlice<u8>) -> Result<()> {
        let nonce = Aes256Gcm::generate_nonce(&mut self.rng);
        let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
            .map_err(|_| eyre!("invalid key length"))?;
        let plaintext = toml::to_string(&entry)?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| eyre!("encryption error: {}", e))?;
        let enc_entry = EncVaultEntry {
            nonce: hex::encode(nonce.as_slice()),
            ciphertext: hex::encode(ciphertext),
        };
        self.enc_entries.push(enc_entry);
        self.entries.push(entry);
        Ok(())
    }
}
