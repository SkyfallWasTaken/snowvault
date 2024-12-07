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
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod error;
pub use error::Error;

const SALT_SIZE: usize = 16; // As recommended by the Argon2 docs
const KEY_SIZE: usize = 32; // We use AES-256, so we need a 256-bit key (32 bytes)
pub const MIN_PASSWORD_LENGTH: usize = 6;

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    pub meta: VaultMeta,
    pub path: PathBuf,
    enc_entries: Vec<EncVaultEntry>,
    #[serde(skip)]
    pub entries: Vec<VaultEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncVaultEntry {
    /// The nonce is encoded as a hex string.
    nonce: String,

    /// The ciphertext is encoded as a hex string.
    encoded_ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
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

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VaultMeta {
    pub salt: String,
    pub key_len: usize,
    #[serde(skip)]
    pub master_key: Option<SecretSlice<u8>>,
    pub master_key_hash: String,
}

impl Vault {
    pub fn new_from_password(path: PathBuf, password: &SecretString) -> Result<Self, Error> {
        let mut salt = [0u8; SALT_SIZE];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut salt);
        let output_key_material = generate_master_key(password, &salt)?;
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
            path,
            enc_entries: Vec::new(),
            entries: Vec::new(),
        };

        vault.save()?;
        Ok(vault)
    }

    pub fn load_from_file(path: &Path, password: &SecretString) -> Result<Self, Error> {
        let mut file = File::open(path)?;
        let mut vault_contents = String::new();
        file.read_to_string(&mut vault_contents)?;

        let mut vault: Self = toml::from_str(&vault_contents)?;
        let salt = hex::decode(vault.meta.salt.clone())?;

        let output_key_material = generate_master_key(password, &salt)?;
        if output_key_material.expose_secret().len() != 32 {
            return Err(Error::InvalidKeyLength);
        }
        vault.meta.master_key = Some(output_key_material.clone());

        verify_master_key(&vault, &output_key_material)?;

        let cipher = Aes256Gcm::new_from_slice(output_key_material.expose_secret())
            .map_err(|_| Error::InvalidKeyLength)?;

        decrypt_entries(&mut vault, &cipher)?;

        Ok(vault)
    }

    pub fn add_entry(&mut self, entry: VaultEntry, key: &SecretSlice<u8>) -> Result<(), Error> {
        let nonce = {
            let mut rng = ChaCha20Rng::from_entropy();
            Aes256Gcm::generate_nonce(&mut rng)
        };
        let cipher =
            Aes256Gcm::new_from_slice(key.expose_secret()).map_err(|_| Error::InvalidKeyLength)?;
        let plaintext = toml::to_string(&entry)?;
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())?;
        let enc_entry = EncVaultEntry {
            nonce: hex::encode(nonce),
            encoded_ciphertext: hex::encode(ciphertext),
        };
        self.enc_entries.push(enc_entry);
        self.entries.push(entry);
        Ok(())
    }

    pub fn rm_entry(&mut self, index: usize) {
        self.enc_entries.remove(index);
        self.entries.remove(index);
    }

    pub fn save(&self) -> Result<(), Error> {
        // Everything's encrypted already, so this isn't an issue
        let toml: String = toml::to_string(self)?;
        std::fs::write(&self.path, toml)?;
        Ok(())
    }
}

fn generate_master_key(password: &SecretString, salt: &[u8]) -> Result<SecretSlice<u8>, Error> {
    let mut output_key_material = SecretSlice::new(Box::new([0u8; KEY_SIZE]));
    Argon2::default().hash_password_into(
        password.expose_secret().as_bytes(),
        salt,
        output_key_material.expose_secret_mut(),
    )?;
    debug_assert_eq!(output_key_material.expose_secret().len(), KEY_SIZE);
    Ok(output_key_material)
}

fn verify_master_key(vault: &Vault, output_key_material: &SecretSlice<u8>) -> Result<(), Error> {
    let master_key_hash = hex::encode(
        Sha256::new()
            .chain_update(output_key_material.expose_secret())
            .chain_update(vault.meta.salt.as_bytes())
            .finalize(),
    );

    if master_key_hash != vault.meta.master_key_hash {
        return Err(Error::InvalidPassword);
    }
    Ok(())
}

fn decrypt_entries(vault: &mut Vault, cipher: &Aes256Gcm) -> Result<(), Error> {
    for entry in &vault.enc_entries {
        let nonce_vec = hex::decode(entry.nonce.clone())?;
        let nonce = Nonce::from_slice(&nonce_vec);
        let ciphertext = hex::decode(&entry.encoded_ciphertext)?;
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|_| Error::AesGcmError)?;

        let entry_str = std::str::from_utf8(&plaintext).unwrap();
        let entry: VaultEntry = toml::from_str(entry_str)?;
        vault.entries.push(entry);
    }
    Ok(())
}
