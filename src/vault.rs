use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
};

use argon2::Argon2;
use color_eyre::{
    eyre::{eyre, Context},
    Result,
};
use const_format::formatcp;
use rand::{rngs::ThreadRng, Rng};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;
use zstd::Decoder;

const SALT_SIZE: usize = 16; // As recommended by the Argon2 docs
const KEY_SIZE: usize = 256; // We use AES-256, so we need a 256-bit key
const META_FILENAME: &str = "snowvault.toml";
pub const VAULT_EXTENSION: &str = "snow";
pub const MIN_PASSWORD_LENGTH: usize = 8;

pub struct Vault<'a> {
    pub meta: VaultMeta,
    pub path: &'a PathBuf,
    rng: ThreadRng,
    temp: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    pub salt: String,
    pub key_len: usize,
    #[serde(skip)]
    pub master_key: Option<Vec<u8>>,
    pub master_key_hash: String,
}

impl<'a> Vault<'a> {
    pub fn new_from_password(path: &'a PathBuf, password: &SecretString) -> Result<Self> {
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
        let salt = hex::encode(salt);
        let meta = VaultMeta {
            salt: salt.clone(),
            key_len: KEY_SIZE,
            master_key: Some(output_key_material.to_vec()),
            master_key_hash: hex::encode(
                Sha256::new()
                    .chain_update(output_key_material)
                    .chain_update(salt.as_bytes())
                    .finalize(),
            ),
        };
        let meta_toml: String = toml::to_string(&meta).wrap_err("failed to serialize metadata")?;

        let mut vault = Self {
            meta,
            rng,
            temp: HashMap::new(),
            path,
        };
        vault.add_file(META_FILENAME, meta_toml.as_bytes())?;
        vault.flush()?;
        Ok(vault)
    }

    pub fn load_from_file(path: &'a PathBuf, password: &SecretString) -> Result<Self> {
        let file = File::open(path.clone()).wrap_err("failed to open archive file")?;
        let reader = BufReader::new(file);
        let decoder = Decoder::new(reader).wrap_err("failed to decompress archive")?;
        let mut archive = Archive::new(decoder);
        let entries = archive
            .entries()
            .wrap_err("failed to get archive entries")?;

        let mut meta_contents: String = String::new();
        let mut found_meta = false;
        for entry in entries {
            let mut entry = entry?;
            if entry.path()?.ends_with(META_FILENAME) {
                entry.read_to_string(&mut meta_contents).unwrap();
                found_meta = true;
                break;
            }
        }
        if !found_meta {
            return Err(eyre!(formatcp!("{META_FILENAME} not found in archive")));
        }

        let mut vault_meta: VaultMeta = toml::from_str(&meta_contents)?;
        let salt = hex::decode(vault_meta.salt.clone()).wrap_err("failed to decode salt")?;
        let mut output_key_material = [0u8; KEY_SIZE];
        Argon2::default()
            .hash_password_into(
                password.expose_secret().as_bytes(),
                &salt,
                &mut output_key_material,
            )
            .map_err(|_| eyre!("failed to generate master key when opening archive"))?;
        vault_meta.master_key = Some(output_key_material.to_vec());
        let master_key_hash = hex::encode(
            Sha256::new()
                .chain_update(output_key_material)
                .chain_update(vault_meta.salt.as_bytes())
                .finalize(),
        );
        if master_key_hash != vault_meta.master_key_hash {
            return Err(eyre!("invalid password"));
        }

        Ok(Self {
            meta: vault_meta,
            rng: rand::thread_rng(),
            path,
            temp: HashMap::new(),
        })
    }

    pub fn flush(&mut self) -> Result<()> {
        let mut tar_bytes = Vec::new();
        let mut archive = tar::Builder::new(&mut tar_bytes);
        for (name, data) in self.temp.iter() {
            let mut header = tar::Header::new_gnu();
            header.set_path(name)?;
            header.set_size(data.len() as u64);
            header.set_cksum();
            archive.append(&header, &data[..])?;
        }
        let tar_bytes = archive
            .into_inner()
            .wrap_err("failed to finalize archive")?;
        let compressed =
            zstd::encode_all(&tar_bytes[..], 0).wrap_err("failed to compress archive")?;
        std::fs::write(&self.path, compressed).wrap_err("failed to write archive")?;
        self.temp.clear();
        Ok(())
    }

    pub fn add_file(&mut self, name: &str, data: &[u8]) -> Result<()> {
        self.temp.insert(name.to_string(), data.to_vec());
        Ok(())
    }
}
