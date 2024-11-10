use std::{
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
use tar::Archive;
use zstd::Decoder;

const SALT_SIZE: usize = 16; // As recommended by the Argon2 docs
const KEY_SIZE: usize = 256; // We use AES-256, so we need a 256-bit key
const META_FILENAME: &str = "snowvault.toml";
pub const VAULT_EXTENSION: &str = "snow";
pub const MIN_PASSWORD_LENGTH: usize = 8;

pub struct Vault<'a> {
    pub meta: VaultMeta,
    rng: ThreadRng,
    archive: Archive,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    pub salt: String,
    pub key_len: usize,
    pub master_key: Option<Vec<u8>>, // Assert that this is valid length!
}

impl<'a> Vault<'a> {
    pub fn new_from_password(password: &SecretString, path: PathBuf) -> Result<Self> {
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
        let meta = VaultMeta {
            salt: hex::encode(salt),
            key_len: KEY_SIZE,
            master_key: Some(output_key_material.to_vec()),
        };
        let meta_toml: String = toml::to_string(&meta).wrap_err("failed to serialize metadata")?;

        let mut archive = tar::Builder::new(TODO);
        let mut header = tar::Header::new_gnu();
        header.set_path(META_FILENAME)?;
        header.set_size(meta_toml.len() as u64);
        header.set_cksum();
        archive.append(&header, meta_toml.as_bytes())?;

        Ok(Self { meta, rng })
    }

    pub fn load_from_file(path: PathBuf, password: &SecretString) -> Result<Self> {
        let file = File::open(path).wrap_err("failed to open archive file")?;
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

        Ok(Self {
            meta: vault_meta,
            rng: rand::thread_rng(),
            archive,
        })
    }
}
