# Snowvault

![Snowvault - One password to rule them all.](https://raw.githubusercontent.com/SkyfallWasTaken/snowvault/refs/heads/master/snowvault-hero.png)

Snowvault is a fast, secure password manager written in Rust. One of the key goals is to provide passwords/API keys etc. to production applications, so it has a CLI interface, as well as a WIP GUI version.

## Cryptography & Security

- **AES-256-GCM** used for encryption of entries. Unique nonce per entry.
- **Argon2id** used as a **key derivation function (KDF)** to derive the master key for decrypting entries, with a salt which is different for every vault.
- **SHA256** used only for a master key hash in the vault, used for password verification
- `secrecy` crate to help prevent leakage/logging of the master key
- **ChaCha20 CSPRNG** from `rand_chacha` crate, used for generating random nonces and salts

(the above is definitely worded a bit oddly to say the least - promise it's not AI though :P)

---

© 2024 [Mahad Kalam](https://skyfall.dev)

All rights reserved.
