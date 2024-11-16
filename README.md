# Snowvault

## Cryptography & Security

- **AES-256-GCM** used for encryption of entries. Unique nonce per entry.
- **Argon2id** used as a **key derivation function (KDF)** to derive the master key for decrypting entries, with a salt which is different for every vault.
- **SHA256** used only for a master key hash in the vault, used for password verification
- `secrecy` crate to help prevent leakage/logging of the master key
- **ChaCha12 CSPRNG** from `rand_chacha` crate, used for generating random nonces and salts

---

© 2024 [Mahad Kalam](https://skyfall.dev)

All rights reserved.
