# Snowvault

![Snowvault - One password to rule them all.](https://raw.githubusercontent.com/SkyfallWasTaken/snowvault/refs/heads/master/snowvault-hero.png)

Snowvault is a fast, secure password manager written in Rust. One of the key goals is to provide passwords/API keys etc. to production applications, so it has a CLI interface, as well as a WIP GUI version.

## Getting started

First, install Snowvault:

```
git clone https://github.com/SkyfallWasTaken/snowvault && cd snowvault
cargo install --path .
```

Then, create a new vault:
```
snowvault new vault.snow
# Will ask for a master password to use
```

You can then add an entry, like so:

```
snowvault add vault.snow "GitHub"
# Will ask for vault password, and username/password to be stored in the entry
```

And finally, view the entries in the vault:

```
snowvault open vault.snow
```

## Cryptography & Security

**When you create a new vault,** Snowvault generates a random salt using ChaCha20 (a cryptographically secure RNG), and stores both the SHA256 master key hash and the salt in the vault file - this is safe as getting the master key requires knowing the password and having the salt, preventing rainbow table attacks. The key itself is generated with the Argon2id key derivation function using both the salt and the user-provided password. The `secrecy` crate is used to prevent leaking of secrets (like the key/passwords) in memory.

When **an item is added,** Snowvault generates a random nonce (random value) per entry using ChaCha20, then encrypts the value using AES-256-GCM and both the master key and the nonce. The encrypted ciphertext and the nonce are both stored in the vault file - this is safe as the value can't be read without the master key, and the master key requires both the salt and the password to be derived.

When **the vault is opened,** the master key is derived using both the user-provided password and the stored salt. The key is then hashed with SHA256 and compared with the hash in the vault file to verify that it's valid. If it's valid, the entries in the file are decrypted using the derived master key.

---

© 2025 [Mahad Kalam](https://skyfall.dev)
