[![crates.io](https://img.shields.io/crates/v/cargo-credential-pass.svg)](https://crates.io/crates/cargo-credential-pass)
[![docs.rs](https://docs.rs/cargo-credential-pass/badge.svg)](https://docs.rs/cargo-credential-pass)

# cargo-credential-pass

A Cargo [credential provider] for [pass].

* No config needed[^cargo]
* Stores encrypted tokens in your password store with all your other secrets
* Automatically encrypts using your password store GPG key
* Works great with keys stored on HSMs too (hello YubiKey!)

Because no one likes plaintext credentials on disk :(

## Use It

1. Install `cargo-credential-pass`:

```shellsession
% cargo install --locked cargo-credential-pass
```

2. [Configure Cargo] to use this credential provider:

```toml
[registry]
global-credential-providers = ["cargo-credential-pass"]
```

3. Login! `cargo login` will pop up your editor - paste your registry token and
   close the window.

Your token will now be stored as an encrypted text file in
`$PASSWORD_STORE_DIR/cargo-registry/<registery-name>.token`.

That's it - you're good to go!

[pass]: https://www.passwordstore.org/
[credential provider]:
    https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html
[Configure Cargo]:
    https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html#credential-plugins

[^cargo]: Kinda - just cargo!
