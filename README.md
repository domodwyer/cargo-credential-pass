[![crates.io](https://img.shields.io/crates/v/cargo-credential-pass.svg)](https://crates.io/crates/cargo-credential-pass)

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

## (Optionally) Configure It

### Token Directory

You override where the tokens are stored in the password store, replacing the
the default `cargo-registry` subdir:

```toml
[registry]
global-credential-providers = ["cargo-credential-pass cargo-tokens/live/here/"]
```

Note the trailing `/` is important - it indicates the directory to be used for
storing tokens, and the filename will be automatically derived.

### Exact Token Path

A path without the trailing `/` will be interpreted as the exact token path
(inc. filename) to use.

This is helpful for setting per-registry token paths like below, but an exact
path can only be used by 1 registry:

```toml
[registries.my-work-registry]
credential-provider = ["cargo-credential-pass work/cargo-token.secret"]
```


[pass]: https://www.passwordstore.org/
[credential provider]:
    https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html
[Configure Cargo]:
    https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html#credential-plugins

[^cargo]: Kinda - only cargo required!
