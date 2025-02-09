#![allow(clippy::default_constructed_unit_structs)]

//   Copyright 2024 Dominic Dwyer (dom@itsallbroken.com)
//
//   Licensed under the Apache License, Version 2.0 (the "License"); you may not
//   use this file except in compliance with the License. You may obtain a copy
//   of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//   License for the specific language governing permissions and limitations
//   under the License.

use std::path::{Path, PathBuf};

use cargo_credential::{Action, CacheControl, Credential, CredentialResponse, RegistryInfo};
use pass::{PassKeychain, PassPath, PassPathBuilder};

mod pass;

/// Convert [`pass::Error`] instances into RPC error responses.
impl From<pass::Error> for cargo_credential::Error {
    fn from(v: pass::Error) -> Self {
        use pass::Error;

        match v {
            Error::Exec(_) | Error::ExecNonZero { .. } | Error::NonUtf8Password(_) => {
                cargo_credential::Error::Other(v.into())
            }
        }
    }
}

/// A request dispatcher for [`cargo_credential`].
///
/// A thin layer to translate [`cargo_credential::Action`] ops into
/// [`PassKeychain`] operations.
struct Dispatch;

impl Credential for Dispatch {
    fn perform(
        &self,
        registry: &RegistryInfo<'_>,
        action: &Action<'_>,
        args: &[&str],
    ) -> Result<CredentialResponse, cargo_credential::Error> {
        let path = path_from_args(args, registry)?;
        let keychain = PassKeychain::default();

        match action {
            // Prompt for a token (or use the one provided) and store it into
            // the password store.
            Action::Login(opts) => {
                match &opts.token {
                    Some(token) => keychain.upsert_token(&path, token),
                    None => keychain.edit_token(&path),
                }?;

                Ok(CredentialResponse::Login)
            }

            // Return a token for a specific registry, if one exists.
            Action::Get(_opts) => Ok(CredentialResponse::Get {
                token: keychain.read_token(&path)?,
                cache: CacheControl::Session,
                operation_independent: true,
            }),

            // Destroy the token in the password store.
            Action::Logout => {
                keychain.delete_token(&path)?;
                Ok(CredentialResponse::Logout)
            }
            _ => Err(cargo_credential::Error::OperationNotSupported),
        }
    }
}

/// Parse (potentially empty) `args` to construct a [`PassPath`].
///
///   1. If args is empty, return a [`PassPath`] derived from `registry`.
///   2. If args contains more than 1 entry, return an error.
///   3. If args contains exactly one entry, and starts with `/`, return an
///      error.
///   4. If args contains exactly one entry, and ends with `/`, return a
///      [`PassPath`] that uses this value as the directory under the password
///      store root where tokens are stored.
///   5. If args contains exactly one entry, and does not end with `/`, return a
///      [`PassPath`] that uses this exact value as the storage path for the
///      token.
fn path_from_args(
    args: &[&str],
    registry: &RegistryInfo<'_>,
) -> Result<PassPath, cargo_credential::Error> {
    let mut p = PassPathBuilder::default();
    if let Some(name) = registry.name {
        p = p.with_name(name);
    }

    // Accept exactly 0 or 1 arguments.
    let path = match args {
        [] => return Ok(p.build(registry.index_url)),
        [path] => path,
        [_, ..] => {
            return Err(cargo_credential::Error::Other(
                "too many arguments specified in cargo credential provider config".into(),
            ))
        }
    };

    // Disallow absolute paths, as they're always rooted under the password
    // store dir.
    if path.starts_with('/') {
        return Err(cargo_credential::Error::Other(
            "pass cargo credential provider cannot be configured with absolute \
            path, specify path relative to password store root"
                .into(),
        ));
    }

    // A path that ends with a `/` is specifying a directory tokens are stored
    // in.
    if path.ends_with('/') {
        return Ok(p.under_dir(Path::new(path)).build(registry.index_url));
    }

    // Otherwise this path specifies the exact token file path to use.
    Ok(PassPath::new(PathBuf::from(path.to_string())))
}

pub fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let args_str = args.iter().map(|v| v.as_str()).collect::<Vec<_>>();

    match args_str.as_slice() {
        [_, "--cargo-plugin"] => cargo_credential::main(Dispatch {}),
        _ => print_help(),
    }
}

fn print_help() {
    eprintln!("Hi there!");
    eprintln!();
    eprintln!(
        "This is a credential helper for cargo that reads registry \
                tokens from the 'pass' secret store."
    );
    eprintln!();
    eprintln!(
        "Configure cargo to use this binary, and then run 'cargo login \
        --token <mytoken>' to initialise it:"
    );
    eprintln!();
    eprintln!("\thttps://doc.rust-lang.org/cargo/reference/registry-authentication.html");
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    const REG: RegistryInfo = RegistryInfo {
        index_url: "http://itsallbroken.com/cargo",
        name: Some("bananas"),
        headers: vec![],
    };

    #[test]
    fn test_path_from_no_custom_path() {
        let got = path_from_args(&[], &REG).expect("valid path").to_string();

        assert_eq!(got, "cargo-registry/bananas.token");
    }

    #[test]
    fn test_path_from_with_custom_path() {
        let got = path_from_args(&["tokens/go/here"], &REG)
            .expect("valid path")
            .to_string();

        assert_eq!(got, "tokens/go/here");
    }

    #[test]
    fn test_path_from_with_custom_dir() {
        let got = path_from_args(&["tokens/go/here/"], &REG)
            .expect("valid path")
            .to_string();

        assert_eq!(got, "tokens/go/here/bananas.token");
    }
}
