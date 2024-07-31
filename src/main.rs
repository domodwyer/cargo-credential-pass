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

use cargo_credential::{Action, CacheControl, Credential, CredentialResponse, RegistryInfo};
use pass::{PassKeychain, PassPath};

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
        _args: &[&str],
    ) -> Result<CredentialResponse, cargo_credential::Error> {
        let path = PassPath::from(registry);
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
