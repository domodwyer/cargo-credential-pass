use std::path::PathBuf;

use clap::{crate_name, CommandFactory, Parser};

use crate::pass::{self, PassKeychain, PassPath, PassPathBuilder};
use cargo_credential::{Action, CacheControl, Credential, CredentialResponse, RegistryInfo};

/// Convert [`pass::Error`] instances into RPC error responses.
impl From<pass::Error> for cargo_credential::Error {
    fn from(v: pass::Error) -> Self {
        use pass::Error;

        match v {
            Error::Exec(_)
            | Error::ExecNonZero { .. }
            | Error::EditNonZero(_)
            | Error::NonUtf8Password(_) => cargo_credential::Error::Other(v.into()),
        }
    }
}

/// A credential helper for cargo that reads registry tokens from the 'pass'
/// secret store.
///
/// Configure cargo to use this binary, and then run 'cargo login' to initialise
/// the default token.
///
/// See https://doc.rust-lang.org/cargo/reference/registry-authentication.html
/// for general cargo credential help.
///
///
#[derive(Parser, Debug)]
#[command(version, long_about, verbatim_doc_comment)]
pub(super) struct Config {
    path: Option<PathBuf>,

    /// A prefix to prepend to the returned token.
    ///
    /// This is useful for 3rd party cargo registries that expect an API token
    /// to be provided in the "Bearer {token}" format (provide "Bearer " as
    /// prefix).
    #[arg(long, verbatim_doc_comment)]
    prefix: Option<String>,
}

/// A request dispatcher for [`cargo_credential`].
///
/// A thin layer to translate [`cargo_credential::Action`] ops into
/// [`PassKeychain`] operations.
pub(super) struct Dispatch;

impl Credential for Dispatch {
    fn perform(
        &self,
        registry: &RegistryInfo<'_>,
        action: &Action<'_>,
        args: &[&str],
    ) -> Result<CredentialResponse, cargo_credential::Error> {
        let (path, config) = path_from_args(args, registry)?;
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
            Action::Get(_opts) => {
                let mut token = keychain.read_token(&path)?;

                // Apply a prefix if requested.
                if let Some(prefix) = config.prefix {
                    token = token.map(|v| format!("{prefix}{v}"))
                }

                Ok(CredentialResponse::Get {
                    token,
                    cache: CacheControl::Session,
                    operation_independent: true,
                })
            }

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
) -> Result<(PassPath, Config), cargo_credential::Error> {
    // Parse the arg input, inserting a dummy first argument for clap to use as
    // the bin name in any help text.
    let args = match Config::try_parse_from(
        std::iter::once(Config::command().get_bin_name().unwrap_or(crate_name!()))
            .chain(args.iter().copied()),
    ) {
        Ok(v) => v,
        Err(e) => {
            return Err(cargo_credential::Error::Other(
                format!(
                    "invalid arguments provided to cargo-credential-pass: \
					\n\n\t{e}\n\n \
					try running '{} --help' for allowed options.",
                    crate_name!(),
                )
                .into(),
            ));
        }
    };

    let mut p = PassPathBuilder::default();
    if let Some(name) = registry.name {
        p = p.with_name(name);
    }

    let path = match &args.path {
        Some(ref v) => v,
        None => return Ok((p.build(registry.index_url), args)),
    };

    // Disallow absolute paths, as they're always rooted under the password
    // store dir.
    if path.is_absolute() {
        return Err(cargo_credential::Error::Other(
            format!(
                "{} cannot be configured with absolute \
            path, specify path relative to password store root",
                crate_name!()
            )
            .into(),
        ));
    }

    // A path that ends with a `/` is specifying a directory tokens are stored
    // in.
    if path.to_string_lossy().ends_with('/') {
        return Ok((p.under_dir(path.as_ref()).build(registry.index_url), args));
    }

    // Otherwise this path specifies the exact token file path to use.
    Ok((PassPath::new(path.clone()), args))
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
        let got = path_from_args(&[], &REG).expect("valid path").0.to_string();

        assert_eq!(got, "cargo-registry/bananas.token");
    }

    #[test]
    fn test_path_from_with_custom_path() {
        let got = path_from_args(&["tokens/go/here"], &REG)
            .expect("valid path")
            .0
            .to_string();

        assert_eq!(got, "tokens/go/here");
    }

    #[test]
    fn test_path_from_with_custom_dir() {
        let got = path_from_args(&["tokens/go/here/"], &REG)
            .expect("valid path")
            .0
            .to_string();

        assert_eq!(got, "tokens/go/here/bananas.token");
    }

    #[test]
    fn test_custom_path_with_prefix_reversed() {
        let (path, config) =
            path_from_args(&["--prefix", "platanos", "tokens/go/here"], &REG).expect("valid path");

        assert_eq!(path.to_string(), "tokens/go/here");
        assert_eq!(config.prefix.as_deref(), Some("platanos"));
    }

    #[test]
    fn test_custom_path_with_prefix() {
        let (path, config) =
            path_from_args(&["tokens/go/here", "--prefix", "platanos"], &REG).expect("valid path");

        assert_eq!(path.to_string(), "tokens/go/here");
        assert_eq!(config.prefix.as_deref(), Some("platanos"));
    }

    #[test]
    fn test_path_with_prefix() {
        let (path, config) = path_from_args(&["--prefix", "platanos"], &REG).expect("valid path");

        assert_eq!(path.to_string(), "cargo-registry/bananas.token");
        assert_eq!(config.prefix.as_deref(), Some("platanos"));
    }
}
