use std::path::{Path, PathBuf};

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
