use std::{
    io::Write,
    process::{Command, Stdio},
};

use cargo_credential::Secret;
use thiserror::Error;

use super::PassPath;

/// Failures interacting with `pass`.
#[derive(Debug, Error)]
pub(crate) enum Error {
    /// Spawning a `pass` child process failed.
    #[error("error executing pass: {0}")]
    Exec(std::io::Error),

    /// `pass` was executed, but returned a non-zero error code..
    #[error("pass exited with a non-zero status code (stdout='{stdout}', stderr='{stderr}')")]
    ExecNonZero { stdout: String, stderr: String },

    /// The token read from `pass` is not a valid UTF-8 string.
    #[error("read invalid (non-utf8) token: {0}")]
    NonUtf8Password(#[from] std::string::FromUtf8Error),
}

impl From<std::process::Output> for Error {
    fn from(v: std::process::Output) -> Self {
        // Success isn't failure.
        assert!(!v.status.success());

        fn to_err_string(bytes: &[u8]) -> String {
            std::str::from_utf8(bytes)
                .expect("invalid utf8 in stderr")
                .trim_end()
                .to_string()
        }

        Self::ExecNonZero {
            stdout: to_err_string(&v.stdout),
            stderr: to_err_string(&v.stderr),
        }
    }
}

/// [`pass`] integration layer.
///
/// [`pass`]: https://www.passwordstore.org/
#[derive(Debug, Default)]
pub(crate) struct PassKeychain;

impl PassKeychain {
    /// Insert or overwrite the `path` to store `token`.
    pub(crate) fn upsert_token(&self, path: &PassPath, token: &Secret<&str>) -> Result<(), Error> {
        let mut child = Command::new("pass")
            .arg("insert")
            .arg("--force")
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .spawn()
            .map_err(Error::Exec)?;

        let mut stdin = child.stdin.take().expect("no stdin for pass child process");

        // Write the token to stdin.
        writeln!(stdin, "{}", token.as_ref().expose()).map_err(Error::Exec)?;

        // Write the repeat / confirmation.
        writeln!(stdin, "{}", token.as_ref().expose()).map_err(Error::Exec)?;

        // And wait for pass to exit.
        let output = child.wait_with_output().map_err(Error::Exec)?;

        if !output.status.success() {
            return Err(Error::from(output));
        }

        Ok(())
    }

    /// Pop up the user's `$EDITOR` to edit the token at `path`.
    pub(crate) fn edit_token(&self, path: &PassPath) -> Result<(), Error> {
        let output = Command::new("pass")
            .arg("edit")
            .arg(path)
            .output()
            .map_err(Error::Exec)?;

        if !output.status.success() {
            return Err(Error::from(output));
        }

        Ok(())
    }

    /// Delete the token at `path`.
    pub(crate) fn delete_token(&self, path: &PassPath) -> Result<(), Error> {
        let output = Command::new("pass")
            .arg("rm")
            .arg("--force")
            .arg(path)
            .output()
            .map_err(Error::Exec)?;

        if !output.status.success() {
            return Err(Error::from(output));
        }

        Ok(())
    }

    /// Read the token at `path`.
    pub(crate) fn read_token(&self, path: &PassPath) -> Result<Secret<String>, Error> {
        let output = Command::new("pass")
            .arg("show")
            .arg(path)
            .output()
            .map_err(Error::Exec)?;

        if !output.status.success() {
            return Err(Error::from(output));
        }

        let token = String::from_utf8(output.stdout)?;

        // Trim any trailing newline / whitespace.
        let token = token.trim();

        Ok(Secret::from(token.to_string()))
    }
}
