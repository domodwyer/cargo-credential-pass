use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use tempfile::{tempdir, TempDir};

/// A handle to a temporary, isolated GPG keychain containing a single GPG key
/// for `bananas@itsallbroken.com`.
///
/// When dropped the GPG env is deleted.
#[derive(Debug)]
pub(crate) struct GpgHandle {
    dir: TempDir,
}

impl GpgHandle {
    /// Set the appropriate env config to cause the test GPG env to be used by
    /// `c`.
    pub(crate) fn set_scope<'a>(
        &self,
        c: &'a mut std::process::Command,
    ) -> &'a mut std::process::Command {
        c.env("GNUPGHOME", &self.home_dir())
    }

    pub(crate) fn home_dir(&self) -> &Path {
        self.dir.path()
    }
}

impl Default for GpgHandle {
    fn default() -> Self {
        let dir = tempdir().expect("cannot create temp directory");

        let mut child = Command::new("gpg")
            .env("GNUPGHOME", dir.path())
            .arg("--gen-key")
            .arg("--batch")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdin(Stdio::piped())
            .spawn()
            .expect("failed to spawn pass init command");

        let mut stdin = child.stdin.take().expect("no stdin");
        std::thread::spawn(move || {
            stdin.write_all(
                "%no-protection
Key-Type: eddsa
Key-Curve: Ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: Curve25519
Subkey-Usage: encrypt
Name-Real: Cargo Test Key
Name-Email: bananas@itsallbroken.com
Expire-Date: 0"
                    .as_bytes(),
            )
        });

        let out = child.wait_with_output().expect("pass init exec failure");

        assert!(
            out.status.success(),
            "generating test gpg key failed - is gpg installed?"
        );

        eprintln!("gpg init complete: {}", dir.path().display());

        Self { dir }
    }
}
