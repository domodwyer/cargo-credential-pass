use std::{
    path::Path,
    process::{Command, Stdio},
};

use tempfile::{tempdir, TempDir};

use super::gpg::GpgHandle;

/// A temporary, isolated `pass` environment.
#[derive(Debug)]
pub(crate) struct PassHandle {
    dir: TempDir,
}

impl PassHandle {
    /// Construct a [`PassHandle`] env using the GPG environment and key from
    /// [`GpgHandle`].
    pub(crate) fn new(gpg: &GpgHandle) -> Self {
        let dir = tempdir().expect("failed to create tempdir");

        let _out = gpg
            .set_scope(
                Command::new("pass")
                    .env("PASSWORD_STORE_DIR", dir.path())
                    .arg("init")
                    .arg("bananas@itsallbroken.com")
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .stdin(Stdio::piped()),
            )
            .output()
            .expect("pass init failed - is pass installed?");

        eprintln!("pass init complete: {}", dir.path().display());

        Self { dir }
    }

    pub(crate) fn dir(&self) -> &Path {
        self.dir.path()
    }
}
