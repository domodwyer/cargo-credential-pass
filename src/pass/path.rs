use std::{
    ffi::{OsStr, OsString},
    fmt::Display,
    path::{Path, PathBuf},
};

use cargo_credential::RegistryInfo;

/// An initialiser of [`PassPath`] from configuration.
#[derive(Debug, Default)]
pub(crate) struct PassPathBuilder<'a, 'b> {
    /// Directory to store token relative to password store root.
    dir: Option<&'a Path>,

    /// Filename without extension.
    name: Option<&'b str>,
}

impl<'a, 'b> PassPathBuilder<'a, 'b> {
    /// Set the path relative to the password store root, under which the token
    /// is created.
    ///
    /// If not provided, tokens will be stored under the default path of
    /// `cargo-registry`.
    ///
    /// # Panics
    ///
    /// This call panics if an absolute path is provided. A relative path must
    /// be provided as the path will be interpreted relative to the password
    /// store root.
    #[expect(dead_code)]
    pub(crate) fn under_dir(mut self, dir: &'a Path) -> Self {
        assert!(dir.is_relative());

        self.dir = Some(dir);
        self
    }

    /// Set the name of the token, or deterministically derive it from the
    /// registry URL if not provided.
    pub(crate) fn with_name(mut self, name: &'b str) -> Self {
        self.name = Some(name);
        self
    }

    /// Instantiate a [`PassPath`] with the specified components.
    pub(crate) fn build(self, index_url: &str) -> PassPath {
        let name = self.name.map(ToString::to_string).unwrap_or_else(|| {
            // Remove the sparse+ prefix from the URL if present, so that a
            // token is resolved for a registry regardless of the index protocol
            // used.
            let name = index_url.strip_prefix("sparse+").unwrap_or(index_url);
            normalise_url(name)
        });

        let mut path = self.dir.map(ToOwned::to_owned).unwrap_or_else(|| {
            let mut p = PathBuf::new();
            p.push("cargo-registry");
            p
        });

        path.push(format!("{}.token", name));

        PassPath::new(path)
    }
}

/// A `pass` path used to deterministically address a specific registry.
#[derive(Debug)]
pub(crate) struct PassPath(OsString);

impl PassPath {
    /// Initialise a new [`PassPath`] instance that stores the token in the
    /// specified path.
    ///
    /// # Panics
    ///
    /// This call panics if an absolute path is provided. A relative path must
    /// be provided as the path will be interpreted relative to the password
    /// store root.
    pub(crate) fn new(path: PathBuf) -> Self {
        assert!(path.is_relative());

        Self(OsString::from(path))
    }
}

impl Display for PassPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.to_str().expect("invalid registry name").fmt(f)
    }
}

impl AsRef<OsStr> for PassPath {
    fn as_ref(&self) -> &OsStr {
        &self.0
    }
}

impl<'a> From<&'a RegistryInfo<'a>> for PassPath {
    fn from(v: &'a RegistryInfo<'a>) -> Self {
        let mut p = PassPathBuilder::default();

        // Use the provided name or infer one if not specified.
        if let Some(name) = v.name {
            p = p.with_name(name);
        }

        p.build(v.index_url)
    }
}

/// Replace any non-alphanumeric characters in `url` with an underscore.
fn normalise_url(url: &str) -> String {
    url.replace(|v| !char::is_alphanumeric(v), "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_with_name() {
        let p = PassPathBuilder::default()
            .with_name("bananas")
            .build("sparse+https://cargo.itsallbroken.com/index/");

        assert_eq!(p.to_string(), "cargo-registry/bananas.token");
    }

    #[test]
    fn test_path_without_name_sparse() {
        let p = PassPathBuilder::default().build("sparse+https://cargo.itsallbroken.com/index/");

        assert_eq!(
            p.to_string(),
            "cargo-registry/https___cargo_itsallbroken_com_index_.token"
        );
    }

    #[test]
    fn test_path_without_name_non_sparse() {
        let p = PassPathBuilder::default().build("https://cargo.itsallbroken.com/index/");

        assert_eq!(
            p.to_string(),
            "cargo-registry/https___cargo_itsallbroken_com_index_.token"
        );
    }

    #[test]
    fn test_path_under_dir() {
        let p = PassPathBuilder::default()
            .with_name("bananas")
            .under_dir(Path::new("platanos/are/good"))
            .build("sparse+https://cargo.itsallbroken.com/index/");

        assert_eq!(p.to_string(), "platanos/are/good/bananas.token");
    }

    #[test]
    fn test_path_under_dir_trailing_slash() {
        let p = PassPathBuilder::default()
            .with_name("bananas")
            .under_dir(Path::new("platanos/are/good/"))
            .build("sparse+https://cargo.itsallbroken.com/index/");

        assert_eq!(p.to_string(), "platanos/are/good/bananas.token");
    }

    #[should_panic(expected = "dir.is_relative()")]
    #[test]
    fn test_path_under_absolute_dir() {
        let p = PassPathBuilder::default()
            .with_name("bananas")
            .under_dir(Path::new("/root"))
            .build("sparse+https://cargo.itsallbroken.com/index/");

        assert_eq!(p.to_string(), "platanos/are/good/bananas.token");
    }
}
