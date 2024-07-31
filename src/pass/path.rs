use std::{
    ffi::{OsStr, OsString},
    fmt::Display,
};

use cargo_credential::RegistryInfo;

/// A `pass` path used to deterministically address a specific registry.
#[derive(Debug)]
pub(crate) struct PassPath(OsString);

impl PassPath {
    /// Construct a [`PassPath`] from the provided `name` if [`Some`], or
    /// deterministically derive one from `index_url` if [`None`].
    pub(crate) fn new(index_url: &str, name: Option<&str>) -> Self {
        let name = name.map(ToString::to_string).unwrap_or_else(|| {
            // Remove the sparse+ prefix from the URL if present, so that a
            // token is resolved for a registry regardless of the index protocol
            // used.
            let name = index_url.strip_prefix("sparse+").unwrap_or(index_url);
            normalise_url(name)
        });

        let path = format!("cargo-registry/{}.token", name);

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
        PassPath::new(v.index_url, v.name)
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
        let p = PassPath::new(
            "sparse+https://cargo.itsallbroken.com/index/",
            Some("bananas"),
        );

        assert_eq!(p.to_string(), "cargo-registry/bananas.token");
    }

    #[test]
    fn test_path_without_name_sparse() {
        let p = PassPath::new("sparse+https://cargo.itsallbroken.com/index/", None);

        assert_eq!(
            p.to_string(),
            "cargo-registry/https___cargo_itsallbroken_com_index_.token"
        );
    }

    #[test]
    fn test_path_without_name_non_sparse() {
        let p = PassPath::new("https://cargo.itsallbroken.com/index/", None);

        assert_eq!(
            p.to_string(),
            "cargo-registry/https___cargo_itsallbroken_com_index_.token"
        );
    }
}
