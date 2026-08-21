use std::fmt;

use serde::{Deserialize, Deserializer};

/// A string that never prints itself.
///
/// The upstream API key flows through config, state and error paths; wrapping it
/// means an accidental `{:?}` in a log line or a panic message cannot leak it.
/// The inner value is only reachable through [`Secret::expose`], which is easy
/// to grep for during review.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Yields the wrapped secret. Call sites are deliberately conspicuous.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_renders_the_inner_value() {
        let s = Secret::new("super-secret-api-key");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(format!("{s}"), "***");
        assert!(!format!("{s:?} {s}").contains("super-secret"));
        assert_eq!(s.expose(), "super-secret-api-key");
    }
}
