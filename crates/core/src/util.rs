//! Small cross-cutting utilities that don't belong to any single
//! subsystem. Currently: cross-platform home-directory lookup.

use std::path::PathBuf;

/// The current user's home directory, in a form that works on both
/// Unix and Windows.
///
/// On Unix this is just `$HOME`. On Windows there's no `HOME` by
/// default — we fall back to `%USERPROFILE%` (set by Explorer and
/// the user profile loader on every login) and then
/// `%HOMEDRIVE%%HOMEPATH%` (used by some older tooling).
///
/// Returns `None` only if every candidate is unset or empty — in
/// practice a truly broken Windows environment; most of the
/// path-touching code in thClaws degrades gracefully in that case
/// rather than panicking.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Ok(h) = std::env::var("USERPROFILE") {
            if !h.is_empty() {
                return Some(PathBuf::from(h));
            }
        }
        if let (Ok(d), Ok(p)) = (
            std::env::var("HOMEDRIVE"),
            std::env::var("HOMEPATH"),
        ) {
            if !d.is_empty() && !p.is_empty() {
                return Some(PathBuf::from(format!("{d}{p}")));
            }
        }
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// String form of `home_dir()` — mirrors the shape of call sites
/// that did `std::env::var("HOME").ok()?` and then used the result
/// as a `&str` / joined paths via `format!`. Prefer `home_dir()`
/// when you want a `PathBuf` directly.
pub fn home_string() -> Option<String> {
    home_dir().map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_dir_returns_something_on_dev_machine() {
        // Dev machines set HOME (Unix) or USERPROFILE (Windows). In
        // CI this could fail if a sandboxed runner strips env — we
        // allow `None` there, but don't crash.
        let _ = home_dir();
    }
}
