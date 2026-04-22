//! Persistent memory: a directory of markdown files the agent can read as
//! long-lived context.
//!
//! Shape:
//! - `~/.local/share/thclaws/memory/MEMORY.md` — index. Free-form markdown;
//!   the typical pattern is one line per entry pointing at a topic file.
//! - `~/.local/share/thclaws/memory/<slug>.md` — individual entries with
//!   optional YAML-ish frontmatter (`name`, `description`, `type`) followed
//!   by a body. Frontmatter is parsed loosely: `---` fences, `key: value`
//!   lines inside. Anything outside the fences goes in `body`.
//!
//! Phase 13b is **read-only**: the REPL lists / reads entries and the agent
//! includes a short summary in the system prompt. Writes are a future concern
//! (maybe a `Memory` tool that goes through the permission gate).

use crate::error::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEntry {
    /// File stem, e.g. `user_role` for `user_role.md`.
    pub name: String,
    pub description: String,
    /// Frontmatter `type` field, if present (e.g. `user`, `feedback`, `project`).
    pub memory_type: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct MemoryStore {
    pub root: PathBuf,
}

impl MemoryStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Preferred path (project-scoped): `./.thclaws/memory/`.
    /// Falls back — in order — to the old user-level Claude-Code-compatible
    /// per-project dirs, then to the user-global `~/.local/share/thclaws/memory/`.
    pub fn default_path() -> Option<PathBuf> {
        // Project-scoped: if we're inside a thClaws project (./.thclaws/
        // exists), keep memory with the project. Create the memory/ dir as
        // needed.
        if let Ok(cwd) = std::env::current_dir() {
            let project_root = cwd.join(".thclaws");
            if project_root.is_dir() {
                return Some(project_root.join("memory"));
            }
        }

        let home = crate::util::home_dir()?;

        // Legacy user-level per-project paths (read-only fallback).
        if let Ok(cwd) = std::env::current_dir() {
            let sanitized = cwd
                .to_string_lossy()
                .replace('/', "-")
                .trim_start_matches('-')
                .to_string();
            let claude_project = home
                .join(".claude/projects")
                .join(&sanitized)
                .join("memory");
            if claude_project.exists() {
                return Some(claude_project);
            }
            let thclaws_project = home
                .join(".thclaws/projects")
                .join(&sanitized)
                .join("memory");
            if thclaws_project.exists() {
                return Some(thclaws_project);
            }
        }

        // Global fallback.
        let thclaws = home.join(".local/share/thclaws/memory");
        if thclaws.exists() {
            return Some(thclaws);
        }
        Some(thclaws)
    }

    /// Free-form contents of `MEMORY.md` (the index file), or `None` if missing.
    pub fn index(&self) -> Option<String> {
        std::fs::read_to_string(self.root.join("MEMORY.md")).ok()
    }

    /// List all `*.md` files in the root (excluding `MEMORY.md`), parsed as
    /// `MemoryEntry`. Sorted by name. Returns empty vec if the root is missing.
    pub fn list(&self) -> Result<Vec<MemoryEntry>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.root)?.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name == "MEMORY.md" || !name.ends_with(".md") {
                continue;
            }
            if let Some(parsed) = parse_entry_file(&path) {
                out.push(parsed);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Read one entry by file-stem name (e.g. `user_role`).
    pub fn get(&self, name: &str) -> Option<MemoryEntry> {
        parse_entry_file(&self.root.join(format!("{name}.md")))
    }

    /// Produce a full memory section suitable for appending to a system prompt.
    /// Each entry becomes a `## name` block with its description and body, so
    /// the model can use the contents directly — not just know that the entry
    /// exists. Returns `None` when there's nothing to say.
    pub fn system_prompt_section(&self) -> Option<String> {
        let entries = self.list().ok()?;
        let index = self.index().and_then(|s| {
            let t = s.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        });
        if entries.is_empty() && index.is_none() {
            return None;
        }

        let mut parts: Vec<String> = Vec::new();
        if let Some(index) = index {
            parts.push(format!("## Index\n{index}"));
        }
        for e in &entries {
            let mut section = format!("## {}", e.name);
            if let Some(ty) = &e.memory_type {
                section.push_str(&format!(" ({ty})"));
            }
            if !e.description.is_empty() {
                section.push_str(&format!("\n_{}_", e.description));
            }
            let body = e.body.trim();
            if !body.is_empty() {
                section.push_str("\n\n");
                section.push_str(body);
            }
            parts.push(section);
        }
        Some(parts.join("\n\n"))
    }
}

fn parse_entry_file(path: &Path) -> Option<MemoryEntry> {
    let contents = std::fs::read_to_string(path).ok()?;
    let name = path.file_stem()?.to_string_lossy().into_owned();
    let (front, body) = parse_frontmatter(&contents);
    let description = front.get("description").cloned().unwrap_or_default();
    let memory_type = front.get("type").cloned();
    Some(MemoryEntry {
        name,
        description,
        memory_type,
        body,
    })
}

/// Parse YAML-ish frontmatter between `---` fences at the start of the file.
/// Anything else goes in `body`. Intentionally permissive — missing fences,
/// trailing whitespace, and non-`key: value` lines inside the block are all OK.
pub fn parse_frontmatter(s: &str) -> (HashMap<String, String>, String) {
    let mut map = HashMap::new();

    // Must open with `---` on the first line.
    let mut lines = s.lines();
    let Some(first) = lines.next() else {
        return (map, String::new());
    };
    if first.trim() != "---" {
        return (map, s.to_string());
    }

    let mut fm_lines: Vec<&str> = Vec::new();
    let mut closed = false;
    for line in lines.by_ref() {
        if line.trim() == "---" {
            closed = true;
            break;
        }
        fm_lines.push(line);
    }
    if !closed {
        return (map, s.to_string());
    }

    for line in fm_lines {
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    // Remaining iterator is the body.
    let body: String = lines
        .collect::<Vec<_>>()
        .join("\n")
        .trim_start()
        .to_string();
    (map, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn parse_frontmatter_extracts_fields_and_body() {
        let s = "---\nname: foo\ndescription: a thing\ntype: user\n---\nbody text\nmore body";
        let (front, body) = parse_frontmatter(s);
        assert_eq!(front.get("name").map(String::as_str), Some("foo"));
        assert_eq!(
            front.get("description").map(String::as_str),
            Some("a thing")
        );
        assert_eq!(front.get("type").map(String::as_str), Some("user"));
        assert_eq!(body, "body text\nmore body");
    }

    #[test]
    fn parse_frontmatter_missing_fences_returns_body_as_is() {
        let s = "no frontmatter here";
        let (front, body) = parse_frontmatter(s);
        assert!(front.is_empty());
        assert_eq!(body, s);
    }

    #[test]
    fn parse_frontmatter_unclosed_fence_is_body() {
        let s = "---\nname: foo\nno closing fence";
        let (front, body) = parse_frontmatter(s);
        assert!(front.is_empty());
        assert_eq!(body, s);
    }

    #[test]
    fn list_returns_empty_when_missing() {
        let dir = tempdir().unwrap();
        let store = MemoryStore::new(dir.path().join("nonexistent"));
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn list_skips_memory_md_index_and_non_md_files() {
        let dir = tempdir().unwrap();
        let store = MemoryStore::new(dir.path().to_path_buf());
        write(&store.root.join("MEMORY.md"), "# index");
        write(&store.root.join("scratch.txt"), "not markdown");
        write(
            &store.root.join("user.md"),
            "---\ndescription: who I am\ntype: user\n---\nbody",
        );
        let entries = store.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "user");
        assert_eq!(entries[0].description, "who I am");
        assert_eq!(entries[0].memory_type.as_deref(), Some("user"));
    }

    #[test]
    fn get_reads_single_entry_by_name() {
        let dir = tempdir().unwrap();
        let store = MemoryStore::new(dir.path().to_path_buf());
        write(
            &store.root.join("proj.md"),
            "---\ndescription: current sprint\ntype: project\n---\nsprint body",
        );
        let entry = store.get("proj").unwrap();
        assert_eq!(entry.name, "proj");
        assert_eq!(entry.description, "current sprint");
        assert_eq!(entry.memory_type.as_deref(), Some("project"));
        assert_eq!(entry.body, "sprint body");
    }

    #[test]
    fn get_missing_returns_none() {
        let dir = tempdir().unwrap();
        let store = MemoryStore::new(dir.path().to_path_buf());
        assert!(store.get("nope").is_none());
    }

    #[test]
    fn list_sorts_by_name() {
        let dir = tempdir().unwrap();
        let store = MemoryStore::new(dir.path().to_path_buf());
        write(&store.root.join("b.md"), "---\ndescription: second\n---\n");
        write(&store.root.join("a.md"), "---\ndescription: first\n---\n");
        let names: Vec<String> = store.list().unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn system_prompt_section_omits_when_empty_and_no_index() {
        let dir = tempdir().unwrap();
        let store = MemoryStore::new(dir.path().to_path_buf());
        std::fs::create_dir_all(&store.root).unwrap();
        assert!(store.system_prompt_section().is_none());
    }

    #[test]
    fn system_prompt_section_renders_full_bodies() {
        let dir = tempdir().unwrap();
        let store = MemoryStore::new(dir.path().to_path_buf());
        write(&store.root.join("MEMORY.md"), "- [foo](foo.md) — hook line");
        write(
            &store.root.join("foo.md"),
            "---\ndescription: foo entry\ntype: user\n---\nActual body content goes here.",
        );
        write(
            &store.root.join("bar.md"),
            "---\n---\njust a body, no frontmatter",
        );

        let section = store.system_prompt_section().unwrap();
        // Index is rendered
        assert!(section.contains("## Index"));
        assert!(section.contains("hook line"));
        // Each entry becomes its own ## section
        assert!(section.contains("## foo"));
        assert!(section.contains("(user)")); // type annotation
        assert!(section.contains("_foo entry_")); // description
        assert!(section.contains("Actual body content goes here."));
        // Body-only entry (no description)
        assert!(section.contains("## bar"));
        assert!(section.contains("just a body"));
    }
}
