//! OAuth 2.1 + PKCE for MCP HTTP servers.
//!
//! Flow (per MCP spec / RFC 9728):
//!
//!   1. POST to MCP server without auth → 401 + WWW-Authenticate header
//!      containing `resource_metadata` URL.
//!   2. GET `/.well-known/oauth-protected-resource` → `authorization_servers[]`.
//!   3. GET `<auth-server>/.well-known/oauth-authorization-server` → RFC 8414
//!      metadata (authorize_endpoint, token_endpoint, etc.).
//!   4. Generate PKCE code_verifier + code_challenge.
//!   5. Open browser to `authorize_endpoint` with redirect to a local
//!      ephemeral HTTP server.
//!   6. User consents; browser redirects to our callback with `?code=...`.
//!   7. Exchange code + code_verifier for access_token + refresh_token.
//!   8. Store tokens to `~/.config/thclaws/oauth_tokens.json`.
//!   9. Attach `Authorization: Bearer <at>` to every subsequent MCP POST.
//!  10. On 401 during a session, try refresh_token → new access_token.

use crate::error::{Error, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

const CALLBACK_PORT_START: u16 = 19150;
const CALLBACK_PORT_END: u16 = 19160;
const CLIENT_ID: &str = "thclaws";

// ── Token storage ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenStore {
    /// Keyed by MCP server URL (the resource endpoint, not the auth server).
    pub tokens: HashMap<String, TokenEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_endpoint: String,
    /// Unix timestamp when the access token expires (0 = unknown).
    pub expires_at: u64,
    /// Origin (scheme+host+port) of the authorization server that issued
    /// this token. Used on retrieval to reject token reuse if an attacker
    /// swaps the MCP server's OAuth discovery to point at a different
    /// authorization server. `None` on entries saved before this field
    /// existed; such entries are treated as unvalidated and re-auth is
    /// forced.
    #[serde(default)]
    pub authorization_server: Option<String>,
}

impl TokenStore {
    fn path() -> Option<PathBuf> {
        let home = std::env::var("HOME").ok()?;
        Some(PathBuf::from(home).join(".config/thclaws/oauth_tokens.json"))
    }

    pub fn load() -> Self {
        Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Serialise + write atomically with `0600` permissions on Unix so
    /// other users / processes on the machine can't read cached refresh
    /// tokens. On Windows we rely on the default per-user ACL.
    pub fn save(&self) {
        let Some(path) = Self::path() else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let contents = serde_json::to_string_pretty(self).unwrap_or_default();

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Open the file with 0600 explicitly on creation. If the
            // file already exists with a more-permissive mode, tighten
            // it defensively.
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
            {
                use std::io::Write;
                let _ = f.write_all(contents.as_bytes());
            }
            // Belt-and-suspenders: even if the file pre-existed with a
            // looser mode, clamp it now.
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&path, perms);
            }
        }

        #[cfg(not(unix))]
        {
            let _ = std::fs::write(&path, &contents);
        }
    }

    pub fn get(&self, server_url: &str) -> Option<&TokenEntry> {
        self.tokens.get(server_url)
    }

    /// Retrieve a cached token entry only if its authorization server
    /// matches the currently-discovered one. Callers that just did
    /// OAuth discovery can pass the `expected_as_origin` to defend
    /// against cross-server token reuse (e.g. DNS hijack swapping the
    /// OAuth server underneath a previously-trusted MCP URL).
    pub fn get_validated(&self, server_url: &str, expected_as_origin: &str) -> Option<&TokenEntry> {
        let entry = self.tokens.get(server_url)?;
        match entry.authorization_server.as_deref() {
            Some(origin) if origin == expected_as_origin => Some(entry),
            _ => None,
        }
    }

    pub fn set(&mut self, server_url: &str, entry: TokenEntry) {
        self.tokens.insert(server_url.to_string(), entry);
        self.save();
    }

    pub fn remove(&mut self, server_url: &str) {
        self.tokens.remove(server_url);
        self.save();
    }
}

// ── Discovery ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct OAuthMetadata {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Vec<String>,
    /// Origin (scheme://host[:port]) of the authorization server that
    /// advertised these endpoints. Cached alongside issued tokens so a
    /// later discovery that points at a *different* AS cannot silently
    /// reuse a previously-issued token.
    pub authorization_server_origin: String,
}

/// Extract a scheme+host+port origin from a URL string. Returns the
/// trimmed input if parsing fails so callers always get a non-empty
/// fingerprint.
fn origin_of(url_str: &str) -> String {
    match url::Url::parse(url_str) {
        Ok(u) => {
            let host = u.host_str().unwrap_or("");
            match u.port() {
                Some(p) => format!("{}://{}:{}", u.scheme(), host, p),
                None => format!("{}://{}", u.scheme(), host),
            }
        }
        Err(_) => url_str.trim_end_matches('/').to_string(),
    }
}

/// Discover the OAuth authorization server for an MCP HTTP endpoint.
/// Returns (resource_metadata_url, auth_server_url, metadata).
pub async fn discover(client: &Client, mcp_url: &str) -> Result<OAuthMetadata> {
    // Step 1: derive the server origin from the MCP URL and fetch the
    // resource metadata at the well-known path. The well-known document
    // lives at the server ROOT, not under the MCP path.
    //   https://mcp.artech.cloud/mcp/  →  https://mcp.artech.cloud
    let origin = match url::Url::parse(mcp_url) {
        Ok(u) => format!("{}://{}", u.scheme(), u.host_str().unwrap_or("localhost")),
        Err(_) => mcp_url
            .trim_end_matches('/')
            .rsplit_once("/mcp")
            .map(|(base, _)| base.to_string())
            .unwrap_or_else(|| mcp_url.trim_end_matches('/').to_string()),
    };
    let resource_meta_url = format!("{origin}/.well-known/oauth-protected-resource");
    eprintln!("\x1b[2m[oauth] fetching {resource_meta_url}\x1b[0m");

    let resource_resp = client
        .get(&resource_meta_url)
        .send()
        .await
        .map_err(|e| Error::Provider(format!("oauth discovery: {e}")))?;
    let resource: Value = resource_resp
        .json()
        .await
        .map_err(|e| Error::Provider(format!("oauth resource metadata: {e}")))?;

    let auth_server = resource
        .get("authorization_servers")
        .and_then(|a| a.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::Provider("oauth: no authorization_servers in resource metadata".into())
        })?
        .to_string();

    // Step 2: fetch the auth server's RFC 8414 metadata.
    let meta_url = format!(
        "{}/.well-known/oauth-authorization-server",
        auth_server.trim_end_matches('/')
    );
    let meta_resp = client
        .get(&meta_url)
        .send()
        .await
        .map_err(|e| Error::Provider(format!("oauth server metadata: {e}")))?;
    let meta: Value = meta_resp
        .json()
        .await
        .map_err(|e| Error::Provider(format!("oauth server metadata json: {e}")))?;

    let authorization_endpoint = meta
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Provider("missing authorization_endpoint".into()))?
        .to_string();
    let token_endpoint = meta
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Provider("missing token_endpoint".into()))?
        .to_string();
    let registration_endpoint = meta
        .get("registration_endpoint")
        .and_then(|v| v.as_str())
        .map(String::from);
    let scopes_supported: Vec<String> = meta
        .get("scopes_supported")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let authorization_server_origin = origin_of(&auth_server);

    Ok(OAuthMetadata {
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        scopes_supported,
        authorization_server_origin,
    })
}

// ── PKCE ─────────────────────────────────────────────────────────────

/// Fill `buf` with cryptographically-random bytes. OAuth state + PKCE
/// security depends on this — if the CSPRNG is unavailable we hard-fail
/// rather than silently degrading to a timestamp-derived value that an
/// attacker on the same machine could predict within microseconds.
fn secure_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| {
        Error::Provider(format!(
            "OS CSPRNG unavailable for OAuth security: {e}. Refusing to proceed."
        ))
    })
}

fn generate_pkce() -> Result<(String, String)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let mut verifier_bytes = [0u8; 32];
    secure_random(&mut verifier_bytes)?;
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    Ok((code_verifier, code_challenge))
}

/// 128-bit (16-byte) random token encoded as URL-safe base64. Used for
/// the OAuth `state` parameter. 64 bits (prior implementation) was below
/// the RFC 6234 recommendation and brute-force / precompute-feasible.
fn generate_state() -> Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut bytes = [0u8; 16];
    secure_random(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

// ── Authorization flow ───────────────────────────────────────────────

/// Run the full OAuth 2.1 + PKCE browser flow. Opens a browser, waits for
/// the callback on a local ephemeral HTTP server, exchanges the code for
/// tokens, and returns a `TokenEntry`. The caller is responsible for storing
/// it in the `TokenStore`.
pub async fn authorize(
    client: &Client,
    meta: &OAuthMetadata,
    _mcp_url: &str,
) -> Result<TokenEntry> {
    let (code_verifier, code_challenge) = generate_pkce()?;
    let state = generate_state()?;

    // Find a free local port for the callback server.
    let listener = find_listener().await?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::Provider(format!("callback addr: {e}")))?
        .port();
    let redirect_uri = format!("http://localhost:{port}/callback");

    // Build the authorization URL.
    let scope = if meta.scopes_supported.is_empty() {
        "hosting:read hosting:write deploy:write".to_string()
    } else {
        meta.scopes_supported.join(" ")
    };
    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}\
         &code_challenge={}&code_challenge_method=S256",
        meta.authorization_endpoint,
        urlencoding::encode(CLIENT_ID),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scope),
        urlencoding::encode(&state),
        urlencoding::encode(&code_challenge),
    );

    eprintln!("\x1b[36m[oauth] opening browser for authorization…\x1b[0m");
    open_browser(&auth_url);

    // Wait for the callback.
    let code = wait_for_callback(listener, &state).await?;

    eprintln!("\x1b[36m[oauth] exchanging code for tokens…\x1b[0m");

    // Exchange code for tokens.
    let token_resp = client
        .post(&meta.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", CLIENT_ID),
            ("code_verifier", &code_verifier),
        ])
        .send()
        .await
        .map_err(|e| Error::Provider(format!("token exchange: {e}")))?;

    if !token_resp.status().is_success() {
        let text = token_resp.text().await.unwrap_or_default();
        return Err(Error::Provider(format!("token exchange failed: {text}")));
    }

    let tv: Value = token_resp
        .json()
        .await
        .map_err(|e| Error::Provider(format!("token json: {e}")))?;

    let access_token = tv
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Provider("token response missing access_token".into()))?
        .to_string();
    let refresh_token = tv
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let expires_in = tv
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    eprintln!(
        "\x1b[32m[oauth] authorized successfully\x1b[0m\n\x1b[2m  token ({}B): {}…\n  has_refresh: {}\x1b[0m",
        access_token.len(),
        &access_token[..access_token.len().min(40)],
        refresh_token.is_some()
    );

    Ok(TokenEntry {
        access_token,
        refresh_token,
        token_endpoint: meta.token_endpoint.clone(),
        expires_at: now + expires_in,
        authorization_server: Some(meta.authorization_server_origin.clone()),
    })
}

/// Try to refresh an expired token. Returns a new TokenEntry on success.
pub async fn refresh(client: &Client, entry: &TokenEntry) -> Result<TokenEntry> {
    let refresh_token = entry
        .refresh_token
        .as_ref()
        .ok_or_else(|| Error::Provider("no refresh_token available".into()))?;

    let resp = client
        .post(&entry.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|e| Error::Provider(format!("token refresh: {e}")))?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(Error::Provider(format!("token refresh failed: {text}")));
    }

    let tv: Value = resp
        .json()
        .await
        .map_err(|e| Error::Provider(format!("refresh json: {e}")))?;

    let access_token = tv
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Provider("refresh response missing access_token".into()))?
        .to_string();
    let new_refresh = tv
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| entry.refresh_token.clone());
    let expires_in = tv
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(TokenEntry {
        access_token,
        refresh_token: new_refresh,
        token_endpoint: entry.token_endpoint.clone(),
        expires_at: now + expires_in,
        authorization_server: entry.authorization_server.clone(),
    })
}

/// Check whether a token entry is still valid (with a 60 s margin).
pub fn is_valid(entry: &TokenEntry) -> bool {
    if entry.access_token.is_empty() {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    entry.expires_at == 0 || now + 60 < entry.expires_at
}

// ── Helpers ──────────────────────────────────────────────────────────

async fn find_listener() -> Result<tokio::net::TcpListener> {
    for port in CALLBACK_PORT_START..=CALLBACK_PORT_END {
        if let Ok(l) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            return Ok(l);
        }
    }
    Err(Error::Provider(format!(
        "oauth: could not bind callback server on ports {CALLBACK_PORT_START}-{CALLBACK_PORT_END}"
    )))
}

async fn wait_for_callback(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut stream, _addr) =
        tokio::time::timeout(std::time::Duration::from_secs(300), listener.accept())
            .await
            .map_err(|_| {
                Error::Provider("oauth: timed out waiting for browser callback (5 min)".into())
            })?
            .map_err(|e| Error::Provider(format!("oauth accept: {e}")))?;

    let mut buf = vec![0u8; 4096];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| Error::Provider(format!("oauth read: {e}")))?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse the GET /callback?code=...&state=... line.
    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("");
    let query = path.split('?').nth(1).unwrap_or("");
    let params: HashMap<&str, &str> = query
        .split('&')
        .filter_map(|p| {
            let mut kv = p.splitn(2, '=');
            Some((kv.next()?, kv.next().unwrap_or("")))
        })
        .collect();

    // Send a user-friendly response.
    let html = "<html><body style='font-family:system-ui;text-align:center;margin-top:80px'>\
                <h2>Authorized!</h2><p>You can close this tab and return to thClaws.</p>\
                </body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    let _ = stream.write_all(response.as_bytes()).await;

    // Validate state.
    let state = *params.get("state").unwrap_or(&"");
    if state != expected_state {
        return Err(Error::Provider(format!(
            "oauth: state mismatch (CSRF protection). Expected {expected_state}, got {state}"
        )));
    }

    if let Some(error) = params.get("error") {
        let desc = params.get("error_description").unwrap_or(&"");
        return Err(Error::Provider(format!("oauth denied: {error} {desc}")));
    }

    params
        .get("code")
        .map(|c| c.to_string())
        .ok_or_else(|| Error::Provider("oauth: callback missing 'code' parameter".into()))
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", url])
            .spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct HomeGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: Option<String>,
        _dir: tempfile::TempDir,
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    fn scoped_home() -> HomeGuard {
        // Share the crate-wide env lock with kms tests to avoid racing
        // each other on HOME / cwd.
        let lock = crate::kms::test_env_lock();
        let prev = std::env::var("HOME").ok();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        HomeGuard {
            _lock: lock,
            prev,
            _dir: dir,
        }
    }

    fn sample_entry(issuer: Option<&str>) -> TokenEntry {
        TokenEntry {
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            token_endpoint: "https://as.example/token".into(),
            expires_at: 0,
            authorization_server: issuer.map(String::from),
        }
    }

    #[test]
    fn state_is_high_entropy_and_unique() {
        let a = generate_state().unwrap();
        let b = generate_state().unwrap();
        assert_ne!(a, b);
        // 16 bytes → base64url without padding = 22 chars
        assert!(a.len() >= 22);
        assert!(b.len() >= 22);
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_file_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let _home = scoped_home();
        let mut store = TokenStore::default();
        store.set(
            "https://mcp.example",
            sample_entry(Some("https://as.example")),
        );
        let path = TokenStore::path().unwrap();
        assert!(path.exists(), "token file should have been created");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file must be 0600, got {mode:o}");
    }

    #[test]
    fn get_validated_rejects_mismatched_authorization_server() {
        let _home = scoped_home();
        let mut store = TokenStore::default();
        store.set(
            "https://mcp.example",
            sample_entry(Some("https://as-legit.example")),
        );
        // Same URL, different AS origin → must be treated as missing.
        assert!(store
            .get_validated("https://mcp.example", "https://as-legit.example")
            .is_some());
        assert!(store
            .get_validated("https://mcp.example", "https://as-evil.example")
            .is_none());
    }

    #[test]
    fn get_validated_rejects_legacy_entries_without_issuer() {
        let _home = scoped_home();
        let mut store = TokenStore::default();
        store.set("https://mcp.example", sample_entry(None));
        assert!(store
            .get_validated("https://mcp.example", "https://as.example")
            .is_none());
        // But the raw `get` still returns it so we can garbage-collect.
        assert!(store.get("https://mcp.example").is_some());
    }
}
