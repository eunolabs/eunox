//! `eunox sign`: become a Web Bot Auth operator.
//!
//! - `init` generates an Ed25519 operator key and a small config in a state
//!   directory, and checks that a request it signs verifies.
//! - `request` signs one request (prints the headers, or sends it).
//! - `serve` serves the key directory, signing each response for the
//!   configured authority only.
//! - `export` writes the directory and its signed headers as static files for
//!   a CDN or static host, valid until a given time.
//!
//! The signing itself is `eunox_core::sign`. Keys are PKCS#8 PEM files,
//! the format `openssl genpkey -algorithm ed25519` writes, created with mode
//! 0600 and never printed. A secret manager can supply the key instead, as
//! PEM text in `EUNOX_SIGN_KEY` or a file named by `EUNOX_SIGN_KEY_FILE`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use eunox_core::{
    DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, Key, OperatorKey, Outcome, Request, RequestToSign,
    SignedDirectory, SignedHeaders, VerifyOptions, sign_directory, sign_request, verify,
};
use eunox_directory::unix_now;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpListener;

/// Default state directory.
pub const DEFAULT_DIR: &str = "eunox-sign";
/// Default `serve` address.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8050";
/// Default directory `Cache-Control` max-age. Key rotation waits this long
/// between steps, so it's kept shorter than the draft's one-day example.
pub const DEFAULT_MAX_AGE: u64 = 3600;
/// Default lifetime of a signed request.
pub const DEFAULT_REQUEST_LIFETIME: i64 = 60;
/// Default validity of an exported directory, in days.
pub const DEFAULT_EXPORT_DAYS: u64 = 7;
/// Signature label used on requests.
pub const LABEL: &str = "sig1";

const CONFIG_FILE: &str = "sign.toml";
const KEYS_DIR: &str = "keys";

/// Usage text for `eunox sign`.
pub const USAGE: &str = "\
usage:
  eunox sign init --origin https://agent.example [--signature-agent URL]
      generate an operator key; the directory is to be served at the origin's
      /.well-known/http-message-signatures-directory
  eunox sign request URL [--send] [--lifetime SECS]
      sign a GET to URL and print the headers, or send it with --send
  eunox sign serve [--listen ADDR] [--max-age SECS]
      serve the signed key directory over HTTP, behind your TLS terminator
      (default 0.0.0.0:8050)
  eunox sign export --out DIR [--days N] [--max-age SECS]
      write the directory and a _headers file for a static host; re-run
      before the printed expiry

every command takes --dir DIR, the state directory (EUNOX_SIGN_DIR, default ./eunox-sign).
EUNOX_SIGN_KEY (PEM text) or EUNOX_SIGN_KEY_FILE replaces the keys in DIR/keys.
";

/// Run `eunox sign ARGS`.
pub async fn main(args: &[String]) -> Result<(), String> {
    let Some((cmd, rest)) = args.split_first() else {
        return Err(format!("missing command\n\n{USAGE}"));
    };
    match cmd.as_str() {
        "init" => {
            let f = Flags::parse(rest, &["--dir", "--origin", "--signature-agent"], &[])?;
            let origin = f.value("--origin").ok_or("init needs --origin")?;
            let report = init(&f.dir(), origin, f.value("--signature-agent"))?;
            print!("{report}");
            Ok(())
        }
        "request" => {
            let f = Flags::parse(rest, &["--dir", "--lifetime"], &["--send"])?;
            let [url] = f.positional.as_slice() else {
                return Err(format!("request needs one URL\n\n{USAGE}"));
            };
            let lifetime = f.number("--lifetime", DEFAULT_REQUEST_LIFETIME)?;
            let state = State::load(&f.dir())?;
            let headers = state.sign_request(url, unix_now(), lifetime, &nonce()?)?;
            if f.has("--send") {
                send(url, &headers).await
            } else {
                print!("{}", header_lines(&headers));
                Ok(())
            }
        }
        "serve" => {
            let f = Flags::parse(rest, &["--dir", "--listen", "--max-age"], &[])?;
            let max_age = f.number("--max-age", DEFAULT_MAX_AGE)?;
            let state = State::load(&f.dir())?;
            let listen = f
                .value("--listen")
                .map(str::to_owned)
                .or_else(|| env("EUNOX_SIGN_LISTEN"))
                .unwrap_or_else(|| DEFAULT_LISTEN.into());
            let listener = TcpListener::bind(&listen)
                .await
                .map_err(|e| format!("{listen}: {e}"))?;
            let addr = listener.local_addr().map_err(|e| e.to_string())?;
            eprintln!(
                "eunox sign: serving {} keys for {} on http://{addr}{DIRECTORY_PATH}",
                state.keys.len(),
                state.authority
            );
            serve(listener, Arc::new(state), max_age)
                .await
                .map_err(|e| e.to_string())
        }
        "export" => {
            let f = Flags::parse(rest, &["--dir", "--out", "--days", "--max-age"], &[])?;
            let out = f.value("--out").ok_or("export needs --out DIR")?;
            let days = f.number("--days", DEFAULT_EXPORT_DAYS)?;
            let max_age = f.number("--max-age", DEFAULT_MAX_AGE)?;
            let state = State::load(&f.dir())?;
            let report = export(&state, Path::new(out), unix_now(), days, max_age)?;
            print!("{report}");
            Ok(())
        }
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

/// `sign.toml`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignConfig {
    /// `https://host[:port]`, where the directory is served.
    pub origin: String,
    /// The `Signature-Agent` value requests carry. Defaults to the
    /// directory's well-known URL, which the current draft resolves directly
    /// as a JWK Set and binds to the domain. Earlier drafts and some
    /// deployments send the bare origin instead.
    pub signature_agent: String,
}

/// A loaded state directory: config and keys.
pub struct State {
    /// The config.
    pub config: SignConfig,
    /// Authority the directory is served at (from the origin).
    pub authority: String,
    /// Every published key, ordered by key id.
    pub keys: Vec<OperatorKey>,
}

impl State {
    /// Load `dir`, with `EUNOX_SIGN_KEY` or `EUNOX_SIGN_KEY_FILE` replacing
    /// its keys when set.
    pub fn load(dir: &Path) -> Result<Self, String> {
        let override_key = match (env("EUNOX_SIGN_KEY"), env("EUNOX_SIGN_KEY_FILE")) {
            (Some(_), Some(_)) => {
                return Err("set EUNOX_SIGN_KEY or EUNOX_SIGN_KEY_FILE, not both".into());
            }
            (Some(pem), None) => Some(parse_key(&pem).map_err(|e| format!("EUNOX_SIGN_KEY: {e}"))?),
            (None, Some(path)) => Some(read_key(Path::new(&path))?),
            (None, None) => None,
        };
        Self::load_with(dir, override_key)
    }

    /// Load `dir`, with `key` replacing its keys if given.
    pub fn load_with(dir: &Path, key: Option<OperatorKey>) -> Result<Self, String> {
        let path = dir.join(CONFIG_FILE);
        let text = fs::read_to_string(&path).map_err(|e| {
            format!(
                "{}: {e} (run `eunox sign init` first, or pass --dir)",
                path.display()
            )
        })?;
        let config: SignConfig =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let authority = origin_authority(&config.origin)?;
        let keys = match key {
            Some(k) => vec![k],
            None => read_keys(&dir.join(KEYS_DIR))?,
        };
        if keys.is_empty() {
            return Err(format!("no keys in {}", dir.join(KEYS_DIR).display()));
        }
        Ok(Self {
            config,
            authority,
            keys,
        })
    }

    /// The key requests are signed with. Rotation isn't built yet, so there
    /// has to be exactly one.
    pub fn signing_key(&self) -> Result<&OperatorKey, String> {
        match self.keys.as_slice() {
            [k] => Ok(k),
            _ => Err(format!(
                "{} keys published; signing needs exactly one until rotation is built",
                self.keys.len()
            )),
        }
    }

    /// Sign a request to `url`.
    pub fn sign_request(
        &self,
        url: &str,
        now: i64,
        lifetime: i64,
        nonce: &str,
    ) -> Result<SignedHeaders, String> {
        let (scheme, authority) = url_authority(url)?;
        sign_request(
            self.signing_key()?,
            &RequestToSign {
                scheme: &scheme,
                authority: &authority,
                signature_agent: &self.config.signature_agent,
                label: LABEL,
                created: now,
                expires: now + lifetime,
                nonce: Some(nonce),
            },
        )
        .map_err(|e| e.to_string())
    }

    /// The directory, signed for the configured authority.
    pub fn sign_directory(&self, created: i64, expires: i64) -> Result<SignedDirectory, String> {
        let keys: Vec<&OperatorKey> = self.keys.iter().collect();
        sign_directory(&keys, "https", &self.authority, created, expires).map_err(|e| e.to_string())
    }
}

/// `eunox sign init`: generate a key and write `dir`. Fails if `dir` already
/// has a config, so an existing key is never overwritten.
pub fn init(dir: &Path, origin: &str, signature_agent: Option<&str>) -> Result<String, String> {
    let authority = origin_authority(origin)?;
    let origin = format!("https://{authority}");
    let signature_agent = match signature_agent {
        Some(s) => {
            if !s.starts_with("https://") {
                return Err("--signature-agent must be an https URL".into());
            }
            s.to_owned()
        }
        None => format!("{origin}{DIRECTORY_PATH}"),
    };
    let config_path = dir.join(CONFIG_FILE);
    if config_path.exists() {
        return Err(format!(
            "{} exists; not overwriting an operator key",
            config_path.display()
        ));
    }
    let keys_dir = dir.join(KEYS_DIR);
    if fs::read_dir(&keys_dir).is_ok_and(|mut d| d.next().is_some()) {
        return Err(format!(
            "{} already has keys; not adding another",
            keys_dir.display()
        ));
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("random: {e}"))?;
    let key = OperatorKey::from_seed(&seed);
    seed.fill(0);

    create_private_dir(dir)?;
    create_private_dir(&keys_dir)?;
    let pem = key
        .as_dalek()
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("encoding key: {e}"))?;
    let key_path = keys_dir.join(format!("{}.pem", key.keyid()));
    write_private(&key_path, pem.as_bytes())?;
    let config = format!(
        "# eunox sign: operator config\norigin = {}\nsignature_agent = {}\n",
        toml_string(&origin),
        toml_string(&signature_agent)
    );
    fs::write(&config_path, config).map_err(|e| format!("{}: {e}", config_path.display()))?;

    // Check the setup end to end: sign a request the way `request` does and
    // run it through the same verifier `eunox serve` uses.
    let state = State::load_with(dir, None)?;
    let now = unix_now();
    let url = format!("{origin}/");
    let headers = state.sign_request(&url, now, DEFAULT_REQUEST_LIFETIME, &nonce()?)?;
    let check = self_check(&state, &authority, &headers, now);

    Ok(format!(
        "operator key  {}\n\
         key file      {}\n\
         config        {}\n\
         directory     {origin}{DIRECTORY_PATH}\n\
         Signature-Agent {signature_agent}\n\
         self-check    {check}\n\n\
         next:\n  \
         serve the directory at that URL: `eunox sign serve` behind your TLS terminator,\n  \
         or `eunox sign export --out DIR` for a static host\n  \
         then sign a request: `eunox sign request https://example.com/ --send`\n",
        key.keyid(),
        key_path.display(),
        config_path.display(),
    ))
}

fn self_check(state: &State, authority: &str, headers: &SignedHeaders, now: i64) -> String {
    let Ok(key) = state.signing_key() else {
        return "skipped".into();
    };
    let keys = HashMap::from([(
        key.keyid().to_owned(),
        Key {
            operator: "self".into(),
            public_key: key.public_key(),
        },
    )]);
    let req = Request {
        method: "GET",
        scheme: "https",
        authority,
        target: "/",
        signature: Some(&headers.signature),
        signature_input: Some(&headers.signature_input),
        signature_agent: Some(&headers.signature_agent),
        ..Default::default()
    };
    match verify(&req, &keys, now, &VerifyOptions::default()) {
        Outcome::Verified(_) => "a signed request verifies with eunox's verifier".into(),
        other => format!("FAILED: {other:?}"),
    }
}

/// `eunox sign export`: write `out/.well-known/http-message-signatures-directory`
/// and `out/_headers` (the Cloudflare Pages and Netlify format).
pub fn export(
    state: &State,
    out: &Path,
    now: i64,
    days: u64,
    max_age: u64,
) -> Result<String, String> {
    let lifetime = days
        .checked_mul(86_400)
        .and_then(|s| i64::try_from(s).ok())
        .ok_or("--days is too large")?;
    if lifetime <= i64::try_from(max_age).unwrap_or(i64::MAX) {
        return Err(format!(
            "--days {days} must outlast --max-age {max_age}s, or cached copies expire unsigned"
        ));
    }
    let expires = now + lifetime;
    let d = state.sign_directory(now, expires)?;
    let well_known = out.join(".well-known");
    fs::create_dir_all(&well_known).map_err(|e| format!("{}: {e}", well_known.display()))?;
    let body_path = out.join(DIRECTORY_PATH.trim_start_matches('/'));
    fs::write(&body_path, &d.body).map_err(|e| format!("{}: {e}", body_path.display()))?;
    let headers_path = out.join("_headers");
    let mut headers = format!("{DIRECTORY_PATH}\n");
    for (name, value) in directory_headers(&d, max_age) {
        headers.push_str(&format!("  {name}: {value}\n"));
    }
    fs::write(&headers_path, headers).map_err(|e| format!("{}: {e}", headers_path.display()))?;
    Ok(format!(
        "wrote {} and {}\n\
         signed for {}, valid until {expires} (unix seconds, {days} days)\n\
         re-run export and redeploy before then; the body must be served byte for byte\n",
        body_path.display(),
        headers_path.display(),
        state.authority
    ))
}

/// Response headers for a signed directory.
pub fn directory_headers(d: &SignedDirectory, max_age: u64) -> [(&'static str, String); 5] {
    [
        ("Content-Type", DIRECTORY_MEDIA_TYPE.to_owned()),
        ("Cache-Control", format!("max-age={max_age}")),
        ("Content-Digest", d.content_digest.clone()),
        ("Signature-Input", d.signature_input.clone()),
        ("Signature", d.signature.clone()),
    ]
}

/// Serve the directory forever. Each response is signed fresh, valid for
/// `max_age` plus an hour, so a cached copy is still signed when it expires.
pub async fn serve(listener: TcpListener, state: Arc<State>, max_age: u64) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(&state, &req, max_age, unix_now())) }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn handle(
    state: &State,
    req: &hyper::Request<Incoming>,
    max_age: u64,
    now: i64,
) -> Response<Full<Bytes>> {
    respond(
        state,
        req.method(),
        req.uri().path(),
        req.headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok()),
        max_age,
        now,
    )
}

/// The response to one request, separated from hyper for testing.
pub fn respond(
    state: &State,
    method: &Method,
    path: &str,
    host: Option<&str>,
    max_age: u64,
    now: i64,
) -> Response<Full<Bytes>> {
    if path != DIRECTORY_PATH {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    if method != Method::GET && method != Method::HEAD {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "GET only\n");
    }
    // Sign only for our own authority: a signature over whatever Host a
    // client sends would let anyone re-serve our keys as theirs.
    let ours = host.is_some_and(|h| {
        origin_authority(&format!("https://{h}")).is_ok_and(|a| a == state.authority)
    });
    if !ours {
        return plain(
            StatusCode::MISDIRECTED_REQUEST,
            "this server signs its directory for another authority\n",
        );
    }
    let expires = now + i64::try_from(max_age).unwrap_or(i64::MAX / 2) + 3600;
    let d = match state.sign_directory(now, expires) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("eunox sign: {e}");
            return plain(StatusCode::INTERNAL_SERVER_ERROR, "signing failed\n");
        }
    };
    let body = if method == Method::HEAD {
        Bytes::new()
    } else {
        Bytes::from(d.body.clone())
    };
    let mut resp = Response::new(Full::new(body));
    for (name, value) in directory_headers(&d, max_age) {
        if let Ok(v) = header::HeaderValue::from_str(&value) {
            resp.headers_mut().insert(name, v);
        }
    }
    resp
}

fn plain(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

async fn send(url: &str, h: &SignedHeaders) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("eunox-sign/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(url)
        .header("signature-agent", &h.signature_agent)
        .header("signature-input", &h.signature_input)
        .header("signature", &h.signature)
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    print!("{}", header_lines(h));
    println!("\n{} {}", resp.status(), url);
    for (name, value) in resp.headers() {
        if let Ok(v) = value.to_str() {
            println!("{name}: {v}");
        }
    }
    Ok(())
}

/// The headers as `Name: value` lines.
pub fn header_lines(h: &SignedHeaders) -> String {
    format!(
        "Signature-Agent: {}\nSignature-Input: {}\nSignature: {}\n",
        h.signature_agent, h.signature_input, h.signature
    )
}

/// 64 random bytes, base64, as the draft's examples use.
fn nonce() -> Result<String, String> {
    let mut b = [0u8; 64];
    getrandom::getrandom(&mut b).map_err(|e| format!("random: {e}"))?;
    Ok(BASE64.encode(b))
}

/// `https://host[:port]` (optional trailing slash) to its authority,
/// lowercased with the default port dropped.
pub fn origin_authority(origin: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(origin).map_err(|e| format!("{origin:?}: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!(
            "{origin:?}: the directory must be served over https"
        ));
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{origin:?}: give the origin only, no path"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{origin:?}: no credentials in the origin"));
    }
    url_authority(origin).map(|(_, a)| a)
}

fn url_authority(url: &str) -> Result<(String, String), String> {
    let u = reqwest::Url::parse(url).map_err(|e| format!("{url:?}: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(format!("{url:?}: not an http(s) URL"));
    }
    let host = u.host_str().ok_or_else(|| format!("{url:?}: no host"))?;
    let authority = match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    };
    Ok((u.scheme().to_owned(), authority.to_ascii_lowercase()))
}

fn read_keys(dir: &Path) -> Result<Vec<OperatorKey>, String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pem"))
        .collect();
    paths.sort();
    paths.iter().map(|p| read_key(p)).collect()
}

fn read_key(path: &Path) -> Result<OperatorKey, String> {
    let pem = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_key(&pem).map_err(|e| format!("{}: {e}", path.display()))
}

/// An Ed25519 PKCS#8 PEM private key.
pub fn parse_key(pem: &str) -> Result<OperatorKey, String> {
    ed25519_dalek::SigningKey::from_pkcs8_pem(pem.trim())
        .map(OperatorKey::from_dalek)
        .map_err(|_| "not an Ed25519 PKCS#8 PEM private key".to_owned())
}

fn create_private_dir(dir: &Path) -> Result<(), String> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

fn write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(contents)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn toml_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

/// Minimal flag parsing: `--name value` for `valued`, bare `--name` for
/// `switches`, anything else positional.
struct Flags {
    values: HashMap<String, String>,
    switches: Vec<String>,
    positional: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], valued: &[&str], switches: &[&str]) -> Result<Self, String> {
        let mut f = Flags {
            values: HashMap::new(),
            switches: Vec::new(),
            positional: Vec::new(),
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if valued.contains(&a.as_str()) {
                let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
                f.values.insert(a.clone(), v.clone());
            } else if switches.contains(&a.as_str()) {
                f.switches.push(a.clone());
            } else if a.starts_with("--") {
                return Err(format!("unknown flag {a}\n\n{USAGE}"));
            } else {
                f.positional.push(a.clone());
            }
        }
        Ok(f)
    }

    fn value(&self, k: &str) -> Option<&str> {
        self.values.get(k).map(String::as_str)
    }

    fn has(&self, k: &str) -> bool {
        self.switches.iter().any(|s| s == k)
    }

    fn number<T: std::str::FromStr>(&self, k: &str, default: T) -> Result<T, String> {
        match self.value(k) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| format!("{k}: {v:?} is not a number")),
        }
    }

    fn dir(&self) -> PathBuf {
        PathBuf::from(
            self.value("--dir")
                .map(str::to_owned)
                .or_else(|| env("EUNOX_SIGN_DIR"))
                .unwrap_or_else(|| DEFAULT_DIR.into()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert_eq!(
            origin_authority("https://Agent.Example").unwrap(),
            "agent.example"
        );
        assert_eq!(
            origin_authority("https://agent.example:443/").unwrap(),
            "agent.example"
        );
        assert_eq!(
            origin_authority("https://agent.example:8443").unwrap(),
            "agent.example:8443"
        );
        for bad in [
            "http://agent.example",
            "https://agent.example/keys",
            "https://u:p@agent.example",
            "agent.example",
        ] {
            assert!(origin_authority(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn toml_strings_round_trip() {
        let s = "https://a.example/\"q\"\\";
        let parsed: HashMap<String, String> =
            toml::from_str(&format!("v = {}", toml_string(s))).unwrap();
        assert_eq!(parsed["v"], s);
    }
}
