//! The signer half of Web Bot Auth: sign requests as an operator, and build
//! and sign the operator's key directory.
//!
//! Like the rest of this crate it does no I/O: the caller supplies the key,
//! the time and the nonce, so signing is deterministic and testable. Follows
//! `draft-ietf-webbotauth-httpsig-protocol-01`:
//!
//! - Requests cover `@authority` and the `Signature-Agent` member for the
//!   signature's label (`"signature-agent";key="<label>"`), carry `created`,
//!   `expires`, `keyid`, `alg`, `tag="web-bot-auth"` and usually a `nonce`,
//!   and send `Signature-Agent` in its dictionary form, which the draft
//!   requires of signers.
//! - The directory is a JWK Set whose `kid`s are the keys' thumbprints. Its
//!   response carries one signature per key (Appendix B.1) over
//!   `"@authority";req` and `content-digest`, with
//!   `tag="http-message-signatures-directory"`.
//!
//! Both are checked byte for byte against the draft's test vectors
//! (Appendix E.2.1 and E.2.3).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};

use crate::signature::{UnixSeconds, WEB_BOT_AUTH_TAG, normalize_authority};

/// `tag` of a directory response signature.
pub const DIRECTORY_TAG: &str = "http-message-signatures-directory";
/// Well-known path of a key directory.
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
/// Media type a directory at [`DIRECTORY_PATH`] must be served with.
pub const DIRECTORY_MEDIA_TYPE: &str = "application/http-message-signatures-directory+json";

/// An Ed25519 operator signing key.
///
/// `Debug` shows only the key id, so the private half can't end up in a log
/// by accident.
#[derive(Clone)]
pub struct OperatorKey {
    inner: ed25519_dalek::SigningKey,
    keyid: String,
}

impl OperatorKey {
    /// A key from its 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let inner = ed25519_dalek::SigningKey::from_bytes(seed);
        let keyid = jwk_thumbprint(inner.verifying_key().as_bytes());
        Self { inner, keyid }
    }

    /// Wrap an existing `ed25519-dalek` key.
    pub fn from_dalek(inner: ed25519_dalek::SigningKey) -> Self {
        let keyid = jwk_thumbprint(inner.verifying_key().as_bytes());
        Self { inner, keyid }
    }

    /// The underlying key, for serializing it to storage.
    pub fn as_dalek(&self) -> &ed25519_dalek::SigningKey {
        &self.inner
    }

    /// Raw public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    /// The Web Bot Auth `keyid`: the key's JWK thumbprint (RFC 8037 A.3).
    pub fn keyid(&self) -> &str {
        &self.keyid
    }

    fn sign(&self, base: &str) -> String {
        format!(
            ":{}:",
            BASE64.encode(self.inner.sign(base.as_bytes()).to_bytes())
        )
    }
}

impl fmt::Debug for OperatorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorKey")
            .field("keyid", &self.keyid)
            .finish_non_exhaustive()
    }
}

/// Base64url SHA-256 JWK thumbprint of an Ed25519 public key (RFC 7638,
/// RFC 8037 Appendix A.3).
pub fn jwk_thumbprint(public_key: &[u8; 32]) -> String {
    let x = BASE64URL.encode(public_key);
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    BASE64URL.encode(Sha256::digest(canonical.as_bytes()))
}

/// Why a signature couldn't be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The label isn't a structured-field key (lowercase letter or `*`, then
    /// lowercase letters, digits, `_`, `-`, `.` or `*`).
    BadLabel(String),
    /// A value that goes into a structured-field string has characters a
    /// string can't hold (non-ASCII or control characters).
    BadString(&'static str),
    /// The authority is empty or contains characters an authority can't.
    BadAuthority(String),
    /// `expires` isn't after `created`.
    BadLifetime,
    /// A directory needs at least one key.
    NoKeys,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLabel(l) => write!(f, "{l:?} is not a valid signature label"),
            Self::BadString(what) => write!(f, "{what} must be printable ASCII"),
            Self::BadAuthority(a) => write!(f, "{a:?} is not a valid authority"),
            Self::BadLifetime => f.write_str("expires must be after created"),
            Self::NoKeys => f.write_str("a key directory needs at least one key"),
        }
    }
}

impl std::error::Error for SignError {}

/// A request to sign.
#[derive(Clone, Copy, Debug)]
pub struct RequestToSign<'a> {
    /// `http` or `https`; only used to drop the default port.
    pub scheme: &'a str,
    /// Host and optional port the request goes to, as in the URL.
    pub authority: &'a str,
    /// Value of the `Signature-Agent` member: the URL the operator's key
    /// directory is served at.
    pub signature_agent: &'a str,
    /// Signature label, e.g. `sig1`.
    pub label: &'a str,
    /// `created`.
    pub created: UnixSeconds,
    /// `expires`. The draft recommends no more than 24 hours after `created`.
    pub expires: UnixSeconds,
    /// `nonce`, if any. The caller picks it, normally 64 random bytes in
    /// base64.
    pub nonce: Option<&'a str>,
}

/// The three headers a signed request carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeaders {
    /// `Signature-Agent`, dictionary form.
    pub signature_agent: String,
    /// `Signature-Input`.
    pub signature_input: String,
    /// `Signature`.
    pub signature: String,
}

/// Sign a request with Web Bot Auth.
pub fn sign_request(
    key: &OperatorKey,
    req: &RequestToSign<'_>,
) -> Result<SignedHeaders, SignError> {
    check_label(req.label)?;
    check_lifetime(req.created, req.expires)?;
    let authority = normalized_authority(req.scheme, req.authority)?;
    let agent = sf_string(req.signature_agent, "the Signature-Agent URL")?;
    let label = req.label;

    // Parameter order follows the draft's test vector (E.2.1).
    let mut params = format!(
        r#"("@authority" "signature-agent";key={label_s});created={};keyid={};alg="ed25519";expires={}"#,
        req.created,
        sf_string(key.keyid(), "keyid")?,
        req.expires,
        label_s = sf_string(label, "label")?,
    );
    if let Some(nonce) = req.nonce {
        params.push_str(";nonce=");
        params.push_str(&sf_string(nonce, "nonce")?);
    }
    params.push_str(";tag=");
    params.push_str(&sf_string(WEB_BOT_AUTH_TAG, "tag")?);

    let base = format!(
        "\"@authority\": {authority}\n\"signature-agent\";key=\"{label}\": {agent}\n\"@signature-params\": {params}"
    );
    Ok(SignedHeaders {
        signature_agent: format!("{label}={agent}"),
        signature_input: format!("{label}={params}"),
        signature: format!("{label}={}", key.sign(&base)),
    })
}

/// The JWK Set for these keys: Ed25519 `OKP` keys with `kid` set to the
/// thumbprint, as the draft requires at the well-known path, and
/// `use="sig"`. No whitespace and no trailing newline, matching the draft's
/// example byte for byte; the digest is over exactly these bytes.
pub fn directory_jwks(keys: &[&OperatorKey]) -> String {
    let entries: Vec<String> = keys
        .iter()
        .map(|k| {
            format!(
                r#"{{"kty":"OKP","crv":"Ed25519","kid":"{}","x":"{}","use":"sig"}}"#,
                k.keyid(),
                BASE64URL.encode(k.public_key())
            )
        })
        .collect();
    format!(r#"{{"keys":[{}]}}"#, entries.join(","))
}

/// `Content-Digest` value for a body (RFC 9530, `sha-256`).
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", BASE64.encode(Sha256::digest(body)))
}

/// A directory response body and the headers that prove the server holds
/// every key in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDirectory {
    /// The JWK Set, from [`directory_jwks`].
    pub body: String,
    /// `Content-Digest` of the body.
    pub content_digest: String,
    /// `Signature-Input`, one member per key.
    pub signature_input: String,
    /// `Signature`, one member per key.
    pub signature: String,
}

/// Build the directory for `keys` and sign it for a request that fetched it
/// from `authority`, one signature per key. Labels are `binding` for the
/// first key and `binding1`, `binding2`, ... after it.
///
/// The signature covers the authority, so a server must only sign for the
/// authorities it is meant to serve: signing for whatever `Host` a client
/// sends would let anyone re-serve the key set under their own name, which is
/// what the signature exists to prevent.
pub fn sign_directory(
    keys: &[&OperatorKey],
    scheme: &str,
    authority: &str,
    created: UnixSeconds,
    expires: UnixSeconds,
) -> Result<SignedDirectory, SignError> {
    if keys.is_empty() {
        return Err(SignError::NoKeys);
    }
    check_lifetime(created, expires)?;
    let authority = normalized_authority(scheme, authority)?;
    let body = directory_jwks(keys);
    let digest = content_digest(body.as_bytes());
    let mut inputs = Vec::with_capacity(keys.len());
    let mut signatures = Vec::with_capacity(keys.len());
    for (i, key) in keys.iter().enumerate() {
        let label = if i == 0 {
            "binding".to_owned()
        } else {
            format!("binding{i}")
        };
        // Parameter order follows the draft's test vector (E.2.3).
        let params = format!(
            r#"("@authority";req "content-digest");created={created};expires={expires};keyid={};tag={}"#,
            sf_string(key.keyid(), "keyid")?,
            sf_string(DIRECTORY_TAG, "tag")?,
        );
        let base = format!(
            "\"@authority\";req: {authority}\n\"content-digest\": {digest}\n\"@signature-params\": {params}"
        );
        inputs.push(format!("{label}={params}"));
        signatures.push(format!("{label}={}", key.sign(&base)));
    }
    Ok(SignedDirectory {
        body,
        content_digest: digest,
        signature_input: inputs.join(", "),
        signature: signatures.join(", "),
    })
}

fn normalized_authority(scheme: &str, raw: &str) -> Result<String, SignError> {
    let a = normalize_authority(scheme, raw);
    let ok = !a.is_empty()
        && a.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_')
        });
    if ok {
        Ok(a)
    } else {
        Err(SignError::BadAuthority(raw.to_owned()))
    }
}

fn check_label(label: &str) -> Result<(), SignError> {
    let mut bytes = label.bytes();
    let ok = matches!(bytes.next(), Some(b'a'..=b'z' | b'*'))
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*'));
    if ok {
        Ok(())
    } else {
        Err(SignError::BadLabel(label.to_owned()))
    }
}

fn check_lifetime(created: UnixSeconds, expires: UnixSeconds) -> Result<(), SignError> {
    if expires > created {
        Ok(())
    } else {
        Err(SignError::BadLifetime)
    }
}

/// A structured-field string, quoted and escaped.
fn sf_string(s: &str, what: &'static str) -> Result<String, SignError> {
    let s = sfv::StringRef::from_str(s).map_err(|_| SignError::BadString(what))?;
    Ok(sfv::ItemSerializer::new()
        .bare_item(sfv::RefBareItem::String(s))
        .finish())
}
