//! Web Bot Auth (RFC 9421 HTTP Message Signatures) verification at a supplied
//! timestamp.
//!
//! Verification is out-of-band: the request has already been served and we are
//! looking at its access-log record. The time to verify against is therefore the
//! log timestamp, never "now". Parsing and the cryptographic check are delegated
//! to Cloudflare's `web-bot-auth` crate; this module supplies the request
//! components from a log record, applies the time window itself and maps the
//! result onto failure reasons that classification can act on.
//!
//! What this cannot do out-of-band: reject a replayed signature. The nonce is
//! returned in [`Verified`] so a later stage can count reuse, but by then the
//! request has been served.
//!
//! Known limits, all reported as failures rather than guessed at:
//! - A `@query-param` name repeated in the query is [`Failure::Unsupported`]:
//!   the RFC signs each occurrence separately and the crate can't express it.
//! - `bs` needs each field line logged separately; a value the gateway has
//!   already combined fails as [`Failure::BadSignature`].
//! - `req` and `@status` only exist on response signatures, so a request
//!   carrying them is [`Failure::Malformed`].

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sfv::SerializeValue;
use web_bot_auth::components::{
    CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParameters, QueryParamParameters,
};
use web_bot_auth::keyring::{Algorithm, KeyRing};
use web_bot_auth::message_signatures::SignedMessage;
use web_bot_auth::{ImplementationError, SignatureAgentLink, WebBotAuthVerifier};

/// Seconds since the Unix epoch, matching the `created` and `expires`
/// signature parameters.
pub type UnixSeconds = i64;

/// The parts of one logged request that verification needs.
///
/// All values must be what the client sent, before any gateway rewrite. In
/// nginx that means `$request_uri`, not `$uri`, and `$http_host`, not
/// `$server_name`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Request<'a> {
    /// Request method, as sent (case is significant).
    pub method: &'a str,
    /// `http` or `https`, as seen by the client.
    pub scheme: &'a str,
    /// Host header or `:authority`, as sent. Normalized here per RFC 9421
    /// §2.2.3 (lowercased, default port removed).
    pub authority: &'a str,
    /// Origin-form request target: path plus optional `?query`, undecoded.
    pub target: &'a str,
    /// `Signature` header, verbatim.
    pub signature: Option<&'a str>,
    /// `Signature-Input` header, verbatim.
    pub signature_input: Option<&'a str>,
    /// `Signature-Agent` header, verbatim.
    pub signature_agent: Option<&'a str>,
    /// Any other logged headers a signature might cover, as (name, value).
    /// Names are matched case-insensitively. Repeat a name once per field
    /// line, in order, if the gateway logs them separately: `bs` signs each
    /// line on its own, so a gateway-combined value won't verify.
    pub other_headers: &'a [(&'a str, &'a str)],
    /// Request trailer fields, for components carrying `;tr`.
    pub trailers: &'a [(&'a str, &'a str)],
}

/// A public key published in an operator's key directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    /// Operator that published the key, e.g. `openai`.
    pub operator: String,
    /// Raw Ed25519 public key.
    pub public_key: [u8; 32],
}

/// Source of verification keys. Implemented by the `directory` crate.
pub trait KeyStore {
    /// Return the key with this `keyid` (the JWK thumbprint) that was valid at
    /// `at`. Stores that keep key history should honour `at`, so a key rotated
    /// out after a request was logged still verifies that request.
    fn lookup(&self, keyid: &str, at: UnixSeconds) -> Option<&Key>;
}

/// A store with no history: every key is valid at every time.
impl KeyStore for HashMap<String, Key> {
    fn lookup(&self, keyid: &str, _at: UnixSeconds) -> Option<&Key> {
        self.get(keyid)
    }
}

/// Tunables for [`verify`].
#[derive(Clone, Copy, Debug)]
pub struct VerifyOptions {
    /// Seconds of clock disagreement tolerated between the agent and the
    /// gateway, applied to both `created` and `expires`.
    pub clock_skew: i64,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self { clock_skew: 30 }
    }
}

/// Result of verifying one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Neither `Signature` nor `Signature-Input` was present.
    Unsigned,
    /// A valid Web Bot Auth signature from a known key, inside its time window.
    Verified(Verified),
    /// A signature was present but did not verify.
    Failed(Failure),
}

/// Details of a verified signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// `keyid` parameter (JWK thumbprint).
    pub keyid: String,
    /// Operator that published the key.
    pub operator: String,
    /// Key directory URL from a covered `Signature-Agent`, if any. Inline
    /// (`data:`) directories are not reported.
    pub signature_agent: Option<String>,
    /// `created` parameter.
    pub created: UnixSeconds,
    /// `expires` parameter.
    pub expires: UnixSeconds,
    /// `nonce` parameter, for after-the-fact replay counting.
    pub nonce: Option<String>,
}

/// Why a present signature did not verify.
///
/// The cryptographic check runs before the time check, so [`Failure::Expired`]
/// and [`Failure::NotYetValid`] mean the signature itself was genuine: the
/// request is a replay or the agent's clock is wrong, not a forgery. A forged
/// signature is always [`Failure::BadSignature`], whatever its timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Headers could not be parsed, or no label met the Web Bot Auth profile
    /// (`tag="web-bot-auth"`, `keyid`, `created`, `expires`, `@authority` or
    /// `@target-uri` covered, and `signature-agent` covered when sent).
    Malformed(String),
    /// The signature covers a component that was not logged.
    MissingComponent(String),
    /// Valid RFC 9421, but not something this verifier can check (for
    /// example a repeated `@query-param` name). Not evidence of forgery.
    Unsupported(String),
    /// The `alg` parameter names something other than `ed25519`.
    UnsupportedAlgorithm(String),
    /// No key with this `keyid` in any known directory.
    UnknownKey {
        /// The `keyid` that was looked up.
        keyid: String,
    },
    /// The signature does not match the request and key.
    BadSignature {
        /// The `keyid` used.
        keyid: String,
        /// Operator owning that key.
        operator: String,
    },
    /// Genuine signature, but `created` is in the future at the log time.
    NotYetValid {
        /// The `keyid` used.
        keyid: String,
        /// Operator owning that key.
        operator: String,
        /// `created` parameter.
        created: UnixSeconds,
        /// Time verified against.
        at: UnixSeconds,
    },
    /// Genuine signature, but past `expires` at the log time.
    Expired {
        /// The `keyid` used.
        keyid: String,
        /// Operator owning that key.
        operator: String,
        /// `expires` parameter.
        expires: UnixSeconds,
        /// Time verified against.
        at: UnixSeconds,
    },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Malformed(why) => write!(f, "malformed signature: {why}"),
            Failure::MissingComponent(c) => write!(f, "covered component not logged: {c}"),
            Failure::Unsupported(why) => write!(f, "unsupported signature: {why}"),
            Failure::UnsupportedAlgorithm(a) => write!(f, "unsupported algorithm: {a}"),
            Failure::UnknownKey { keyid } => write!(f, "unknown key {keyid}"),
            Failure::BadSignature { keyid, operator } => {
                write!(f, "bad signature for {operator} key {keyid}")
            }
            Failure::NotYetValid { created, at, .. } => {
                write!(f, "signature created at {created}, after log time {at}")
            }
            Failure::Expired { expires, at, .. } => {
                write!(f, "signature expired at {expires}, before log time {at}")
            }
        }
    }
}

impl std::error::Error for Failure {}

/// The `tag` parameter Web Bot Auth signatures carry.
pub const WEB_BOT_AUTH_TAG: &str = "web-bot-auth";

/// The `tag` of every label in a `Signature-Input` header, in order.
///
/// Parsed as a structured-field dictionary first. If that fails, falls back
/// to scanning for `;tag="..."`, because some signers emit headers that
/// aren't valid structured fields (Visa's Trusted Agent Protocol sample
/// writes `keyId`, and keys must be lowercase). The result is for recording
/// and reporting only; it says nothing about validity.
pub fn signature_tags(signature_input: &str) -> Vec<String> {
    if let Ok(dict) = sfv::Parser::new(signature_input).parse_dictionary() {
        return dict
            .values()
            .filter_map(|entry| match entry {
                sfv::ListEntry::InnerList(list) => list
                    .params
                    .get("tag")
                    .and_then(|t| t.as_string())
                    .map(|t| t.as_str().to_owned()),
                sfv::ListEntry::Item(_) => None,
            })
            .collect();
    }
    let mut tags = Vec::new();
    let mut rest = signature_input;
    while let Some(i) = rest.find("tag=\"") {
        let boundary = rest[..i]
            .chars()
            .next_back()
            .is_none_or(|c| c == ';' || c.is_ascii_whitespace());
        let after = &rest[i + 5..];
        let Some(end) = after.find('"') else { break };
        if boundary {
            tags.push(after[..end].to_owned());
        }
        rest = &after[end..];
    }
    tags
}

/// Verify the Web Bot Auth signature on `req` as of time `at`.
pub fn verify(
    req: &Request<'_>,
    keys: &impl KeyStore,
    at: UnixSeconds,
    opts: &VerifyOptions,
) -> Outcome {
    match (req.signature, req.signature_input) {
        (None, None) => return Outcome::Unsigned,
        (Some(_), Some(input)) => {
            // Signatures under another scheme (for example Visa's Trusted
            // Agent Protocol tags) aren't broken Web Bot Auth signatures, so
            // don't report them as malformed.
            let tags = signature_tags(input);
            if !tags.is_empty() && !tags.iter().any(|t| t == WEB_BOT_AUTH_TAG) {
                return Outcome::Failed(Failure::Unsupported(format!(
                    "signature tag {}",
                    tags.join(", ")
                )));
            }
        }
        _ => {
            return Outcome::Failed(Failure::Malformed(
                "Signature and Signature-Input must both be present".into(),
            ));
        }
    }
    match verify_signed(req, keys, at, opts) {
        Ok(v) => Outcome::Verified(v),
        Err(f) => Outcome::Failed(f),
    }
}

fn verify_signed(
    req: &Request<'_>,
    keys: &impl KeyStore,
    at: UnixSeconds,
    opts: &VerifyOptions,
) -> Result<Verified, Failure> {
    let message = LoggedMessage {
        req,
        problem: RefCell::new(None),
    };
    let verifier = WebBotAuthVerifier::parse(&message).map_err(|e| message.failure(e))?;

    let params = &verifier.get_parsed_label().base.parameters;
    // The crate verifies with the key's algorithm and ignores `alg`; RFC 9421
    // §3.2 requires rejecting a mismatch.
    if let Some(alg) = params.raw.get("alg")
        && alg.as_string().is_none_or(|s| s.as_str() != "ed25519")
    {
        return Err(Failure::UnsupportedAlgorithm(
            alg.as_string()
                .map_or_else(|| format!("{alg:?}"), |s| s.as_str().to_owned()),
        ));
    }
    let details = &params.details;
    // `parse` only accepts labels carrying these, but they may not be the
    // right type (e.g. a string `created`).
    let (Some(keyid), Some(created), Some(expires)) =
        (details.keyid.clone(), details.created, details.expires)
    else {
        return Err(Failure::Malformed(
            "keyid must be a string; created and expires integers".into(),
        ));
    };
    if expires <= created {
        return Err(Failure::Malformed(format!(
            "expires ({expires}) is not after created ({created})"
        )));
    }
    let nonce = details.nonce.clone();
    let signature_agent = verifier
        .get_signature_agents()
        .iter()
        .find_map(|link| match link {
            SignatureAgentLink::External(url) => Some(url.clone()),
            SignatureAgentLink::Inline(_) => None,
        });

    let key = keys.lookup(&keyid, at).ok_or_else(|| Failure::UnknownKey {
        keyid: keyid.clone(),
    })?;
    let mut ring = KeyRing::default();
    ring.import_raw(keyid.clone(), Algorithm::Ed25519, key.public_key.to_vec());
    let operator = key.operator.clone();

    // Crypto before time, so an expired failure means "genuine but replayed".
    verifier.verify(&ring, None).map_err(|e| match e {
        ImplementationError::FailedToVerify(_) | ImplementationError::InvalidSignatureLength => {
            Failure::BadSignature {
                keyid: keyid.clone(),
                operator: operator.clone(),
            }
        }
        other => message.failure(other),
    })?;

    if at.saturating_add(opts.clock_skew) < created {
        return Err(Failure::NotYetValid {
            keyid,
            operator,
            created,
            at,
        });
    }
    if at >= expires.saturating_add(opts.clock_skew) {
        return Err(Failure::Expired {
            keyid,
            operator,
            expires,
            at,
        });
    }

    Ok(Verified {
        keyid,
        operator,
        signature_agent,
        created,
        expires,
        nonce,
    })
}

fn map_error(e: ImplementationError) -> Failure {
    match e {
        ImplementationError::LookupError(c) => Failure::MissingComponent(component_name(&c)),
        ImplementationError::UnsupportedAlgorithm(a) => {
            Failure::UnsupportedAlgorithm(a.to_string())
        }
        ImplementationError::ParsingError(why) => Failure::Malformed(why),
        other => Failure::Malformed(other.to_string()),
    }
}

fn component_name(c: &CoveredComponent) -> String {
    match c {
        CoveredComponent::HTTP(f) => f.name.clone(),
        CoveredComponent::Derived(d) => match d {
            DerivedComponent::Authority { .. } => "@authority".into(),
            DerivedComponent::TargetUri { .. } => "@target-uri".into(),
            DerivedComponent::RequestTarget { .. } => "@request-target".into(),
            DerivedComponent::Method { .. } => "@method".into(),
            DerivedComponent::Path { .. } => "@path".into(),
            DerivedComponent::Scheme { .. } => "@scheme".into(),
            DerivedComponent::Query { .. } => "@query".into(),
            DerivedComponent::QueryParams { parameters } => {
                match parameters.0.iter().find_map(|p| match p {
                    QueryParamParameters::Name(n) => Some(n),
                    QueryParamParameters::Req => None,
                }) {
                    Some(name) => format!("@query-param;name=\"{name}\""),
                    None => "@query-param".into(),
                }
            }
            DerivedComponent::Status { .. } => "@status".into(),
        },
    }
}

/// Adapts a log record to the crate's component lookup.
///
/// The lookup can only answer "here are the values" or "nothing", and the
/// crate reports "nothing" as a missing component. When the real reason is
/// different (the component is invalid on a request, or valid but
/// unverifiable here), it is recorded in `problem` and reported instead.
struct LoggedMessage<'r, 'a> {
    req: &'r Request<'a>,
    problem: RefCell<Option<Failure>>,
}

impl SignedMessage for LoggedMessage<'_, '_> {
    fn lookup_component(&self, component: &CoveredComponent) -> Vec<String> {
        let found = match component {
            CoveredComponent::HTTP(field) => self.field(field),
            CoveredComponent::Derived(d) => self.derived(d),
        };
        match found {
            Ok(values) => values,
            Err(problem) => {
                self.problem.borrow_mut().get_or_insert(problem);
                Vec::new()
            }
        }
    }
}

/// `Err` carries a reason more specific than "not logged"; `Ok(vec![])`
/// means not logged.
type Lookup = Result<Vec<String>, Failure>;

fn not_on_request(what: &str) -> Failure {
    Failure::Malformed(format!("{what} is only valid when signing a response"))
}

impl LoggedMessage<'_, '_> {
    fn failure(&self, e: ImplementationError) -> Failure {
        match (e, self.problem.borrow_mut().take()) {
            (ImplementationError::LookupError(_), Some(problem)) => problem,
            (e, _) => map_error(e),
        }
    }

    /// All logged instances of a field, in order.
    fn instances(&self, name: &str, trailer: bool) -> Vec<&str> {
        let r = self.req;
        if trailer {
            return find_all(r.trailers, name);
        }
        let single = match name {
            "signature" => r.signature,
            "signature-input" => r.signature_input,
            "signature-agent" => r.signature_agent,
            _ => return find_all(r.other_headers, name),
        };
        single.into_iter().collect()
    }

    /// RFC 9421 §2.1 HTTP field values.
    fn field(&self, field: &HTTPField) -> Lookup {
        let mut key = None;
        let (mut sf, mut bs, mut tr) = (false, false, false);
        for p in &field.parameters.0 {
            match p {
                HTTPFieldParameters::Key(k) => key = Some(k.as_str()),
                HTTPFieldParameters::Sf => sf = true,
                HTTPFieldParameters::Bs => bs = true,
                HTTPFieldParameters::Tr => tr = true,
                HTTPFieldParameters::Req => {
                    return Err(not_on_request(&format!("\"{}\";req", field.name)));
                }
            }
        }
        // §2.1: strip surrounding whitespace from each field line.
        let lines: Vec<&str> = self
            .instances(&field.name, tr)
            .into_iter()
            .map(|v| v.trim_matches([' ', '\t']))
            .collect();
        if lines.is_empty() {
            return Ok(Vec::new());
        }

        // §2.1.3: each line as its own byte sequence. The crate joins
        // multiple values with ", ", which is what the RFC specifies.
        if bs {
            return Ok(lines
                .iter()
                .map(|line| format!(":{}:", BASE64.encode(line)))
                .collect());
        }

        // §2.1.2 / §2.1.1: structured values are parsed from the combined
        // field value and re-serialized.
        let combined = lines.join(", ");
        if let Some(k) = key {
            let Ok(mut dict) = sfv::Parser::new(&combined).parse_dictionary() else {
                return Err(Failure::Malformed(format!(
                    "{} is not a structured dictionary",
                    field.name
                )));
            };
            return Ok(dict
                .shift_remove(k)
                .and_then(|member| vec![member].serialize_value())
                .into_iter()
                .collect());
        }
        if sf {
            // The field's structured type isn't known here. A dictionary
            // never parses as a list, and an item serializes the same as a
            // one-element list, so try list first.
            let serialized = match sfv::Parser::new(&combined).parse_list() {
                Ok(list) => list.serialize_value(),
                Err(_) => sfv::Parser::new(&combined)
                    .parse_dictionary()
                    .ok()
                    .and_then(|d| d.serialize_value()),
            };
            return serialized.map(|v| vec![v]).ok_or_else(|| {
                Failure::Malformed(format!("{} is not a structured field", field.name))
            });
        }
        // Plain fields: the crate joins multiple lines with ", ".
        Ok(lines.into_iter().map(str::to_owned).collect())
    }

    /// RFC 9421 §2.2 derived components, for requests only.
    fn derived(&self, d: &DerivedComponent) -> Lookup {
        let r = self.req;
        let (path, query) = match r.target.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (r.target, None),
        };
        let path = if path.is_empty() { "/" } else { path };
        let scheme = r.scheme.to_ascii_lowercase();
        let value = match d {
            DerivedComponent::Status { .. } => return Err(not_on_request("@status")),
            DerivedComponent::Method { req: true }
            | DerivedComponent::Scheme { req: true }
            | DerivedComponent::Authority { req: true }
            | DerivedComponent::Path { req: true }
            | DerivedComponent::Query { req: true }
            | DerivedComponent::RequestTarget { req: true }
            | DerivedComponent::TargetUri { req: true } => {
                return Err(not_on_request(&format!(
                    "{};req",
                    component_name(&CoveredComponent::Derived(d.clone()))
                )));
            }
            DerivedComponent::Method { req: false } => r.method.to_owned(),
            DerivedComponent::Scheme { req: false } => scheme,
            DerivedComponent::Authority { req: false } => normalize_authority(&scheme, r.authority),
            DerivedComponent::Path { req: false } => path.to_owned(),
            DerivedComponent::Query { req: false } => format!("?{}", query.unwrap_or("")),
            DerivedComponent::RequestTarget { req: false } => r.target.to_owned(),
            DerivedComponent::TargetUri { req: false } => {
                let authority = normalize_authority(&scheme, r.authority);
                match query {
                    Some(q) => format!("{scheme}://{authority}{path}?{q}"),
                    None => format!("{scheme}://{authority}{path}"),
                }
            }
            DerivedComponent::QueryParams { parameters } => {
                return query_param(query.unwrap_or(""), &parameters.0);
            }
        };
        Ok(vec![value])
    }
}

fn find_all<'a>(fields: &[(&str, &'a str)], name: &str) -> Vec<&'a str> {
    fields
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
        .collect()
}

/// RFC 9421 §2.2.8 `@query-param`: the value of the named parameter, parsed
/// as `application/x-www-form-urlencoded` and re-encoded. The `name`
/// parameter is compared in its re-encoded form, which is how signers write
/// it.
fn query_param(query: &str, params: &[QueryParamParameters]) -> Lookup {
    let mut name = None;
    for p in params {
        match p {
            QueryParamParameters::Name(n) => name = Some(n.as_str()),
            QueryParamParameters::Req => return Err(not_on_request("@query-param;req")),
        }
    }
    let Some(name) = name else {
        return Err(Failure::Malformed("@query-param without a name".into()));
    };
    let values: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (n, v) = pair.split_once('=').unwrap_or((pair, ""));
            (form_reencode(n) == name).then(|| form_reencode(v))
        })
        .collect();
    if values.len() > 1 {
        // §2.2.8 signs each occurrence on its own line under the same
        // identifier; the web-bot-auth crate keys components by identifier
        // and can't represent that.
        return Err(Failure::Unsupported(format!(
            "@query-param;name=\"{name}\" occurs {} times",
            values.len()
        )));
    }
    Ok(values)
}

/// Percent-decode a form-urlencoded token (`+` is a space) and re-encode it
/// with the `application/x-www-form-urlencoded` percent-encode set, leaving
/// only `A-Z a-z 0-9 * - . _` unescaped and writing spaces as `%20`.
fn form_reencode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(&h), Some(&l)) => hex(h).zip(hex(l)),
            _ => None,
        };
        match (bytes[i], escaped) {
            (_, Some((hi, lo))) => {
                decoded.push(hi << 4 | lo);
                i += 3;
                continue;
            }
            // Invalid escapes stay literal, as in the WHATWG URL parser.
            (b'+', None) => decoded.push(b' '),
            (b, None) => decoded.push(b),
        }
        i += 1;
    }
    let mut out = String::with_capacity(decoded.len() * 3);
    for b in decoded {
        if b.is_ascii_alphanumeric() || matches!(b, b'*' | b'-' | b'.' | b'_') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Lowercase and drop the scheme's default port (RFC 9421 §2.2.3, RFC 9110
/// §4.2.3).
pub(crate) fn normalize_authority(scheme: &str, authority: &str) -> String {
    let lower = authority.trim().to_ascii_lowercase();
    let default_port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return lower,
    };
    match lower.strip_suffix(default_port) {
        Some(host) => host.to_owned(),
        None => lower,
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_authority;

    #[test]
    fn authority_normalization() {
        assert_eq!(
            normalize_authority("https", "Example.COM:443"),
            "example.com"
        );
        assert_eq!(normalize_authority("http", "example.com:80"), "example.com");
        assert_eq!(
            normalize_authority("https", "example.com:80"),
            "example.com:80"
        );
        assert_eq!(normalize_authority("https", "[::1]:443"), "[::1]");
        assert_eq!(
            normalize_authority("https", "example.com:4430"),
            "example.com:4430"
        );
    }
}
