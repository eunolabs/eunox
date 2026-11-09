//! Pure parsers for the fetched files.

use eunox_core::IpNet;
use serde_json::Value;
use web_bot_auth::keyring::{Algorithm, Thumbprintable};

/// Parse a range file in Google's format:
/// `{"prefixes": [{"ipv4Prefix": "1.2.3.0/24"}, {"ipv6Prefix": "2001:db8::/32"}]}`.
///
/// Fails if there's no `prefixes` array or if any prefix is invalid: a
/// half-parsed file would silently drop real crawler addresses.
pub fn parse_ranges(body: &[u8]) -> Result<Vec<IpNet>, String> {
    let json: Value = serde_json::from_slice(body).map_err(|e| format!("not JSON: {e}"))?;
    let prefixes = json
        .get("prefixes")
        .and_then(Value::as_array)
        .ok_or("no \"prefixes\" array")?;
    prefixes
        .iter()
        .map(|p| {
            let s = p
                .get("ipv4Prefix")
                .or_else(|| p.get("ipv6Prefix"))
                .and_then(Value::as_str)
                .ok_or_else(|| format!("entry without ipv4Prefix or ipv6Prefix: {p}"))?;
            s.parse::<IpNet>().map_err(|e| e.to_string())
        })
        .collect()
}

/// One verification key from a key directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryKey {
    /// RFC 7638 JWK thumbprint, base64url. Web Bot Auth uses this as `keyid`.
    pub thumbprint: String,
    /// The JWK's own `kid`, if different from the thumbprint. Some operators
    /// (Google) publish short `kid`s; signatures may name either.
    pub kid: Option<String>,
    /// Raw Ed25519 public key.
    pub public_key: [u8; 32],
    /// `nbf`: not valid before (Unix seconds).
    pub not_before: Option<i64>,
    /// `exp`: not valid from (Unix seconds).
    pub expires: Option<i64>,
}

/// Parse a JWKS key directory, keeping Ed25519 keys. Other keys are skipped,
/// not errors: the verifier only supports Ed25519, and one unsupported key
/// mustn't hide the rest.
pub fn parse_key_directory(body: &[u8]) -> Result<Vec<DirectoryKey>, String> {
    let json: Value = serde_json::from_slice(body).map_err(|e| format!("not JSON: {e}"))?;
    let keys = json
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("no \"keys\" array")?;
    Ok(keys.iter().filter_map(parse_jwk).collect())
}

fn parse_jwk(jwk: &Value) -> Option<DirectoryKey> {
    let parsed: Thumbprintable = serde_json::from_value(jwk.clone()).ok()?;
    if parsed.algorithm().ok()? != Algorithm::Ed25519 {
        return None;
    }
    let public_key: [u8; 32] = parsed.public_key().ok()?.try_into().ok()?;
    let thumbprint = parsed.b64_thumbprint();
    let kid = jwk
        .get("kid")
        .and_then(Value::as_str)
        .filter(|k| *k != thumbprint)
        .map(str::to_owned);
    Some(DirectoryKey {
        thumbprint,
        kid,
        public_key,
        not_before: jwk.get("nbf").and_then(Value::as_i64),
        expires: jwk.get("exp").and_then(Value::as_i64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_v4_and_v6() {
        let body = br#"{"creationTime":"2026-11-06T15:46:11","prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"}]}"#;
        let nets = parse_ranges(body).unwrap();
        assert_eq!(nets.len(), 2);
        assert!(nets[0].contains("66.249.64.5".parse().unwrap()));
        assert!(nets[1].contains("2001:4860:4801:10::1".parse().unwrap()));
    }

    #[test]
    fn ranges_reject_partial_files() {
        assert!(
            parse_ranges(br#"{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"},{"ipv4Prefix":"bad"}]}"#)
                .is_err()
        );
        assert!(parse_ranges(br#"{"prefixes":[{"other":"1.2.3.0/24"}]}"#).is_err());
        assert!(parse_ranges(br#"{"nope":[]}"#).is_err());
        assert!(parse_ranges(b"<html>").is_err());
    }

    #[test]
    fn key_directory_rfc9421_test_key() {
        // RFC 9421 B.1.4 test key, public part, with a kid that differs from
        // its thumbprint and validity bounds.
        let body = br#"{"keys":[
            {"kty":"OKP","crv":"Ed25519","kid":"test-key-ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","nbf":100,"exp":200},
            {"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
            {"kty":"OKP","crv":"Ed25519"}
        ]}"#;
        let keys = parse_key_directory(body).unwrap();
        assert_eq!(keys.len(), 1, "EC and broken keys are skipped");
        let k = &keys[0];
        assert_eq!(k.thumbprint, "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U");
        assert_eq!(k.kid.as_deref(), Some("test-key-ed25519"));
        assert_eq!(k.public_key[..4], [0x26, 0xb4, 0x0b, 0x8f]);
        assert_eq!((k.not_before, k.expires), (Some(100), Some(200)));
    }

    #[test]
    fn key_directory_requires_keys_array() {
        assert!(parse_key_directory(br#"{"other":1}"#).is_err());
    }
}
