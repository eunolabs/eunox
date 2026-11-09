//! Verification tests.
//!
//! Two sources of signatures:
//! - Cloudflare's published vector from the `web-bot-auth` crate, signed with
//!   the RFC 9421 Appendix B.1.4 key `test-key-ed25519`.
//! - Signatures built here by hand from the RFC 9421 signature-base rules and
//!   signed with the same key, so the component derivation in `core` is
//!   checked against an independent construction, not against itself.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer as _, SigningKey};
use eunox_core::{Failure, Key, Outcome, Request, Verified, VerifyOptions, signature_tags, verify};

/// JWK thumbprint of `test-key-ed25519`.
const KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
const PUBLIC: [u8; 32] = [
    0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58, 0x2b, 0x23,
    0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd, 0xce, 0x43, 0xd1, 0xbb,
];
const PRIVATE: [u8; 32] = [
    0x9f, 0x83, 0x62, 0xf8, 0x7a, 0x48, 0x4a, 0x95, 0x4e, 0x6e, 0x74, 0x0c, 0x5b, 0x4c, 0x0e, 0x84,
    0x22, 0x91, 0x39, 0xa2, 0x0a, 0xa8, 0xab, 0x56, 0xff, 0x66, 0x58, 0x6f, 0x6a, 0x7d, 0x29, 0xc5,
];

// Cloudflare's vector: covers @authority only, authority "example.com".
const CF_INPUT: &str = r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#;
const CF_SIG: &str = "sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:";
const CF_CREATED: i64 = 1_735_689_600;
const CF_EXPIRES: i64 = 1_735_693_200;

const AGENT_URL: &str = "https://agent.example/.well-known/http-message-signatures-directory";

fn keys() -> HashMap<String, Key> {
    HashMap::from([(
        KEYID.to_owned(),
        Key {
            operator: "test".into(),
            public_key: PUBLIC,
        },
    )])
}

fn req<'a>(authority: &'a str, input: &'a str, sig: &'a str) -> Request<'a> {
    Request {
        method: "GET",
        scheme: "https",
        authority,
        target: "/",
        signature: Some(sig),
        signature_input: Some(input),
        ..Default::default()
    }
}

fn check(r: &Request<'_>, at: i64) -> Outcome {
    verify(r, &keys(), at, &VerifyOptions::default())
}

/// Sign `components` (identifier, value) under `params` and return
/// (Signature-Input, Signature) header values for label `sig1`.
fn sign(components: &[(&str, &str)], params: &str) -> (String, String) {
    let ids: Vec<&str> = components.iter().map(|(id, _)| *id).collect();
    let sig_params = format!("({}){params}", ids.join(" "));
    let mut base = String::new();
    for (id, value) in components {
        base.push_str(&format!("{id}: {value}\n"));
    }
    base.push_str(&format!("\"@signature-params\": {sig_params}"));
    let sig = SigningKey::from_bytes(&PRIVATE).sign(base.as_bytes());
    (
        format!("sig1={sig_params}"),
        format!("sig1=:{}:", B64.encode(sig.to_bytes())),
    )
}

fn params(created: i64, expires: i64) -> String {
    format!(
        r#";created={created};expires={expires};keyid="{KEYID}";alg="ed25519";nonce="n1";tag="web-bot-auth""#
    )
}

// ---- Cloudflare vector ----

#[test]
fn cloudflare_vector_verifies_inside_window() {
    let out = check(&req("example.com", CF_INPUT, CF_SIG), CF_CREATED + 60);
    let Outcome::Verified(v) = out else {
        panic!("{out:?}")
    };
    assert_eq!(v.keyid, KEYID);
    assert_eq!(v.operator, "test");
    assert_eq!((v.created, v.expires), (CF_CREATED, CF_EXPIRES));
    assert!(v.nonce.is_some());
    assert_eq!(v.signature_agent, None);
}

#[test]
fn cloudflare_vector_expired_at_expires() {
    let at = CF_EXPIRES + VerifyOptions::default().clock_skew;
    assert!(matches!(
        check(&req("example.com", CF_INPUT, CF_SIG), at),
        Outcome::Failed(Failure::Expired { .. })
    ));
}

#[test]
fn cloudflare_vector_valid_within_skew_of_expiry() {
    let at = CF_EXPIRES + VerifyOptions::default().clock_skew - 1;
    assert!(matches!(
        check(&req("example.com", CF_INPUT, CF_SIG), at),
        Outcome::Verified(_)
    ));
}

#[test]
fn cloudflare_vector_not_yet_valid_beyond_skew() {
    let skew = VerifyOptions::default().clock_skew;
    let r = req("example.com", CF_INPUT, CF_SIG);
    assert!(matches!(check(&r, CF_CREATED - skew), Outcome::Verified(_)));
    assert!(matches!(
        check(&r, CF_CREATED - skew - 1),
        Outcome::Failed(Failure::NotYetValid { .. })
    ));
}

#[test]
fn cloudflare_vector_tampered_authority_is_bad_signature() {
    assert_eq!(
        check(&req("example.org", CF_INPUT, CF_SIG), CF_CREATED + 60),
        Outcome::Failed(Failure::BadSignature {
            keyid: KEYID.into(),
            operator: "test".into()
        })
    );
}

#[test]
fn cloudflare_vector_authority_is_normalized() {
    let out = check(&req("EXAMPLE.com:443", CF_INPUT, CF_SIG), CF_CREATED + 60);
    assert!(matches!(out, Outcome::Verified(_)), "{out:?}");
}

#[test]
fn unknown_key() {
    let out = verify(
        &req("example.com", CF_INPUT, CF_SIG),
        &HashMap::new(),
        CF_CREATED + 60,
        &VerifyOptions::default(),
    );
    assert_eq!(
        out,
        Outcome::Failed(Failure::UnknownKey {
            keyid: KEYID.into()
        })
    );
}

// ---- Header presence and shape ----

#[test]
fn no_signature_headers_is_unsigned() {
    let r = Request {
        method: "GET",
        scheme: "https",
        authority: "example.com",
        target: "/",
        ..Default::default()
    };
    assert_eq!(check(&r, CF_CREATED), Outcome::Unsigned);
}

#[test]
fn signature_without_input_is_malformed() {
    let r = Request {
        signature_input: None,
        ..req("example.com", CF_INPUT, CF_SIG)
    };
    assert!(matches!(
        check(&r, CF_CREATED),
        Outcome::Failed(Failure::Malformed(_))
    ));
}

#[test]
fn garbage_headers_are_malformed() {
    for (input, sig) in [
        ("not a dictionary(", CF_SIG),
        (CF_INPUT, "sig1=12"),
        (CF_INPUT, "sig2=:AAAA:"),
    ] {
        let out = check(&req("example.com", input, sig), CF_CREATED + 60);
        assert!(
            matches!(out, Outcome::Failed(Failure::Malformed(_))),
            "{input} / {sig}: {out:?}"
        );
    }
}

#[test]
fn non_web_bot_auth_tag_is_unsupported() {
    let input = CF_INPUT.replace(r#"tag="web-bot-auth""#, r#"tag="other""#);
    assert!(matches!(
        check(&req("example.com", &input, CF_SIG), CF_CREATED + 60),
        Outcome::Failed(Failure::Unsupported(_))
    ));
}

#[test]
fn truncated_signature_is_bad_signature() {
    let out = check(
        &req("example.com", CF_INPUT, "sig1=:AAAA:"),
        CF_CREATED + 60,
    );
    assert!(
        matches!(out, Outcome::Failed(Failure::BadSignature { .. })),
        "{out:?}"
    );
}

// ---- Hand-built signatures ----

#[test]
fn alg_mismatch_is_rejected_even_though_crypto_passes() {
    let p = params(100, 200).replace(r#"alg="ed25519""#, r#"alg="rsa-pss-sha512""#);
    let (input, sig) = sign(&[(r#""@authority""#, "example.com")], &p);
    assert_eq!(
        check(&req("example.com", &input, &sig), 150),
        Outcome::Failed(Failure::UnsupportedAlgorithm("rsa-pss-sha512".into()))
    );
}

#[test]
fn forged_signature_with_expired_window_is_bad_signature_not_expired() {
    let (input, _) = sign(&[(r#""@authority""#, "example.com")], &params(100, 200));
    let forged = "sig1=:".to_owned() + &B64.encode([7u8; 64]) + ":";
    let out = check(&req("example.com", &input, &forged), 10_000);
    assert!(
        matches!(out, Outcome::Failed(Failure::BadSignature { .. })),
        "{out:?}"
    );
}

#[test]
fn expires_before_created_is_malformed() {
    let (input, sig) = sign(&[(r#""@authority""#, "example.com")], &params(200, 100));
    assert!(matches!(
        check(&req("example.com", &input, &sig), 150),
        Outcome::Failed(Failure::Malformed(_))
    ));
}

#[test]
fn signature_agent_dictionary_member() {
    let agent_header = format!(r#"agent1="{AGENT_URL}", other="https://elsewhere.example""#);
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (
                r#""signature-agent";key="agent1""#,
                &format!(r#""{AGENT_URL}""#),
            ),
        ],
        &params(100, 200),
    );
    let r = Request {
        signature_agent: Some(&agent_header),
        ..req("example.com", &input, &sig)
    };
    let out = check(&r, 150);
    let Outcome::Verified(Verified {
        signature_agent, ..
    }) = out
    else {
        panic!("{out:?}")
    };
    assert_eq!(signature_agent.as_deref(), Some(AGENT_URL));
}

#[test]
fn signature_agent_legacy_item() {
    let agent_header = format!(r#""{AGENT_URL}""#);
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (r#""signature-agent""#, &agent_header),
        ],
        &params(100, 200),
    );
    let r = Request {
        signature_agent: Some(&agent_header),
        ..req("example.com", &input, &sig)
    };
    let out = check(&r, 150);
    let Outcome::Verified(Verified {
        signature_agent, ..
    }) = out
    else {
        panic!("{out:?}")
    };
    assert_eq!(signature_agent.as_deref(), Some(AGENT_URL));
}

#[test]
fn uncovered_signature_agent_is_rejected() {
    // A valid signature over @authority only, with a Signature-Agent added by
    // someone else: the claimed agent isn't authenticated, so don't accept it.
    let (input, sig) = sign(&[(r#""@authority""#, "example.com")], &params(100, 200));
    let agent_header = format!(r#""{AGENT_URL}""#);
    let r = Request {
        signature_agent: Some(&agent_header),
        ..req("example.com", &input, &sig)
    };
    assert!(matches!(
        check(&r, 150),
        Outcome::Failed(Failure::Malformed(_))
    ));
}

#[test]
fn tampered_signature_agent_is_bad_signature() {
    let signed = format!(r#""{AGENT_URL}""#);
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (r#""signature-agent""#, &signed),
        ],
        &params(100, 200),
    );
    let r = Request {
        signature_agent: Some(r#""https://attacker.example/dir""#),
        ..req("example.com", &input, &sig)
    };
    assert!(matches!(
        check(&r, 150),
        Outcome::Failed(Failure::BadSignature { .. })
    ));
}

#[test]
fn derived_components_from_target() {
    let (input, sig) = sign(
        &[
            (r#""@method""#, "POST"),
            (r#""@authority""#, "example.com"),
            (r#""@path""#, "/a/b%20c"),
            (r#""@query""#, "?x=1&y=2"),
            (r#""@target-uri""#, "https://example.com/a/b%20c?x=1&y=2"),
            (r#""@request-target""#, "/a/b%20c?x=1&y=2"),
            (r#""@scheme""#, "https"),
        ],
        &params(100, 200),
    );
    let base = Request {
        method: "POST",
        target: "/a/b%20c?x=1&y=2",
        ..req("example.com", &input, &sig)
    };
    assert!(
        matches!(check(&base, 150), Outcome::Verified(_)),
        "{:?}",
        check(&base, 150)
    );

    // A rewritten path (nginx $uri instead of $request_uri) must not verify.
    let rewritten = Request {
        target: "/a/b c?x=1&y=2",
        ..base
    };
    assert!(matches!(
        check(&rewritten, 150),
        Outcome::Failed(Failure::BadSignature { .. })
    ));
}

#[test]
fn empty_path_and_query() {
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (r#""@path""#, "/"),
            (r#""@query""#, "?"),
        ],
        &params(100, 200),
    );
    let r = Request {
        target: "",
        ..req("example.com", &input, &sig)
    };
    assert!(
        matches!(check(&r, 150), Outcome::Verified(_)),
        "{:?}",
        check(&r, 150)
    );
}

#[test]
fn covered_header_that_was_not_logged() {
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (r#""content-digest""#, "sha-256=:AA==:"),
        ],
        &params(100, 200),
    );
    assert_eq!(
        check(&req("example.com", &input, &sig), 150),
        Outcome::Failed(Failure::MissingComponent("content-digest".into()))
    );
}

#[test]
fn covered_header_that_was_logged() {
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (r#""content-digest""#, "sha-256=:AA==:"),
        ],
        &params(100, 200),
    );
    let headers = [("Content-Digest", "  sha-256=:AA==:  ")];
    let r = Request {
        other_headers: &headers,
        ..req("example.com", &input, &sig)
    };
    assert!(
        matches!(check(&r, 150), Outcome::Verified(_)),
        "{:?}",
        check(&r, 150)
    );
}

// ---- @query-param (RFC 9421 §2.2.8) ----

fn signed_query(target: &str, components: &[(&str, &str)]) -> Outcome {
    let mut all = vec![(r#""@authority""#, "example.com")];
    all.extend_from_slice(components);
    let (input, sig) = sign(&all, &params(100, 200));
    let r = Request {
        target,
        ..req("example.com", &input, &sig)
    };
    check(&r, 150)
}

#[test]
fn query_param_rfc_example_simple() {
    let out = signed_query(
        "/path?param=value&foo=bar&baz=batman&qux=",
        &[
            (r#""@query-param";name="baz""#, "batman"),
            (r#""@query-param";name="qux""#, ""),
            (r#""@query-param";name="param""#, "value"),
        ],
    );
    assert!(matches!(out, Outcome::Verified(_)), "{out:?}");
}

#[test]
fn query_param_rfc_example_reencoding() {
    // Values are decoded and re-encoded: `+` becomes %20, and the name is
    // matched in its encoded form.
    let out = signed_query(
        "/parameters?var=this%20is%20a%20big%0Avalue&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something",
        &[
            (
                r#""@query-param";name="var""#,
                "this%20is%20a%20big%0Avalue",
            ),
            (r#""@query-param";name="bar""#, "with%20plus%20whitespace"),
            (r#""@query-param";name="fa%C3%A7ade%22%3A%20""#, "something"),
        ],
    );
    assert!(matches!(out, Outcome::Verified(_)), "{out:?}");
}

#[test]
fn query_param_lowercase_escapes_and_reserved_chars_are_normalized() {
    let out = signed_query(
        "/?q=a%2fb~c!d&x=%zz",
        &[
            (r#""@query-param";name="q""#, "a%2Fb%7Ec%21d"),
            (r#""@query-param";name="x""#, "%25zz"),
        ],
    );
    assert!(matches!(out, Outcome::Verified(_)), "{out:?}");
}

#[test]
fn query_param_tampered_value_is_bad_signature() {
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (r#""@query-param";name="id""#, "1"),
        ],
        &params(100, 200),
    );
    let r = Request {
        target: "/?id=2",
        ..req("example.com", &input, &sig)
    };
    assert!(matches!(
        check(&r, 150),
        Outcome::Failed(Failure::BadSignature { .. })
    ));
}

#[test]
fn query_param_absent_is_missing_component() {
    let out = signed_query("/?other=1", &[(r#""@query-param";name="id""#, "1")]);
    assert_eq!(
        out,
        Outcome::Failed(Failure::MissingComponent(
            r#"@query-param;name="id""#.into()
        ))
    );
}

#[test]
fn query_param_repeated_is_unsupported_not_forged() {
    let out = signed_query("/?id=1&id=2", &[(r#""@query-param";name="id""#, "1")]);
    assert!(
        matches!(out, Outcome::Failed(Failure::Unsupported(_))),
        "{out:?}"
    );
}

// ---- Field parameters (RFC 9421 §2.1) ----

#[test]
fn multiple_field_lines_are_combined() {
    // §2.1 example: two Example-Header lines.
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (r#""example-header""#, "value, with, lots, of, commas"),
        ],
        &params(100, 200),
    );
    let headers = [
        ("Example-Header", "value, with, lots"),
        ("Example-Header", "  of, commas "),
    ];
    let r = Request {
        other_headers: &headers,
        ..req("example.com", &input, &sig)
    };
    assert!(
        matches!(check(&r, 150), Outcome::Verified(_)),
        "{:?}",
        check(&r, 150)
    );
}

#[test]
fn bs_encodes_each_field_line() {
    // §2.1.3 example.
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (
                r#""example-header";bs"#,
                ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:",
            ),
        ],
        &params(100, 200),
    );
    let headers = [
        ("Example-Header", "value, with, lots"),
        ("Example-Header", "of, commas"),
    ];
    let r = Request {
        other_headers: &headers,
        ..req("example.com", &input, &sig)
    };
    assert!(
        matches!(check(&r, 150), Outcome::Verified(_)),
        "{:?}",
        check(&r, 150)
    );

    // The same field combined by the gateway into one line signs differently.
    let combined = [("Example-Header", "value, with, lots, of, commas")];
    let r = Request {
        other_headers: &combined,
        ..r
    };
    assert!(matches!(
        check(&r, 150),
        Outcome::Failed(Failure::BadSignature { .. })
    ));
}

#[test]
fn sf_reserializes_structured_field() {
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (r#""example-dict";sf"#, "a=1, b=2;x=1;y=2, c=(a b c)"),
        ],
        &params(100, 200),
    );
    let headers = [("Example-Dict", " a=1,    b=2;x=1;y=2,   c=(a   b   c)")];
    let r = Request {
        other_headers: &headers,
        ..req("example.com", &input, &sig)
    };
    assert!(
        matches!(check(&r, 150), Outcome::Verified(_)),
        "{:?}",
        check(&r, 150)
    );
}

#[test]
fn tr_reads_trailers_not_headers() {
    let (input, sig) = sign(
        &[
            (r#""@authority""#, "example.com"),
            (r#""content-digest";tr"#, "sha-256=:AA==:"),
        ],
        &params(100, 200),
    );
    let fields = [("Content-Digest", "sha-256=:AA==:")];
    let in_trailers = Request {
        trailers: &fields,
        ..req("example.com", &input, &sig)
    };
    assert!(matches!(check(&in_trailers, 150), Outcome::Verified(_)));

    let in_headers = Request {
        other_headers: &fields,
        ..req("example.com", &input, &sig)
    };
    assert!(matches!(
        check(&in_headers, 150),
        Outcome::Failed(Failure::MissingComponent(_))
    ));
}

#[test]
fn req_and_status_are_rejected_on_requests() {
    let headers = [("Content-Digest", "sha-256=:AA==:")];
    for component in [
        r#""content-digest";req"#,
        r#""@authority";req"#,
        r#""@query-param";name="id";req"#,
        r#""@status""#,
    ] {
        let (input, sig) = sign(
            &[(r#""@authority""#, "example.com"), (component, "x")],
            &params(100, 200),
        );
        let r = Request {
            target: "/?id=1",
            other_headers: &headers,
            ..req("example.com", &input, &sig)
        };
        let out = check(&r, 150);
        let Outcome::Failed(Failure::Malformed(why)) = &out else {
            panic!("{component}: {out:?}")
        };
        assert!(why.contains("response"), "{component}: {why}");
    }
}

// ---- Other signature schemes ----

// Visa Trusted Agent Protocol, as its sample agent emits it
// (github.com/visa/trusted-agent-protocol, tap-agent/agent_app.py): its own
// tags, `keyId` (not a valid structured-field key) and spaces after `;`.
const TAP_INPUT: &str = r#"sig2=("@authority" "@path"); created=1735689600; expires=1735693200; keyId="primary"; alg="ed25519"; nonce="n"; tag="agent-payer-auth""#;

#[test]
fn signature_tags_strict_and_lenient() {
    assert_eq!(signature_tags(CF_INPUT), ["web-bot-auth"]);
    assert_eq!(
        signature_tags(TAP_INPUT),
        ["agent-payer-auth"],
        "not valid sfv, scanned"
    );
    assert_eq!(
        signature_tags(
            r#"a=("@authority");tag="web-bot-auth", b=("@authority");tag="agent-browser-auth""#
        ),
        ["web-bot-auth", "agent-browser-auth"]
    );
    assert!(signature_tags(r#"sig1=("@authority");created=1"#).is_empty());
    // A `tag="` that isn't a parameter name doesn't count.
    assert!(signature_tags(r#"x=(;nonce="atag="z""#).is_empty());
}

#[test]
fn other_scheme_is_unsupported_not_malformed() {
    let out = check(
        &req("example.com", TAP_INPUT, "sig2=:AAAA:"),
        CF_CREATED + 60,
    );
    assert_eq!(
        out,
        Outcome::Failed(Failure::Unsupported(
            "signature tag agent-payer-auth".into()
        ))
    );

    // Same for a well-formed signature under another tag.
    let p = params(100, 200).replace(r#"tag="web-bot-auth""#, r#"tag="agent-browser-auth""#);
    let (input, sig) = sign(&[(r#""@authority""#, "example.com")], &p);
    assert!(matches!(
        check(&req("example.com", &input, &sig), 150),
        Outcome::Failed(Failure::Unsupported(_))
    ));
}

#[test]
fn web_bot_auth_label_alongside_another_scheme_still_verifies() {
    let input = format!(r#"{CF_INPUT}, sig2=("@authority");tag="agent-browser-auth""#);
    let out = check(&req("example.com", &input, CF_SIG), CF_CREATED + 60);
    assert!(matches!(out, Outcome::Verified(_)), "{out:?}");
}

#[test]
fn untagged_signature_is_still_malformed() {
    let input = CF_INPUT.replace(r#";tag="web-bot-auth""#, "");
    assert!(matches!(
        check(&req("example.com", &input, CF_SIG), CF_CREATED + 60),
        Outcome::Failed(Failure::Malformed(_))
    ));
}
