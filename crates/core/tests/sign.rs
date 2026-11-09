//! The signer, checked against `draft-ietf-webbotauth-httpsig-protocol-01`
//! Appendix E.2 byte for byte, and round-tripped through the verifier.

use std::collections::HashMap;

use eunox_core::{
    DIRECTORY_TAG, Key, OperatorKey, Outcome, Request, RequestToSign, SignError, VerifyOptions,
    content_digest, directory_jwks, jwk_thumbprint, sign_directory, sign_request, verify,
};

/// RFC 9421 B.1.4 `test-key-ed25519`, the key the draft's vectors use.
const TEST_SEED: [u8; 32] = [
    0x9f, 0x83, 0x62, 0xf8, 0x7a, 0x48, 0x4a, 0x95, 0x4e, 0x6e, 0x74, 0x0c, 0x5b, 0x4c, 0x0e, 0x84,
    0x22, 0x91, 0x39, 0xa2, 0x0a, 0xa8, 0xab, 0x56, 0xff, 0x66, 0x58, 0x6f, 0x6a, 0x7d, 0x29, 0xc5,
];
const TEST_KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

fn key() -> OperatorKey {
    OperatorKey::from_seed(&TEST_SEED)
}

#[test]
fn keyid_is_the_jwk_thumbprint() {
    assert_eq!(key().keyid(), TEST_KEYID);
    assert_eq!(jwk_thumbprint(&key().public_key()), TEST_KEYID);
    // Debug never shows the private half.
    let dbg = format!("{:?}", key());
    assert!(dbg.contains(TEST_KEYID), "{dbg}");
    assert!(!dbg.contains("9f8362"), "{dbg}");
}

/// Appendix E.2.1: dictionary-form Signature-Agent.
#[test]
fn request_matches_draft_vector() {
    let nonce =
        "n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";
    let h = sign_request(
        &key(),
        &RequestToSign {
            scheme: "https",
            authority: "example.com",
            signature_agent: "https://signature-agent.test",
            label: "sig2",
            created: 1_735_689_600,
            expires: 4_889_289_600,
            nonce: Some(nonce),
        },
    )
    .unwrap();
    assert_eq!(h.signature_agent, r#"sig2="https://signature-agent.test""#);
    assert_eq!(
        h.signature_input,
        format!(
            r#"sig2=("@authority" "signature-agent";key="sig2");created=1735689600;keyid="{TEST_KEYID}";alg="ed25519";expires=4889289600;nonce="{nonce}";tag="web-bot-auth""#
        )
    );
    assert_eq!(
        h.signature,
        "sig2=:CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ==:"
    );
}

/// Appendix E.2.3: the signed directory response.
#[test]
fn directory_matches_draft_vector() {
    let k = key();
    assert_eq!(
        directory_jwks(&[&k]),
        format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"{TEST_KEYID}","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}}]}}"#
        )
    );
    let d = sign_directory(
        &[&k],
        "https",
        "signature-agent.test",
        1_735_689_600,
        4_889_289_600,
    )
    .unwrap();
    assert_eq!(
        d.content_digest,
        "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:"
    );
    assert_eq!(d.content_digest, content_digest(d.body.as_bytes()));
    assert_eq!(
        d.signature_input,
        format!(
            r#"binding=("@authority";req "content-digest");created=1735689600;expires=4889289600;keyid="{TEST_KEYID}";tag="{DIRECTORY_TAG}""#
        )
    );
    assert_eq!(
        d.signature,
        "binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:"
    );
}

#[test]
fn directory_signs_once_per_key() {
    let a = key();
    let b = OperatorKey::from_seed(&[7; 32]);
    let d = sign_directory(&[&a, &b], "https", "Agent.Example:443", 100, 200).unwrap();
    assert!(d.body.contains(a.keyid()) && d.body.contains(b.keyid()));
    let labels: Vec<&str> = d
        .signature_input
        .split(", ")
        .map(|m| m.split('=').next().unwrap())
        .collect();
    assert_eq!(labels, ["binding", "binding1"]);
    assert!(
        d.signature_input
            .contains(&format!(r#"keyid="{}""#, b.keyid()))
    );
    assert_eq!(d.signature.split(", ").count(), 2);
    // Same request, same keys, same time: deterministic.
    assert_eq!(
        d,
        sign_directory(&[&a, &b], "https", "agent.example", 100, 200).unwrap()
    );
}

#[test]
fn signed_requests_verify_with_the_verifier() {
    let k = OperatorKey::from_seed(&[42; 32]);
    let agent = "https://agent.example/.well-known/http-message-signatures-directory";
    let h = sign_request(
        &k,
        &RequestToSign {
            scheme: "https",
            authority: "Shop.Example:443",
            signature_agent: agent,
            label: "sig1",
            created: 1_000,
            expires: 1_060,
            nonce: Some("bm9uY2U="),
        },
    )
    .unwrap();
    let keys = HashMap::from([(
        k.keyid().to_owned(),
        Key {
            operator: "acme".into(),
            public_key: k.public_key(),
        },
    )]);
    let req = Request {
        method: "GET",
        scheme: "https",
        authority: "shop.example",
        target: "/products/1",
        signature: Some(&h.signature),
        signature_input: Some(&h.signature_input),
        signature_agent: Some(&h.signature_agent),
        ..Default::default()
    };
    let opts = VerifyOptions::default();
    let Outcome::Verified(v) = verify(&req, &keys, 1_010, &opts) else {
        panic!("{:?}", verify(&req, &keys, 1_010, &opts))
    };
    assert_eq!(v.keyid, k.keyid());
    assert_eq!(v.signature_agent.as_deref(), Some(agent));
    assert_eq!(v.nonce.as_deref(), Some("bm9uY2U="));
    // Bound to the authority and the window.
    let elsewhere = Request {
        authority: "other.example",
        ..req
    };
    assert!(matches!(
        verify(&elsewhere, &keys, 1_010, &opts),
        Outcome::Failed(_)
    ));
    assert!(matches!(
        verify(&req, &keys, 2_000, &opts),
        Outcome::Failed(_)
    ));
}

#[test]
fn rejects_bad_input() {
    let k = key();
    let ok = RequestToSign {
        scheme: "https",
        authority: "example.com",
        signature_agent: "https://agent.example",
        label: "sig1",
        created: 1,
        expires: 2,
        nonce: None,
    };
    assert!(sign_request(&k, &ok).is_ok());
    for (bad, want) in [
        (
            RequestToSign {
                label: "Sig1",
                ..ok
            },
            SignError::BadLabel("Sig1".into()),
        ),
        (RequestToSign { expires: 1, ..ok }, SignError::BadLifetime),
        (
            RequestToSign {
                authority: "exa mple.com",
                ..ok
            },
            SignError::BadAuthority("exa mple.com".into()),
        ),
        (
            RequestToSign {
                signature_agent: "https://agent.example/\u{e9}",
                ..ok
            },
            SignError::BadString("the Signature-Agent URL"),
        ),
        (
            RequestToSign {
                nonce: Some("a\nb"),
                ..ok
            },
            SignError::BadString("nonce"),
        ),
    ] {
        assert_eq!(sign_request(&k, &bad), Err(want));
    }
    assert_eq!(
        sign_directory(&[], "https", "example.com", 1, 2),
        Err(SignError::NoKeys)
    );
}

#[test]
fn nonce_is_optional() {
    let h = sign_request(
        &key(),
        &RequestToSign {
            scheme: "https",
            authority: "example.com",
            signature_agent: "https://agent.example",
            label: "sig1",
            created: 1,
            expires: 2,
            nonce: None,
        },
    )
    .unwrap();
    assert!(!h.signature_input.contains("nonce"));
    assert!(h.signature_input.ends_with(r#";tag="web-bot-auth""#));
}
