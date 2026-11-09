//! Classification tests: one per rule in the precedence order, plus the
//! edge cases where a wrong answer would mislabel real crawlers.

use std::collections::HashMap;
use std::net::IpAddr;

use eunox_core::{
    Catalog, Class, Classification, Failure, IpNet, Key, Observation, Outcome, Rdns, Reason,
    Request, Unverifiable, Verified, VerifyOptions, classify, verify,
};

const GPTBOT_UA: &str = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot";
const GOOGLEBOT_UA: &str =
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const SAFARI_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";

// Documentation prefixes (RFC 5737), standing in for published ranges.
const GPTBOT_IP: &str = "192.0.2.10";
const GOOGLE_IP: &str = "198.51.100.20";
const GOOGLE_AGENT_IP: &str = "198.51.100.200";
const ELSEWHERE_IP: &str = "203.0.113.99";

fn ranges() -> HashMap<String, Vec<IpNet>> {
    let set = |nets: &[&str]| nets.iter().map(|n| n.parse().unwrap()).collect();
    HashMap::from([
        ("openai-gptbot".to_owned(), set(&["192.0.2.0/25"])),
        ("openai-searchbot".to_owned(), set(&["192.0.2.128/26"])),
        ("openai-chatgpt-user".to_owned(), set(&["192.0.2.192/27"])),
        ("openai-adsbot".to_owned(), set(&["192.0.2.224/27"])),
        (
            "google-common-crawlers".to_owned(),
            set(&["198.51.100.0/25"]),
        ),
        (
            "google-user-triggered-agents".to_owned(),
            set(&["198.51.100.128/25"]),
        ),
    ])
}

fn obs<'a>(ua: &'a str, ip: &str) -> Observation<'a> {
    Observation {
        user_agent: ua,
        client_ip: ip.parse::<IpAddr>().unwrap(),
        signature_agent: None,
        signature: Outcome::Unsigned,
        rdns: Rdns::NotChecked,
    }
}

fn run<'c>(o: &Observation<'_>, catalog: &'c Catalog) -> Classification<'c> {
    classify(o, catalog, &ranges())
}

fn agent_id<'a>(c: &'a Classification<'_>) -> Option<&'a str> {
    c.agent.map(|a| a.id.as_str())
}

fn verified_by(operator: &str, signature_agent: Option<&str>) -> Outcome {
    Outcome::Verified(Verified {
        keyid: "k".into(),
        operator: operator.into(),
        signature_agent: signature_agent.map(Into::into),
        created: 100,
        expires: 200,
        nonce: None,
    })
}

fn failed(f: Failure) -> Outcome {
    Outcome::Failed(f)
}

fn expired_openai() -> Failure {
    Failure::Expired {
        keyid: "k".into(),
        operator: "openai".into(),
        expires: 200,
        at: 900,
    }
}

// ---- verified ----

#[test]
fn signature_wins_over_ip() {
    let c = Catalog::seed();
    let o = Observation {
        signature: verified_by("openai", None),
        ..obs(GPTBOT_UA, ELSEWHERE_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::Verified);
    assert_eq!(r.reason, Reason::Signature);
    assert_eq!(agent_id(&r), Some("openai-gptbot"));
    assert!(!r.claim_mismatch);
}

#[test]
fn signed_signature_agent_names_the_agent() {
    let c = Catalog::seed();
    let o = Observation {
        signature: verified_by("openai", Some("https://chatgpt.com")),
        ..obs(SAFARI_UA, ELSEWHERE_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::Verified);
    assert_eq!(agent_id(&r), Some("openai-chatgpt-agent"));
}

#[test]
fn verified_with_contradicting_user_agent_is_flagged() {
    let c = Catalog::seed();
    let o = Observation {
        signature: verified_by("anthropic", None),
        ..obs(GPTBOT_UA, ELSEWHERE_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::Verified);
    assert_eq!(r.operator.as_deref(), Some("anthropic"));
    assert_eq!(r.agent, None, "GPTBot isn't an Anthropic agent");
    assert!(r.claim_mismatch);
}

// ---- ip-verified ----

#[test]
fn published_range() {
    let c = Catalog::seed();
    let r = run(&obs(GPTBOT_UA, GPTBOT_IP), &c);
    assert_eq!(r.class, Class::IpVerified);
    assert_eq!(r.reason, Reason::PublishedRange);
    assert_eq!(agent_id(&r), Some("openai-gptbot"));
}

#[test]
fn ranges_are_per_agent() {
    // An IP in GPTBot's ranges doesn't verify a ChatGPT-User claim.
    let c = Catalog::seed();
    let r = run(&obs("ChatGPT-User/1.0", GPTBOT_IP), &c);
    assert_eq!(r.class, Class::Spoofed);
    assert_eq!(agent_id(&r), Some("openai-chatgpt-user"));
}

#[test]
fn published_range_without_reverse_dns() {
    let c = Catalog::seed();
    let r = run(&obs(GOOGLEBOT_UA, GOOGLE_IP), &c);
    assert_eq!(r.class, Class::IpVerified);
    assert_eq!(r.reason, Reason::PublishedRange);
    assert_eq!(agent_id(&r), Some("google-googlebot"));
}

#[test]
fn reverse_dns() {
    let c = Catalog::seed();
    let o = Observation {
        rdns: Rdns::Confirmed("crawl-1.googlebot.com"),
        ..obs(GOOGLEBOT_UA, ELSEWHERE_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::IpVerified);
    assert_eq!(r.reason, Reason::ReverseDns("crawl-1.googlebot.com".into()));
}

#[test]
fn expired_signature_from_operator_network_is_ip_verified() {
    // Genuine but expired (likely a clock problem), from OpenAI's ranges.
    let c = Catalog::seed();
    let o = Observation {
        signature: failed(expired_openai()),
        ..obs(SAFARI_UA, GPTBOT_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::IpVerified);
    assert_eq!(agent_id(&r), Some("openai-gptbot"));
    assert_eq!(r.signature_failure, Some(expired_openai()));
}

#[test]
fn broken_signature_falls_back_to_ip() {
    let c = Catalog::seed();
    let o = Observation {
        signature: failed(Failure::MissingComponent("content-digest".into())),
        ..obs(GPTBOT_UA, GPTBOT_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::IpVerified);
    assert!(r.signature_failure.is_some());
}

#[test]
fn second_claim_can_verify() {
    // User agent says GPTBot, unsigned Signature-Agent says Google-Agent, and
    // the IP is Google's: genuinely Google, with mismatched claims flagged.
    let c = Catalog::seed();
    let o = Observation {
        signature_agent: Some(r#""https://agent.bot.goog""#),
        ..obs(GPTBOT_UA, GOOGLE_AGENT_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::IpVerified);
    assert_eq!(agent_id(&r), Some("google-agent"));
    assert_eq!(r.operator.as_deref(), Some("google"));
    assert!(r.claim_mismatch);
}

// ---- spoofed ----

#[test]
fn forged_gptbot_is_spoofed() {
    let c = Catalog::seed();
    let r = run(&obs(GPTBOT_UA, ELSEWHERE_IP), &c);
    assert_eq!(r.class, Class::Spoofed);
    assert_eq!(r.reason, Reason::FailedIpChecks);
    assert_eq!(agent_id(&r), Some("openai-gptbot"));
}

#[test]
fn forged_gptbot_end_to_end_through_verify() {
    // The v0 "done when" case, from raw request fields.
    let c = Catalog::seed();
    let req = Request {
        method: "GET",
        scheme: "https",
        authority: "example.com",
        target: "/",
        ..Default::default()
    };
    let signature = verify(
        &req,
        &HashMap::<String, Key>::new(),
        1_000,
        &VerifyOptions::default(),
    );
    let o = Observation {
        signature,
        ..obs(GPTBOT_UA, ELSEWHERE_IP)
    };
    assert_eq!(run(&o, &c).class, Class::Spoofed);
}

#[test]
fn googlebot_failing_both_checks_is_spoofed() {
    let c = Catalog::seed();
    for rdns in [
        Rdns::Failed,
        Rdns::Confirmed("crawl.googlebot.com.evil.example"),
    ] {
        let o = Observation {
            rdns,
            ..obs(GOOGLEBOT_UA, ELSEWHERE_IP)
        };
        assert_eq!(run(&o, &c).class, Class::Spoofed, "{rdns:?}");
    }
}

#[test]
fn replayed_signature_from_elsewhere_is_spoofed() {
    let c = Catalog::seed();
    let o = Observation {
        signature: failed(expired_openai()),
        ..obs(SAFARI_UA, ELSEWHERE_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::Spoofed);
    assert_eq!(r.operator.as_deref(), Some("openai"));
    assert_eq!(r.agent, None, "the key names an operator, not an agent");
}

#[test]
fn bad_signature_claiming_known_key_is_spoofed() {
    let c = Catalog::seed();
    let f = Failure::BadSignature {
        keyid: "k".into(),
        operator: "openai".into(),
    };
    let o = Observation {
        signature: failed(f),
        ..obs(GPTBOT_UA, ELSEWHERE_IP)
    };
    assert_eq!(run(&o, &c).class, Class::Spoofed);
}

// ---- unknown-bot ----

#[test]
fn missing_data_is_never_spoofed() {
    let c = Catalog::seed();
    // Range set not loaded yet.
    let r = classify(
        &obs(GPTBOT_UA, ELSEWHERE_IP),
        &c,
        &HashMap::<String, Vec<IpNet>>::new(),
    );
    assert_eq!(r.class, Class::UnknownBot);
    assert_eq!(r.reason, Reason::Unverifiable(Unverifiable::MissingData));
    assert_eq!(agent_id(&r), Some("openai-gptbot"));

    // Outside Google's ranges, reverse DNS not looked up.
    let r = run(&obs(GOOGLEBOT_UA, ELSEWHERE_IP), &c);
    assert_eq!(r.class, Class::UnknownBot);
    assert_eq!(r.reason, Reason::Unverifiable(Unverifiable::MissingData));
}

#[test]
fn claim_with_no_published_method_is_unverifiable() {
    let c = Catalog::seed();
    let o = Observation {
        signature_agent: Some(r#""https://chatgpt.com""#),
        ..obs(SAFARI_UA, ELSEWHERE_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::UnknownBot);
    assert_eq!(
        r.reason,
        Reason::Unverifiable(Unverifiable::NoPublishedMethod)
    );
    assert_eq!(agent_id(&r), Some("openai-chatgpt-agent"));
}

#[test]
fn unknown_signer() {
    let c = Catalog::seed();
    let o = Observation {
        signature: failed(Failure::UnknownKey {
            keyid: "zzz".into(),
        }),
        ..obs(SAFARI_UA, ELSEWHERE_IP)
    };
    let r = run(&o, &c);
    assert_eq!(r.class, Class::UnknownBot);
    assert_eq!(r.reason, Reason::UnknownSigner);
}

#[test]
fn generic_bot_user_agent() {
    let c = Catalog::seed();
    let r = run(&obs("python-requests/2.32.3", ELSEWHERE_IP), &c);
    assert_eq!(r.class, Class::UnknownBot);
    assert_eq!(r.reason, Reason::BotUserAgent("python-requests".into()));
}

// ---- unclassified ----

#[test]
fn browser_is_unclassified() {
    let c = Catalog::seed();
    let r = run(&obs(SAFARI_UA, ELSEWHERE_IP), &c);
    assert_eq!(r.class, Class::Unclassified);
    assert_eq!(r.reason, Reason::NoBotSignals);
    assert_eq!(r.agent, None);
}
