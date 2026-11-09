use std::net::IpAddr;

use eunox_core::{Class, Failure, Reason};
use eunox_ingest::{ClassifiedRecord, RequestRecord, SessionKey};
use eunox_stats::{MAX_FUTURE_MS, MAX_ROWS, RowKey, Stats};

const T0: i64 = 1_794_139_200_000; // 2026-11-08T12:00:00Z
const MIN: i64 = 60_000;
const HOUR: i64 = 60 * MIN;

fn rec(
    ts: i64,
    ip: &str,
    path: &str,
    class: Class,
    agent: Option<&str>,
    reason: Reason,
) -> ClassifiedRecord {
    let client_ip: IpAddr = ip.parse().unwrap();
    ClassifiedRecord {
        record: RequestRecord {
            timestamp_ms: ts,
            method: "GET".into(),
            scheme: "https".into(),
            authority: "example.com".into(),
            target: path.into(),
            client_ip,
            user_agent: "ua".into(),
            status: None,
            signature: None,
            signature_input: None,
            signature_agent: None,
        },
        class,
        agent: agent.map(Into::into),
        operator: agent.map(|a| a.split('-').next().unwrap().to_owned()),
        reason,
        claim_mismatch: false,
        signature_failure: None,
        signature_tags: vec![],
        session: SessionKey::Heuristic {
            client_ip,
            user_agent: "ua".into(),
        },
    }
}

fn spoofed_gptbot(ts: i64, ip: &str, path: &str) -> ClassifiedRecord {
    rec(
        ts,
        ip,
        path,
        Class::Spoofed,
        Some("openai-gptbot"),
        Reason::FailedIpChecks,
    )
}

fn browser(ts: i64) -> ClassifiedRecord {
    rec(
        ts,
        "198.18.0.1",
        "/",
        Class::Unclassified,
        None,
        Reason::NoBotSignals,
    )
}

fn key(label: &str, agent: Option<&str>, class: Class) -> RowKey {
    RowKey {
        label: label.into(),
        agent: agent.map(Into::into),
        class,
    }
}

#[test]
fn counts_rows_and_classes() {
    let mut s = Stats::new();
    for i in 0..3 {
        s.record(&spoofed_gptbot(T0 + i * MIN, "203.0.113.7", "/pricing"), T0);
    }
    s.record(
        &rec(
            T0,
            "192.0.2.1",
            "/",
            Class::IpVerified,
            Some("openai-gptbot"),
            Reason::PublishedRange,
        ),
        T0,
    );
    s.record(
        &rec(
            T0,
            "203.0.113.9",
            "/api",
            Class::UnknownBot,
            None,
            Reason::BotUserAgent("curl/".into()),
        ),
        T0,
    );
    s.record(&browser(T0), T0);

    let sum = s.summary(5);
    assert_eq!(sum.total, 6);
    assert_eq!(sum.window_end_ms, Some(T0 + 2 * MIN));
    assert_eq!(
        sum.classes,
        [
            (Class::Verified, 0),
            (Class::IpVerified, 1),
            (Class::Spoofed, 3),
            (Class::UnknownBot, 1),
            (Class::Unclassified, 1),
        ]
    );
    assert_eq!(
        sum.rows[0].key,
        key("openai-gptbot", Some("openai-gptbot"), Class::Spoofed)
    );
    assert_eq!(sum.rows[0].requests, 3);
    assert_eq!(sum.rows[0].last_seen_ms, T0 + 2 * MIN);
    let labels: Vec<&str> = sum.rows.iter().map(|r| r.key.label.as_str()).collect();
    assert!(
        labels.contains(&"curl/"),
        "bot marker is the label: {labels:?}"
    );
    assert!(
        labels.contains(&"(other)"),
        "browsers fold into (other): {labels:?}"
    );
}

#[test]
fn window_slides_with_the_newest_log_line() {
    let mut s = Stats::new();
    s.record(&spoofed_gptbot(T0, "203.0.113.7", "/"), T0 + 30 * HOUR);
    s.record(
        &spoofed_gptbot(T0 + 23 * HOUR, "203.0.113.7", "/"),
        T0 + 30 * HOUR,
    );
    assert_eq!(s.summary(5).total, 2);

    // 25 hours later: the first one falls out.
    s.record(
        &spoofed_gptbot(T0 + 25 * HOUR, "203.0.113.7", "/"),
        T0 + 30 * HOUR,
    );
    let sum = s.summary(5);
    assert_eq!(sum.total, 2);
    assert_eq!(sum.window_end_ms, Some(T0 + 25 * HOUR));

    // A line older than the window is dropped and counted.
    s.record(
        &spoofed_gptbot(T0 - HOUR, "203.0.113.7", "/"),
        T0 + 30 * HOUR,
    );
    let sum = s.summary(5);
    assert_eq!(sum.total, 2);
    assert_eq!(sum.late, 1);

    // Lifetime counts keep everything that was accepted.
    let lifetime: u64 = s.lifetime().map(|(_, n)| n).sum();
    assert_eq!(lifetime, 3);
}

#[test]
fn replayed_old_logs_report_their_own_window() {
    let mut s = Stats::new();
    let a_month_ago = T0 - 30 * 24 * HOUR;
    s.record(&spoofed_gptbot(a_month_ago, "203.0.113.7", "/"), T0);
    assert_eq!(
        s.summary(5).total,
        1,
        "window ends at the newest line, not the clock"
    );
}

#[test]
fn far_future_timestamps_are_rejected() {
    let mut s = Stats::new();
    s.record(&spoofed_gptbot(T0, "203.0.113.7", "/"), T0);
    s.record(
        &spoofed_gptbot(T0 + MAX_FUTURE_MS + MIN, "203.0.113.7", "/"),
        T0,
    );
    let sum = s.summary(5);
    assert_eq!(sum.future, 1);
    assert_eq!(sum.total, 1, "a bogus timestamp can't empty the window");
    assert_eq!(sum.window_end_ms, Some(T0));
    s.record(
        &spoofed_gptbot(T0 + MAX_FUTURE_MS - MIN, "203.0.113.7", "/"),
        T0,
    );
    assert_eq!(s.summary(5).total, 2, "small clock skew is fine");
}

#[test]
fn top_paths_and_networks() {
    let mut s = Stats::new();
    for (ip, path) in [
        ("203.0.113.7", "/pricing?utm=a"),
        ("203.0.113.8", "/pricing?utm=b"),
        ("203.0.113.9", "/pricing"),
        ("198.51.100.4", "/docs#intro"),
        ("2001:db8:1:2::5", ""),
    ] {
        s.record(&spoofed_gptbot(T0, ip, path), T0);
    }
    let row = &s.summary(2).rows[0];
    assert_eq!(
        row.top_paths,
        [("/pricing".to_owned(), 3), ("/".to_owned(), 1)]
    );
    assert_eq!(row.top_networks[0], ("203.0.113.0/24".to_owned(), 3));
    let all = &s.summary(10).rows[0].top_networks;
    assert!(all.contains(&("2001:db8:1::/48".to_owned(), 1)), "{all:?}");
}

#[test]
fn top_paths_cover_the_window_across_hours() {
    let mut s = Stats::new();
    s.record(&spoofed_gptbot(T0, "203.0.113.7", "/a"), T0 + 30 * HOUR);
    s.record(
        &spoofed_gptbot(T0 + 2 * HOUR, "203.0.113.7", "/a"),
        T0 + 30 * HOUR,
    );
    s.record(
        &spoofed_gptbot(T0 + 2 * HOUR, "203.0.113.7", "/b"),
        T0 + 30 * HOUR,
    );
    assert_eq!(s.summary(5).rows[0].top_paths[0], ("/a".to_owned(), 2));
    // Once T0's hour leaves the window, its paths go too.
    s.record(
        &spoofed_gptbot(T0 + 25 * HOUR, "203.0.113.7", "/c"),
        T0 + 30 * HOUR,
    );
    let paths = s.summary(5).rows[0].top_paths.clone();
    assert!(paths.contains(&("/a".to_owned(), 1)), "{paths:?}");
}

#[test]
fn heavy_hitter_survives_many_distinct_paths() {
    let mut s = Stats::new();
    for i in 0..500 {
        s.record(&spoofed_gptbot(T0, "203.0.113.7", "/hot"), T0);
        s.record(
            &spoofed_gptbot(T0, "203.0.113.7", &format!("/cold/{i}")),
            T0,
        );
    }
    let row = &s.summary(1).rows[0];
    assert_eq!(row.top_paths[0].0, "/hot");
    assert!(row.top_paths[0].1 >= 500);
}

#[test]
fn attacker_chosen_labels_are_capped() {
    let mut s = Stats::new();
    for i in 0..MAX_ROWS + 50 {
        let marker = format!("x{i}bot");
        s.record(
            &rec(
                T0,
                "203.0.113.7",
                "/",
                Class::UnknownBot,
                None,
                Reason::BotUserAgent(marker),
            ),
            T0,
        );
    }
    let sum = s.summary(1);
    assert_eq!(sum.rows.len(), MAX_ROWS + 1, "existing rows plus (other)");
    let other = sum
        .rows
        .iter()
        .find(|r| r.key == key("(other)", None, Class::UnknownBot))
        .unwrap();
    assert_eq!(other.requests, 50);
    assert_eq!(sum.total, (MAX_ROWS + 50) as u64);
}

#[test]
fn unknown_signers_by_signature_agent() {
    let mut s = Stats::new();
    let mut r = rec(
        T0,
        "203.0.113.7",
        "/",
        Class::UnknownBot,
        None,
        Reason::UnknownSigner,
    );
    r.record.signature_agent = Some(
        r#"agent1="https://signer.example/.well-known/http-message-signatures-directory""#.into(),
    );
    r.signature_tags = vec!["web-bot-auth".into()];
    r.signature_failure = Some(Failure::UnknownKey { keyid: "k".into() });
    s.record(&r, T0);
    s.record(&r, T0);

    let mut tap = rec(
        T0,
        "203.0.113.8",
        "/checkout",
        Class::UnknownBot,
        None,
        Reason::UnknownSigner,
    );
    tap.signature_tags = vec!["agent-payer-auth".into()];
    tap.signature_failure = Some(Failure::Unsupported(
        "signature tag agent-payer-auth".into(),
    ));
    s.record(&tap, T0);

    // A known operator's bad signature isn't an unknown signer.
    let mut forged = spoofed_gptbot(T0, "203.0.113.9", "/");
    forged.signature_failure = Some(Failure::BadSignature {
        keyid: "k".into(),
        operator: "openai".into(),
    });
    s.record(&forged, T0);

    let signers = s.summary(5).unknown_signers;
    assert_eq!(signers.len(), 2);
    assert_eq!(
        signers[0].key.signature_agent,
        "https://signer.example/.well-known/http-message-signatures-directory"
    );
    assert_eq!(signers[0].key.tags, "web-bot-auth");
    assert_eq!(signers[0].requests, 2);
    assert_eq!(signers[1].key.signature_agent, "(none)");
    assert_eq!(signers[1].key.tags, "agent-payer-auth");
}

#[test]
fn empty_summary() {
    let sum = Stats::new().summary(5);
    assert_eq!(sum.window_end_ms, None);
    assert_eq!(sum.total, 0);
    assert_eq!(sum.classes.len(), 5);
}

#[test]
fn a_line_exactly_24_hours_old_is_outside_the_window() {
    let mut s = Stats::new();
    s.record(&spoofed_gptbot(T0, "203.0.113.7", "/"), T0 + 30 * HOUR);
    s.record(
        &spoofed_gptbot(T0 + 24 * HOUR, "203.0.113.7", "/"),
        T0 + 30 * HOUR,
    );
    assert_eq!(s.summary(5).total, 1);
    // One minute less than 24 hours: still inside.
    let mut s = Stats::new();
    s.record(
        &spoofed_gptbot(T0 + MIN, "203.0.113.7", "/"),
        T0 + 30 * HOUR,
    );
    s.record(
        &spoofed_gptbot(T0 + 24 * HOUR, "203.0.113.7", "/"),
        T0 + 30 * HOUR,
    );
    assert_eq!(s.summary(5).total, 2);
}

#[test]
fn a_late_line_does_not_wipe_the_newest_hours_top_lists() {
    // The newest line is at 12:30. A line from 12:31 the day before is still
    // inside the 24h minute window, but its hour (12:00 yesterday) shares a
    // ring slot with 12:00 today.
    let mut s = Stats::new();
    let now = T0 + 30 * MIN;
    s.record(&spoofed_gptbot(now, "203.0.113.7", "/now"), now);
    s.record(
        &spoofed_gptbot(now - 24 * HOUR + MIN, "198.51.100.9", "/late"),
        now,
    );

    let row = &s.summary(5).rows[0];
    assert_eq!(row.requests, 2, "the late line still counts");
    assert!(
        row.top_paths.contains(&("/now".to_owned(), 1)),
        "current hour's paths survive: {:?}",
        row.top_paths
    );
    assert!(
        row.top_networks.contains(&("203.0.113.0/24".to_owned(), 1)),
        "current hour's networks survive: {:?}",
        row.top_networks
    );
}
