//! eunox stats: in-memory counters over classified requests.
//!
//! Counts requests per row (an agent, operator or bot marker, and its class)
//! in per-minute buckets over a rolling 24-hour window, plus each row's top
//! paths and client networks per hour, last-seen time and lifetime total.
//! Signed requests from unknown signers are also counted by `Signature-Agent`
//! origin, so operators that sign without a known key directory show up.
//!
//! Pure: no I/O and no clock. The window ends at the newest log timestamp
//! seen, so live traffic and a replayed log behave the same way. Callers pass
//! the current time only to reject timestamps far in the future, which would
//! otherwise drag the window forward and empty it.
//!
//! Row labels come partly from user agents, which clients control, so the
//! number of rows is capped; past the cap, new rows fold into `(other)`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::net::IpAddr;

use eunox_core::{Class, Failure, IpNet, Reason, catalog::signature_agent_urls};
use eunox_ingest::ClassifiedRecord;

/// Window length in minutes.
pub const WINDOW_MINUTES: i64 = 24 * 60;
/// Most rows kept; later new rows fold into `(other)`.
pub const MAX_ROWS: usize = 2_000;
/// Most unknown-signer rows kept.
pub const MAX_SIGNERS: usize = 500;
/// Timestamps further than this ahead of the caller's clock are rejected.
pub const MAX_FUTURE_MS: i64 = 10 * 60_000;
/// Paths and networks tracked per row per hour (space-saving).
const TOP_PER_HOUR: usize = 32;
/// Longest path kept, in bytes.
const MAX_PATH: usize = 200;

const HOURS: i64 = WINDOW_MINUTES / 60;

/// What a row counts.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RowKey {
    /// Catalog agent id, operator id, bot marker (`curl/`, `semrushbot`),
    /// `unknown signer`, or `(other)`.
    pub label: String,
    /// Catalog agent id, when the row is a catalog agent.
    pub agent: Option<String>,
    /// The class.
    pub class: Class,
}

impl RowKey {
    fn of(r: &ClassifiedRecord) -> Self {
        let label = match (&r.agent, &r.operator, &r.reason) {
            (Some(agent), _, _) => agent.clone(),
            (None, Some(op), _) => op.clone(),
            (None, None, Reason::BotUserAgent(marker)) => marker.clone(),
            (None, None, Reason::UnknownSigner) => "unknown signer".into(),
            _ => OTHER.into(),
        };
        Self {
            label,
            agent: r.agent.clone(),
            class: r.class,
        }
    }

    fn other(class: Class) -> Self {
        Self {
            label: OTHER.into(),
            agent: None,
            class,
        }
    }
}

const OTHER: &str = "(other)";

/// Per-minute counts over the window: slot `m % WINDOW_MINUTES` holds minute
/// `m`, and a slot holding an older minute is reset before use.
#[derive(Clone, Debug)]
struct Minutes(Vec<(i64, u64)>);

impl Minutes {
    fn new() -> Self {
        Self(vec![(i64::MIN, 0); WINDOW_MINUTES as usize])
    }

    fn add(&mut self, minute: i64) {
        let slot = &mut self.0[minute.rem_euclid(WINDOW_MINUTES) as usize];
        if slot.0 != minute {
            *slot = (minute, 0);
        }
        slot.1 += 1;
    }

    fn sum(&self, end_minute: i64) -> u64 {
        self.0
            .iter()
            .filter(|(m, _)| *m <= end_minute && *m > end_minute - WINDOW_MINUTES)
            .map(|(_, n)| n)
            .sum()
    }
}

/// Space-saving top-k: a fixed number of counters; a new key evicts the
/// smallest and inherits its count, so heavy hitters survive and counts are
/// upper bounds.
#[derive(Clone, Debug, Default)]
struct TopK(Vec<(String, u64)>);

impl TopK {
    fn add(&mut self, key: &str) {
        if let Some(entry) = self.0.iter_mut().find(|(k, _)| k == key) {
            entry.1 += 1;
        } else if self.0.len() < TOP_PER_HOUR {
            self.0.push((key.to_owned(), 1));
        } else if let Some(min) = self.0.iter_mut().min_by_key(|(_, n)| *n) {
            *min = (key.to_owned(), min.1 + 1);
        }
    }
}

#[derive(Clone, Debug)]
struct Hour {
    hour: i64,
    paths: TopK,
    networks: TopK,
}

#[derive(Clone, Debug)]
struct Row {
    minutes: Minutes,
    hours: Vec<Hour>,
    last_seen_ms: i64,
    lifetime: u64,
}

impl Row {
    fn new() -> Self {
        let empty = Hour {
            hour: i64::MIN,
            paths: TopK::default(),
            networks: TopK::default(),
        };
        Self {
            minutes: Minutes::new(),
            hours: vec![empty; HOURS as usize],
            last_seen_ms: i64::MIN,
            lifetime: 0,
        }
    }

    fn add(&mut self, ts_ms: i64, path: &str, network: &str) {
        let minute = ts_ms.div_euclid(60_000);
        let hour = minute.div_euclid(60);
        self.minutes.add(minute);
        // The minute window can span 25 distinct hours, so a late line's hour
        // can share a slot with the newest hour. Only a newer hour replaces a
        // slot; a line older than its slot still counts above, but skips the
        // hourly top lists, which never show its hour anyway.
        let slot = &mut self.hours[hour.rem_euclid(HOURS) as usize];
        if slot.hour < hour {
            *slot = Hour {
                hour,
                paths: TopK::default(),
                networks: TopK::default(),
            };
        }
        if slot.hour == hour {
            slot.paths.add(path);
            slot.networks.add(network);
        }
        self.last_seen_ms = self.last_seen_ms.max(ts_ms);
        self.lifetime += 1;
    }

    fn top(&self, end_minute: i64, n: usize, pick: impl Fn(&Hour) -> &TopK) -> Vec<(String, u64)> {
        let end_hour = end_minute.div_euclid(60);
        let mut merged: HashMap<&str, u64> = HashMap::new();
        for h in self
            .hours
            .iter()
            .filter(|h| h.hour <= end_hour && h.hour > end_hour - HOURS)
        {
            for (k, c) in &pick(h).0 {
                *merged.entry(k).or_default() += c;
            }
        }
        let mut v: Vec<(String, u64)> =
            merged.into_iter().map(|(k, c)| (k.to_owned(), c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

/// Key of an unknown-signer row.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignerKey {
    /// First `Signature-Agent` URL, or `(none)`.
    pub signature_agent: String,
    /// Signature tags, comma-separated, or `(none)`.
    pub tags: String,
}

#[derive(Clone, Debug)]
struct Signer {
    minutes: Minutes,
    last_seen_ms: i64,
}

/// One row of a [`Summary`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowSummary {
    /// What the row counts.
    pub key: RowKey,
    /// Requests in the window.
    pub requests: u64,
    /// Latest log timestamp seen for this row.
    pub last_seen_ms: i64,
    /// Most requested paths (query strings dropped), with approximate counts.
    pub top_paths: Vec<(String, u64)>,
    /// Most frequent client networks (/24 for IPv4, /48 for IPv6).
    pub top_networks: Vec<(String, u64)>,
}

/// One unknown-signer row of a [`Summary`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerSummary {
    /// Who signed, as far as the request says.
    pub key: SignerKey,
    /// Requests in the window.
    pub requests: u64,
    /// Latest log timestamp seen.
    pub last_seen_ms: i64,
}

/// The window's counts, for the report page and the text report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Newest log timestamp seen: the end of the window. `None` before the
    /// first record.
    pub window_end_ms: Option<i64>,
    /// Requests per class in the window, in class order, all five present.
    pub classes: Vec<(Class, u64)>,
    /// Requests in the window.
    pub total: u64,
    /// Rows with requests in the window, busiest first.
    pub rows: Vec<RowSummary>,
    /// Unknown-signer rows with requests in the window, busiest first.
    pub unknown_signers: Vec<SignerSummary>,
    /// Records dropped for being older than the window.
    pub late: u64,
    /// Records dropped for timestamps too far in the future.
    pub future: u64,
}

/// The counters.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    rows: HashMap<RowKey, Row>,
    signers: HashMap<SignerKey, Signer>,
    newest_ms: Option<i64>,
    late: u64,
    future: u64,
}

impl Stats {
    /// Empty counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one record. `now_ms` is the caller's clock, used only to reject
    /// timestamps more than [`MAX_FUTURE_MS`] ahead.
    pub fn record(&mut self, r: &ClassifiedRecord, now_ms: i64) {
        let ts = r.record.timestamp_ms;
        if ts > now_ms.saturating_add(MAX_FUTURE_MS) {
            self.future += 1;
            return;
        }
        let newest = self.newest_ms.map_or(ts, |n| n.max(ts));
        if ts.div_euclid(60_000) <= newest.div_euclid(60_000) - WINDOW_MINUTES {
            self.late += 1;
            return;
        }
        self.newest_ms = Some(newest);

        let key = RowKey::of(r);
        let key = if self.rows.contains_key(&key) || self.rows.len() < MAX_ROWS {
            key
        } else {
            RowKey::other(r.class)
        };
        let path = path_of(&r.record.target);
        let network = network_of(r.record.client_ip);
        self.rows
            .entry(key)
            .or_insert_with(Row::new)
            .add(ts, path, &network);

        if is_unknown_signer(r) {
            let key = SignerKey {
                signature_agent: r
                    .record
                    .signature_agent
                    .as_deref()
                    .and_then(|h| signature_agent_urls(h).into_iter().next())
                    .map_or_else(|| "(none)".into(), |u| truncate(&u, MAX_PATH).to_owned()),
                tags: if r.signature_tags.is_empty() {
                    "(none)".into()
                } else {
                    truncate(&r.signature_tags.join(","), MAX_PATH).to_owned()
                },
            };
            if self.signers.contains_key(&key) || self.signers.len() < MAX_SIGNERS {
                let s = self.signers.entry(key).or_insert_with(|| Signer {
                    minutes: Minutes::new(),
                    last_seen_ms: i64::MIN,
                });
                s.minutes.add(ts.div_euclid(60_000));
                s.last_seen_ms = s.last_seen_ms.max(ts);
            }
        }
    }

    /// Counts in the current window, with up to `top` paths and networks per
    /// row.
    pub fn summary(&self, top: usize) -> Summary {
        let Some(end) = self.newest_ms else {
            return Summary {
                window_end_ms: None,
                classes: CLASSES.iter().map(|c| (*c, 0)).collect(),
                total: 0,
                rows: Vec::new(),
                unknown_signers: Vec::new(),
                late: self.late,
                future: self.future,
            };
        };
        let end_minute = end.div_euclid(60_000);
        let mut rows: Vec<RowSummary> = self
            .rows
            .iter()
            .filter_map(|(key, row)| {
                let requests = row.minutes.sum(end_minute);
                (requests > 0).then(|| RowSummary {
                    key: key.clone(),
                    requests,
                    last_seen_ms: row.last_seen_ms,
                    top_paths: row.top(end_minute, top, |h| &h.paths),
                    top_networks: row.top(end_minute, top, |h| &h.networks),
                })
            })
            .collect();
        rows.sort_by(|a, b| b.requests.cmp(&a.requests).then_with(|| a.key.cmp(&b.key)));

        let classes: Vec<(Class, u64)> = CLASSES
            .iter()
            .map(|c| {
                let n = rows
                    .iter()
                    .filter(|r| r.key.class == *c)
                    .map(|r| r.requests)
                    .sum();
                (*c, n)
            })
            .collect();
        let total = classes.iter().map(|(_, n)| n).sum();

        let mut unknown_signers: Vec<SignerSummary> = self
            .signers
            .iter()
            .filter_map(|(key, s)| {
                let requests = s.minutes.sum(end_minute);
                (requests > 0).then(|| SignerSummary {
                    key: key.clone(),
                    requests,
                    last_seen_ms: s.last_seen_ms,
                })
            })
            .collect();
        unknown_signers.sort_by(|a, b| b.requests.cmp(&a.requests).then_with(|| a.key.cmp(&b.key)));

        Summary {
            window_end_ms: Some(end),
            classes,
            total,
            rows,
            unknown_signers,
            late: self.late,
            future: self.future,
        }
    }

    /// Lifetime request counts per row, for Prometheus counters.
    pub fn lifetime(&self) -> impl Iterator<Item = (&RowKey, u64)> {
        self.rows.iter().map(|(k, r)| (k, r.lifetime))
    }
}

/// All five classes, in precedence order.
pub const CLASSES: [Class; 5] = [
    Class::Verified,
    Class::IpVerified,
    Class::Spoofed,
    Class::UnknownBot,
    Class::Unclassified,
];

fn is_unknown_signer(r: &ClassifiedRecord) -> bool {
    r.reason == Reason::UnknownSigner
        || matches!(
            r.signature_failure,
            Some(Failure::UnknownKey { .. } | Failure::Unsupported(_))
        )
}

fn path_of(target: &str) -> &str {
    let path = target.split(['?', '#']).next().unwrap_or("/");
    truncate(if path.is_empty() { "/" } else { path }, MAX_PATH)
}

fn network_of(ip: IpAddr) -> String {
    let ip = ip.to_canonical();
    let prefix = if ip.is_ipv4() { 24 } else { 48 };
    IpNet::new(ip, prefix).map_or_else(|_| ip.to_string(), |n| n.to_string())
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}
