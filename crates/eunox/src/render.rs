//! The report as text, HTML and Prometheus metrics. Pure functions.
//!
//! Paths, bot markers and signer URLs come from requests, which clients
//! control: everything is escaped for HTML and Prometheus label values, and
//! metrics label agents by catalog id only, so clients can't create series.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use eunox_core::{Catalog, Class};
use eunox_directory::SourceStatus;
use eunox_stats::{CLASSES, RowKey, RowSummary, Summary};

/// Where the report page's feedback link goes. A plain link: the page never
/// sends anything to it, and nothing is fetched unless the reader clicks.
const FEEDBACK_URL: &str = "https://github.com/eunolabs/eunox/issues/new?template=feedback.yml";

/// Shown under the totals once any line has arrived over UDP syslog.
const UDP_NOTE: &str = "Some of these lines came over UDP syslog, which drops lines without a trace when the network or eunox falls behind, so counts can be low. Send through a log shipper to the TCP listener for exact counts.";

/// Ingest health totals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestTotals {
    /// Lines received.
    pub lines: u64,
    /// Records classified.
    pub records: u64,
    /// Lines that couldn't be parsed.
    pub parse_errors: u64,
    /// Datagrams received over UDP syslog.
    pub udp_datagrams: u64,
    /// The latest parse error.
    pub last_parse_error: Option<String>,
    /// Reverse-DNS lookups started.
    pub rdns_lookups: u64,
    /// Records sent on without reverse DNS because too many were in flight.
    pub rdns_skipped: u64,
}

/// Everything a report shows.
pub struct ReportData<'a> {
    /// Window counts.
    pub summary: &'a Summary,
    /// Lifetime counts per row.
    pub lifetime: &'a [(RowKey, u64)],
    /// Source freshness.
    pub sources: &'a [SourceStatus],
    /// Ingest health.
    pub ingest: &'a IngestTotals,
    /// For display names.
    pub catalog: &'a Catalog,
}

/// Rows shown in the text and HTML reports.
pub const ROWS_SHOWN: usize = 50;

fn name(key: &RowKey, catalog: &Catalog) -> String {
    key.agent
        .as_deref()
        .and_then(|id| catalog.get(id))
        .map_or_else(|| key.label.clone(), |a| a.name.clone())
}

/// The plain-text report (`/report.txt`, `eunox report`, `eunox replay`).
pub fn text(d: &ReportData<'_>) -> String {
    let s = d.summary;
    let mut out = String::new();
    match s.window_end_ms {
        None => {
            out.push_str("eunox report: no requests yet\n");
        }
        Some(end) => {
            let _ = writeln!(
                out,
                "eunox report: 24h window ending {}, {} requests",
                iso8601(end),
                thousands(s.total)
            );
            if d.ingest.udp_datagrams > 0 {
                let _ = writeln!(out, "{UDP_NOTE}");
            }
            out.push('\n');
            let _ = writeln!(
                out,
                "{:<28} {:<14} {:>9}  last seen",
                "agent", "class", "requests"
            );
            for row in s.rows.iter().take(ROWS_SHOWN) {
                let _ = writeln!(
                    out,
                    "{:<28} {:<14} {:>9}  {}",
                    clip(&name(&row.key, d.catalog), 28),
                    row.key.class.as_str(),
                    thousands(row.requests),
                    iso8601(row.last_seen_ms)
                );
            }
            if s.rows.len() > ROWS_SHOWN {
                let _ = writeln!(out, "… {} more rows", s.rows.len() - ROWS_SHOWN);
            }

            let spoofed: Vec<&RowSummary> = s
                .rows
                .iter()
                .filter(|r| r.key.class == Class::Spoofed)
                .collect();
            if !spoofed.is_empty() {
                out.push('\n');
            }
            for row in spoofed.iter().take(10) {
                let from = match row.top_networks.as_slice() {
                    [] => String::new(),
                    [(net, _)] => format!(" from {net}"),
                    [(net, _), rest @ ..] => {
                        format!(" from {net} and {} other networks", rest.len())
                    }
                };
                let _ = writeln!(
                    out,
                    "✗ {} ×{}{from}: no valid signature, fails its published IP checks",
                    name(&row.key, d.catalog),
                    thousands(row.requests)
                );
            }

            if !s.unknown_signers.is_empty() {
                out.push_str("\nsigned by unknown keys or schemes:\n");
                for u in s.unknown_signers.iter().take(20) {
                    let _ = writeln!(
                        out,
                        "  {:>7}  tag {}  Signature-Agent {}",
                        thousands(u.requests),
                        clip(&u.key.tags, 40),
                        clip(&u.key.signature_agent, 100)
                    );
                }
            }
        }
    }
    let warnings = warnings(d);
    if !warnings.is_empty() {
        out.push_str("\nwarnings:\n");
        for w in warnings {
            let _ = writeln!(out, "  {w}");
        }
    }
    out
}

fn warnings(d: &ReportData<'_>) -> Vec<String> {
    let mut w = Vec::new();
    for src in d.sources.iter().filter(|s| s.last_error.is_some()) {
        let state = if src.last_success.is_some() {
            "stale"
        } else {
            "not loaded"
        };
        w.push(format!(
            "source {} {state}: {}",
            src.id,
            clip(src.last_error.as_deref().unwrap_or(""), 120)
        ));
    }
    if d.ingest.parse_errors > 0 {
        w.push(format!(
            "{} lines couldn't be parsed; last: {}",
            thousands(d.ingest.parse_errors),
            clip(d.ingest.last_parse_error.as_deref().unwrap_or("?"), 120)
        ));
    }
    if d.ingest.rdns_skipped > 0 {
        w.push(format!(
            "{} requests skipped reverse DNS (too many lookups in flight)",
            thousands(d.ingest.rdns_skipped)
        ));
    }
    if d.summary.late + d.summary.future > 0 {
        w.push(format!(
            "{} lines older than the window and {} too far in the future were not counted",
            thousands(d.summary.late),
            thousands(d.summary.future)
        ));
    }
    w
}

/// The report page.
pub fn html(d: &ReportData<'_>) -> String {
    let s = d.summary;
    let mut out = String::from(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="15"><title>eunox report</title>
<style>
body{font:14px/1.45 system-ui,sans-serif;margin:24px auto;max-width:1100px;padding:0 16px;color:#1a1a1a;background:#fff}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #e5e5e5;vertical-align:top}
th{font-weight:600;color:#555}td.n{text-align:right;font-variant-numeric:tabular-nums}
.c{display:inline-block;padding:1px 7px;border-radius:9px;font-size:12px}
.verified{background:#d8f3dc}.ip-verified{background:#e3f0ff}.spoofed{background:#ffd6d6}.unknown-bot{background:#fff1c2}.unclassified{background:#eee}
.tiles{display:flex;gap:10px;flex-wrap:wrap}.tile{border:1px solid #e5e5e5;border-radius:8px;padding:10px 14px;min-width:120px}
.tile b{display:block;font-size:20px}small,.muted{color:#666}code{font-size:12px;word-break:break-all}
@media (prefers-color-scheme: dark){body{background:#111;color:#ddd}th{color:#aaa}th,td{border-color:#333}.tile{border-color:#333}
.verified{background:#1d4428}.ip-verified{background:#1b3150}.spoofed{background:#5a1f1f}.unknown-bot{background:#4a3d10}.unclassified{background:#333}small,.muted{color:#999}}
</style></head><body>
<h1>eunox report</h1>
"#,
    );
    match s.window_end_ms {
        None => out.push_str(
            "<p class=\"muted\">No requests yet. Point your gateway's access log at eunox.</p>\n",
        ),
        Some(end) => {
            let _ = writeln!(
                out,
                "<p class=\"muted\">24h window ending {}. {} requests.</p>",
                iso8601(end),
                thousands(s.total)
            );
            if d.ingest.udp_datagrams > 0 {
                let _ = writeln!(out, "<p class=\"muted\">{UDP_NOTE}</p>");
            }
            out.push_str("<div class=\"tiles\">\n");
            for (class, n) in &s.classes {
                let _ = writeln!(
                    out,
                    "<div class=\"tile\"><span class=\"c {c}\">{c}</span><b>{}</b></div>",
                    thousands(*n),
                    c = class.as_str()
                );
            }
            out.push_str("</div>\n<h2>Agents</h2>\n<table><tr><th>agent</th><th>class</th><th>requests</th><th>last seen</th><th>top paths</th><th>top networks</th></tr>\n");
            for row in s.rows.iter().take(ROWS_SHOWN) {
                let list = |items: &[(String, u64)]| -> String {
                    items
                        .iter()
                        .map(|(k, n)| {
                            format!("<code>{}</code> <small>{}</small>", esc(k), thousands(*n))
                        })
                        .collect::<Vec<_>>()
                        .join("<br>")
                };
                let _ = writeln!(
                    out,
                    "<tr><td>{}</td><td><span class=\"c {c}\">{c}</span></td><td class=\"n\">{}</td><td><small>{}</small></td><td>{}</td><td>{}</td></tr>",
                    esc(&name(&row.key, d.catalog)),
                    thousands(row.requests),
                    iso8601(row.last_seen_ms),
                    list(&row.top_paths),
                    list(&row.top_networks),
                    c = row.key.class.as_str()
                );
            }
            out.push_str("</table>\n");
            if !s.unknown_signers.is_empty() {
                out.push_str("<h2>Signed by unknown keys or schemes</h2>\n<table><tr><th>Signature-Agent</th><th>tag</th><th>requests</th><th>last seen</th></tr>\n");
                for u in s.unknown_signers.iter().take(50) {
                    let _ = writeln!(
                        out,
                        "<tr><td><code>{}</code></td><td><code>{}</code></td><td class=\"n\">{}</td><td><small>{}</small></td></tr>",
                        esc(&u.key.signature_agent),
                        esc(&u.key.tags),
                        thousands(u.requests),
                        iso8601(u.last_seen_ms)
                    );
                }
                out.push_str("</table>\n");
            }
        }
    }

    out.push_str("<h2>Sources</h2>\n<table><tr><th>source</th><th>items</th><th>last success</th><th>status</th></tr>\n");
    for src in d.sources {
        let status = match &src.last_error {
            None if src.last_success.is_some() => "ok".to_owned(),
            None => "pending".to_owned(),
            Some(e) => esc(&clip(e, 160)),
        };
        let _ = writeln!(
            out,
            "<tr><td>{}<br><small><code>{}</code></small></td><td class=\"n\">{}</td><td><small>{}</small></td><td>{status}</td></tr>",
            esc(&src.id),
            esc(&src.url),
            src.items,
            src.last_success
                .map_or_else(|| "never".into(), |t| iso8601(t * 1000))
        );
    }
    out.push_str("</table>\n<h2>Ingest</h2>\n");
    let i = d.ingest;
    let _ = writeln!(
        out,
        "<p class=\"muted\">{} lines, {} records, {} parse errors, {} reverse-DNS lookups, {} skipped.{}</p>",
        thousands(i.lines),
        thousands(i.records),
        thousands(i.parse_errors),
        thousands(i.rdns_lookups),
        thousands(i.rdns_skipped),
        i.last_parse_error
            .as_deref()
            .map_or_else(String::new, |e| format!(
                " Last parse error: <code>{}</code>",
                esc(&clip(e, 200))
            ))
    );
    let _ = writeln!(
        out,
        "<p class=\"muted\"><a href=\"/report.txt\">text</a> · <a href=\"/metrics\">metrics</a> · <a href=\"{FEEDBACK_URL}\" rel=\"noopener noreferrer\">how did it go? tell us</a></p>\n</body></html>"
    );
    out
}

/// Prometheus text exposition format.
pub fn metrics(d: &ReportData<'_>) -> String {
    let mut out = String::new();
    let mut by_agent: BTreeMap<(&'static str, &str), u64> = BTreeMap::new();
    for (key, n) in d.lifetime {
        *by_agent
            .entry((key.class.as_str(), key.agent.as_deref().unwrap_or("other")))
            .or_default() += n;
    }
    out.push_str("# HELP eunox_requests_total Requests classified, by class and catalog agent id (other for everything else).\n# TYPE eunox_requests_total counter\n");
    for ((class, agent), n) in &by_agent {
        let _ = writeln!(
            out,
            "eunox_requests_total{{class=\"{class}\",agent=\"{}\"}} {n}",
            label(agent)
        );
    }
    out.push_str("# HELP eunox_window_requests Requests in the 24h window, by class.\n# TYPE eunox_window_requests gauge\n");
    for class in CLASSES {
        let n = d
            .summary
            .classes
            .iter()
            .find(|(c, _)| *c == class)
            .map_or(0, |(_, n)| *n);
        let _ = writeln!(
            out,
            "eunox_window_requests{{class=\"{}\"}} {n}",
            class.as_str()
        );
    }
    let i = d.ingest;
    for (metric, help, n) in [
        ("eunox_ingest_lines_total", "Log lines received.", i.lines),
        (
            "eunox_ingest_records_total",
            "Log lines classified.",
            i.records,
        ),
        (
            "eunox_ingest_parse_errors_total",
            "Log lines that couldn't be parsed.",
            i.parse_errors,
        ),
        (
            "eunox_ingest_udp_datagrams_total",
            "Datagrams received over UDP syslog; compare with the gateway's own request count to estimate loss.",
            i.udp_datagrams,
        ),
        (
            "eunox_rdns_lookups_total",
            "Reverse-DNS lookups started.",
            i.rdns_lookups,
        ),
        (
            "eunox_rdns_skipped_total",
            "Requests sent on without reverse DNS because too many lookups were in flight.",
            i.rdns_skipped,
        ),
    ] {
        let _ = writeln!(
            out,
            "# HELP {metric} {help}\n# TYPE {metric} counter\n{metric} {n}"
        );
    }
    out.push_str("# HELP eunox_stats_dropped_total Records not counted, by reason.\n# TYPE eunox_stats_dropped_total counter\n");
    let _ = writeln!(
        out,
        "eunox_stats_dropped_total{{reason=\"late\"}} {}",
        d.summary.late
    );
    let _ = writeln!(
        out,
        "eunox_stats_dropped_total{{reason=\"future\"}} {}",
        d.summary.future
    );

    out.push_str("# HELP eunox_source_up Whether the last fetch of a key directory or range file succeeded.\n# TYPE eunox_source_up gauge\n");
    for s in d.sources {
        let up = u8::from(s.last_error.is_none() && s.last_success.is_some());
        let _ = writeln!(
            out,
            "eunox_source_up{{source=\"{}\",url=\"{}\"}} {up}",
            label(&s.id),
            label(&s.url)
        );
    }
    out.push_str("# HELP eunox_source_items Prefixes or keys held from a source.\n# TYPE eunox_source_items gauge\n");
    for s in d.sources {
        let _ = writeln!(
            out,
            "eunox_source_items{{source=\"{}\",url=\"{}\"}} {}",
            label(&s.id),
            label(&s.url),
            s.items
        );
    }
    out.push_str("# HELP eunox_source_last_success_timestamp_seconds Last successful fetch of a source.\n# TYPE eunox_source_last_success_timestamp_seconds gauge\n");
    for s in d.sources {
        if let Some(t) = s.last_success {
            let _ = writeln!(
                out,
                "eunox_source_last_success_timestamp_seconds{{source=\"{}\",url=\"{}\"}} {t}",
                label(&s.id),
                label(&s.url)
            );
        }
    }
    out
}

/// Escape for HTML text and attribute values.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Escape a Prometheus label value.
fn label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn clip(s: &str, max_chars: usize) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect();
    if s.chars().count() > max_chars {
        out.pop();
        out.push('…');
    }
    out
}

/// `1234567` → `1,234,567`.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Unix milliseconds as `2026-11-08T12:00:00Z`.
pub fn iso8601(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Inverse of days-from-civil (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_284), "1,284");
        assert_eq!(thousands(48_115), "48,115");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_735_689_660_000), "2025-01-01T00:01:00Z");
        assert_eq!(iso8601(1_709_164_800_000), "2024-02-29T00:00:00Z");
        assert_eq!(iso8601(1_794_139_200_999), "2026-11-08T12:00:00Z");
    }

    #[test]
    fn escaping() {
        assert_eq!(
            esc(r#"<script>alert("x")</script>&'"#),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#39;"
        );
        assert_eq!(label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        assert_eq!(clip("abc\u{7}def", 4), "abc…");
        assert_eq!(clip("abc", 4), "abc");
    }
}
