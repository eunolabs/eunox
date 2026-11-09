//! Give every request exactly one class.
//!
//! Precedence, first match wins:
//! 1. `verified`: a Web Bot Auth signature from a known key. This overrides
//!    anything the user agent or IP says.
//! 2. `ip-verified`: claims a known agent, and the client IP is in that
//!    agent's published ranges or passes forward-confirmed reverse DNS.
//! 3. `spoofed`: claims a known agent, and every check that agent supports
//!    ran and failed.
//! 4. `unknown-bot`: a bot that can't be attributed, including a known-agent
//!    claim that can't be checked (no published method, or data not loaded).
//! 5. `unclassified`: everything else, presumed human.
//!
//! A request "claims" an agent through its user agent, an unverified
//! `Signature-Agent` header, or a failed signature whose key belongs to a
//! known operator. A failed signature on its own decides nothing: whatever
//! the reason, the IP checks decide. So a genuine signature replayed from the
//! operator's own network (a clock problem) is `ip-verified`, and one replayed
//! from elsewhere is `spoofed`.

use std::net::IpAddr;

use crate::catalog::{Agent, Catalog, generic_bot_marker, signature_agent_urls};
use crate::ip::IpRanges;
use crate::signature::{Failure, Outcome};

/// The facts about one request that classification needs.
#[derive(Clone, Debug)]
pub struct Observation<'a> {
    /// `User-Agent` header, verbatim.
    pub user_agent: &'a str,
    /// Client IP after trusted-proxy resolution. Getting this wrong marks real
    /// crawlers as spoofed.
    pub client_ip: IpAddr,
    /// `Signature-Agent` header, verbatim, signed or not.
    pub signature_agent: Option<&'a str>,
    /// Result of [`crate::verify`] on the request.
    pub signature: Outcome,
    /// Result of a forward-confirmed reverse-DNS lookup of `client_ip`.
    pub rdns: Rdns<'a>,
}

/// Forward-confirmed reverse DNS: the PTR name for the IP, which must resolve
/// back to the same IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rdns<'a> {
    /// Not looked up. Never read as a failure.
    NotChecked,
    /// No PTR record, or the name doesn't resolve back to the IP.
    Failed,
    /// The confirmed hostname.
    Confirmed(&'a str),
}

/// The five classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    /// Valid Web Bot Auth signature from a known key directory.
    Verified,
    /// Source IP matches the claimed agent's published ranges or reverse DNS.
    IpVerified,
    /// Claims a known agent but fails its checks.
    Spoofed,
    /// A bot that can't be attributed or verified.
    UnknownBot,
    /// Everything else, presumed human.
    Unclassified,
}

impl Class {
    /// The name used in reports and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Verified => "verified",
            Class::IpVerified => "ip-verified",
            Class::Spoofed => "spoofed",
            Class::UnknownBot => "unknown-bot",
            Class::Unclassified => "unclassified",
        }
    }
}

/// Why the class was chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Valid signature (`verified`).
    Signature,
    /// Client IP is in the agent's published ranges (`ip-verified`).
    PublishedRange,
    /// Reverse DNS confirmed this hostname (`ip-verified`).
    ReverseDns(String),
    /// Every supported check ran and failed (`spoofed`).
    FailedIpChecks,
    /// A known-agent claim that couldn't be checked (`unknown-bot`).
    Unverifiable(Unverifiable),
    /// Signed, but by no known operator (`unknown-bot`).
    UnknownSigner,
    /// Generic bot or automation user agent (`unknown-bot`).
    BotUserAgent(String),
    /// Nothing marks it as a bot (`unclassified`).
    NoBotSignals,
}

/// Why a known-agent claim couldn't be checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unverifiable {
    /// The agent publishes neither IP ranges nor reverse-DNS names.
    NoPublishedMethod,
    /// Its range set isn't loaded yet, or reverse DNS wasn't looked up.
    MissingData,
}

/// The result for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classification<'c> {
    /// The class.
    pub class: Class,
    /// The agent: the verified one for `verified` and `ip-verified`, the
    /// claimed one otherwise. `None` when only the operator is known, e.g. a
    /// signature from an operator's key with no matching catalog entry.
    pub agent: Option<&'c Agent>,
    /// Operator id, when known.
    pub operator: Option<String>,
    /// Why.
    pub reason: Reason,
    /// The request claimed more than one operator: a user agent or
    /// `Signature-Agent` disagreeing with a verified signature, or with each
    /// other.
    pub claim_mismatch: bool,
    /// The signature failure, if there was one, for reporting.
    pub signature_failure: Option<Failure>,
}

/// Classify one request.
pub fn classify<'c>(
    obs: &Observation<'_>,
    catalog: &'c Catalog,
    ranges: &impl IpRanges,
) -> Classification<'c> {
    let ua_agent = catalog.match_user_agent(obs.user_agent);
    let header_agent = obs
        .signature_agent
        .into_iter()
        .flat_map(signature_agent_urls)
        .find_map(|url| catalog.match_signature_agent(&url));

    let (signature_failure, key_operator) = match &obs.signature {
        Outcome::Verified(v) => {
            return verified(
                v.operator.clone(),
                v.signature_agent.as_deref(),
                ua_agent,
                catalog,
            );
        }
        Outcome::Unsigned => (None, None),
        Outcome::Failed(f) => (Some(f.clone()), failure_operator(f)),
    };

    // Everything the request claims to be, most specific first.
    let mut candidates: Vec<&'c Agent> = Vec::new();
    for agent in [ua_agent, header_agent].into_iter().flatten() {
        if !candidates.iter().any(|c| c.id == agent.id) {
            candidates.push(agent);
        }
    }
    let mut operators: Vec<&str> = candidates.iter().map(|a| a.operator.as_str()).collect();
    if let Some(op) = key_operator {
        operators.push(op);
        if candidates.is_empty() {
            candidates.extend(catalog.by_operator(op));
        }
    }
    operators.sort_unstable();
    operators.dedup();
    let claim_mismatch = operators.len() > 1;
    let primary = ua_agent.or(header_agent);
    let operator = primary
        .map(|a| a.operator.clone())
        .or_else(|| key_operator.map(str::to_owned));

    let result = |class, agent, reason| Classification {
        class,
        agent,
        operator: operator.clone(),
        reason,
        claim_mismatch,
        signature_failure: signature_failure.clone(),
    };

    if candidates.is_empty() {
        // A known operator's key, but no catalog entry to check its IPs by.
        if key_operator.is_some() {
            return result(
                Class::UnknownBot,
                None,
                Reason::Unverifiable(Unverifiable::NoPublishedMethod),
            );
        }
        // Sending signature headers at all marks an automated client.
        if signature_failure.is_some() {
            return result(Class::UnknownBot, None, Reason::UnknownSigner);
        }
        return match generic_bot_marker(obs.user_agent) {
            Some(marker) => result(Class::UnknownBot, None, Reason::BotUserAgent(marker)),
            None => result(Class::Unclassified, None, Reason::NoBotSignals),
        };
    }

    let mut missing_data = false;
    let mut any_check = false;
    for agent in &candidates {
        if let Some(set) = &agent.ip_ranges {
            any_check = true;
            match ranges.contains(set, obs.client_ip) {
                Some(true) => {
                    return Classification {
                        operator: Some(agent.operator.clone()),
                        ..result(Class::IpVerified, Some(agent), Reason::PublishedRange)
                    };
                }
                Some(false) => {}
                None => missing_data = true,
            }
        }
        if agent.uses_rdns() {
            any_check = true;
            match obs.rdns {
                Rdns::Confirmed(host) if agent.rdns_matches(host) => {
                    return Classification {
                        operator: Some(agent.operator.clone()),
                        ..result(
                            Class::IpVerified,
                            Some(agent),
                            Reason::ReverseDns(host.to_owned()),
                        )
                    };
                }
                Rdns::Confirmed(_) | Rdns::Failed => {}
                Rdns::NotChecked => missing_data = true,
            }
        }
    }

    // Only name an agent the request itself named; a key alone says which
    // operator, not which of its agents.
    let claimed = primary;
    if missing_data {
        result(
            Class::UnknownBot,
            claimed,
            Reason::Unverifiable(Unverifiable::MissingData),
        )
    } else if !any_check {
        result(
            Class::UnknownBot,
            claimed,
            Reason::Unverifiable(Unverifiable::NoPublishedMethod),
        )
    } else {
        result(Class::Spoofed, claimed, Reason::FailedIpChecks)
    }
}

fn verified<'c>(
    operator: String,
    signed_agent: Option<&str>,
    ua_agent: Option<&'c Agent>,
    catalog: &'c Catalog,
) -> Classification<'c> {
    // The signed Signature-Agent is authenticated, so it names the agent
    // first; the user agent is only a hint, used if it agrees on operator.
    let signed = signed_agent.and_then(|url| catalog.match_signature_agent(url));
    let agent = [signed, ua_agent]
        .into_iter()
        .flatten()
        .find(|a| a.operator == operator);
    let claim_mismatch = [signed, ua_agent]
        .into_iter()
        .flatten()
        .any(|a| a.operator != operator);
    Classification {
        class: Class::Verified,
        agent,
        operator: Some(operator),
        reason: Reason::Signature,
        claim_mismatch,
        signature_failure: None,
    }
}

/// The operator a failed signature's key belongs to, if it was a known key.
fn failure_operator(f: &Failure) -> Option<&str> {
    match f {
        Failure::BadSignature { operator, .. }
        | Failure::NotYetValid { operator, .. }
        | Failure::Expired { operator, .. } => Some(operator),
        Failure::Malformed(_)
        | Failure::MissingComponent(_)
        | Failure::Unsupported(_)
        | Failure::UnsupportedAlgorithm(_)
        | Failure::UnknownKey { .. } => None,
    }
}
