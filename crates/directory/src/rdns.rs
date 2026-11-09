//! Forward-confirmed reverse DNS with a cache.
//!
//! An IP's PTR record is controlled by whoever owns the IP, so a PTR name on
//! its own proves nothing. The name must also resolve forward to the same IP.
//! Matching the name against an operator's documented suffixes is left to
//! `eunox_core`.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use eunox_core::Rdns;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{Name, RData};

/// Outcome of one lookup, owned so it can be cached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RdnsResult {
    /// A definite negative: no PTR record, or no PTR name resolves back to
    /// the IP.
    Failed,
    /// A PTR name that resolves back to the IP.
    Confirmed(String),
    /// The resolver couldn't answer (timeout, SERVFAIL, unreachable). This is
    /// "couldn't check", never "failed": treating it as a failure would mark
    /// a real crawler as spoofed over a DNS outage. Not cached.
    Unavailable,
}

impl RdnsResult {
    /// The form `eunox_core::classify` takes.
    pub fn as_rdns(&self) -> Rdns<'_> {
        match self {
            RdnsResult::Failed => Rdns::Failed,
            RdnsResult::Confirmed(name) => Rdns::Confirmed(name),
            RdnsResult::Unavailable => Rdns::NotChecked,
        }
    }
}

/// Why a DNS query returned no records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// The name or record doesn't exist (NXDOMAIN, or no records of the type).
    NotFound,
    /// No answer: timeout, SERVFAIL, resolver unreachable.
    Unavailable(String),
}

/// The two DNS queries FCrDNS needs. Implemented with hickory for real use
/// and by a fixture in tests.
pub trait DnsLookup: Send + Sync {
    /// PTR names for `ip`.
    fn ptr(&self, ip: IpAddr) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
    /// A and AAAA addresses for `name`.
    fn addrs(&self, name: &str) -> impl Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;
}

fn dns_error(e: hickory_resolver::net::NetError) -> DnsError {
    if e.is_no_records_found() {
        DnsError::NotFound
    } else {
        DnsError::Unavailable(e.to_string())
    }
}

impl DnsLookup for TokioResolver {
    async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        let lookup = self
            .reverse_lookup(Name::from(ip))
            .await
            .map_err(dns_error)?;
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::PTR(ptr) => Some(ptr.0.to_ascii()),
                _ => None,
            })
            .collect())
    }

    async fn addrs(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        let fqdn = if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.")
        };
        let lookup = self.lookup_ip(fqdn.as_str()).await.map_err(dns_error)?;
        Ok(lookup.iter().collect())
    }
}

/// Most PTR names checked per IP. Real crawlers have one.
const MAX_PTR_NAMES: usize = 4;

/// Cached FCrDNS.
pub struct FcrDns<L> {
    dns: L,
    cache: Mutex<HashMap<IpAddr, (RdnsResult, Instant)>>,
    confirmed_ttl: Duration,
    failed_ttl: Duration,
    max_entries: usize,
}

impl FcrDns<TokioResolver> {
    /// Using the system resolver configuration.
    pub fn system() -> Result<Self, String> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| e.to_string())?
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self::new(resolver))
    }
}

impl<L: DnsLookup> FcrDns<L> {
    /// Wrap a lookup implementation. Confirmed results are cached for an
    /// hour and definite failures for five minutes, up to 100k IPs.
    /// Resolver errors aren't cached, so the next request retries.
    pub fn new(dns: L) -> Self {
        Self {
            dns,
            cache: Mutex::new(HashMap::new()),
            confirmed_ttl: Duration::from_secs(3600),
            failed_ttl: Duration::from_secs(300),
            max_entries: 100_000,
        }
    }

    /// Forward-confirmed reverse DNS for `ip`.
    pub async fn check(&self, ip: IpAddr) -> RdnsResult {
        let ip = ip.to_canonical();
        let now = Instant::now();
        if let Some((result, expires)) = self.lock().get(&ip)
            && *expires > now
        {
            return result.clone();
        }
        let result = self.lookup(ip).await;
        let ttl = match result {
            RdnsResult::Confirmed(_) => self.confirmed_ttl,
            RdnsResult::Failed => self.failed_ttl,
            RdnsResult::Unavailable => return result,
        };
        let mut cache = self.lock();
        if cache.len() >= self.max_entries {
            cache.retain(|_, (_, expires)| *expires > now);
            if cache.len() >= self.max_entries {
                cache.clear();
            }
        }
        cache.insert(ip, (result.clone(), now + ttl));
        result
    }

    async fn lookup(&self, ip: IpAddr) -> RdnsResult {
        let names = match self.dns.ptr(ip).await {
            Ok(names) => names,
            Err(DnsError::NotFound) => return RdnsResult::Failed,
            Err(DnsError::Unavailable(_)) => return RdnsResult::Unavailable,
        };
        // Only a definite answer for every name checked is a failure. If a
        // forward lookup couldn't be answered, that name might have confirmed.
        let mut unanswered = false;
        for name in names.into_iter().take(MAX_PTR_NAMES) {
            match self.dns.addrs(&name).await {
                Ok(addrs) if addrs.iter().any(|a| a.to_canonical() == ip) => {
                    return RdnsResult::Confirmed(name.trim_end_matches('.').to_owned());
                }
                Ok(_) | Err(DnsError::NotFound) => {}
                Err(DnsError::Unavailable(_)) => unanswered = true,
            }
        }
        if unanswered {
            RdnsResult::Unavailable
        } else {
            RdnsResult::Failed
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, (RdnsResult, Instant)>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture {
        ptr: HashMap<IpAddr, Vec<String>>,
        a: HashMap<String, Vec<IpAddr>>,
        /// IPs and names whose queries get no answer.
        unavailable: Vec<String>,
        calls: AtomicUsize,
    }

    impl DnsLookup for Fixture {
        async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.unavailable.contains(&ip.to_string()) {
                return Err(DnsError::Unavailable("timed out".into()));
            }
            self.ptr.get(&ip).cloned().ok_or(DnsError::NotFound)
        }
        async fn addrs(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
            if self.unavailable.iter().any(|u| u == name) {
                return Err(DnsError::Unavailable("SERVFAIL".into()));
            }
            self.a.get(name).cloned().ok_or(DnsError::NotFound)
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn fixture() -> Fixture {
        Fixture {
            ptr: HashMap::from([
                (
                    ip("66.249.66.1"),
                    vec!["crawl-66-249-66-1.googlebot.com.".into()],
                ),
                // Attacker-controlled PTR claiming Google, with no forward record back.
                (ip("203.0.113.5"), vec!["crawl-1.googlebot.com.".into()]),
                (ip("192.0.2.2"), vec!["crawl-2.googlebot.com.".into()]),
            ]),
            a: HashMap::from([
                (
                    "crawl-66-249-66-1.googlebot.com.".into(),
                    vec![ip("66.249.66.1")],
                ),
                ("crawl-1.googlebot.com.".into(), vec![ip("66.249.66.99")]),
            ]),
            unavailable: vec![
                // Resolver times out on this IP's PTR query.
                "192.0.2.1".into(),
                // PTR answers, but the forward query gets SERVFAIL.
                "crawl-2.googlebot.com.".into(),
            ],
            calls: AtomicUsize::new(0),
        }
    }

    #[tokio::test]
    async fn confirmed_only_when_forward_matches() {
        let f = FcrDns::new(fixture());
        assert_eq!(
            f.check(ip("66.249.66.1")).await,
            RdnsResult::Confirmed("crawl-66-249-66-1.googlebot.com".into())
        );
        assert_eq!(
            f.check(ip("203.0.113.5")).await,
            RdnsResult::Failed,
            "PTR alone proves nothing"
        );
        assert_eq!(
            f.check(ip("198.51.100.1")).await,
            RdnsResult::Failed,
            "no PTR"
        );
    }

    #[tokio::test]
    async fn v4_mapped_clients_are_canonicalized() {
        let f = FcrDns::new(fixture());
        assert!(matches!(
            f.check(ip("::ffff:66.249.66.1")).await,
            RdnsResult::Confirmed(_)
        ));
    }

    #[tokio::test]
    async fn results_are_cached() {
        let f = FcrDns::new(fixture());
        f.check(ip("66.249.66.1")).await;
        f.check(ip("66.249.66.1")).await;
        f.check(ip("198.51.100.1")).await;
        f.check(ip("198.51.100.1")).await;
        assert_eq!(f.dns.calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn resolver_errors_are_unavailable_not_failed() {
        let f = FcrDns::new(fixture());
        assert_eq!(
            f.check(ip("192.0.2.1")).await,
            RdnsResult::Unavailable,
            "PTR timeout"
        );
        assert_eq!(
            f.check(ip("192.0.2.2")).await,
            RdnsResult::Unavailable,
            "forward SERVFAIL"
        );
        // classify reads it as "not checked", never as a failed check.
        assert_eq!(RdnsResult::Unavailable.as_rdns(), Rdns::NotChecked);
    }

    #[tokio::test]
    async fn resolver_errors_are_not_cached() {
        let f = FcrDns::new(fixture());
        f.check(ip("192.0.2.1")).await;
        f.check(ip("192.0.2.1")).await;
        assert_eq!(
            f.dns.calls.load(Ordering::Relaxed),
            2,
            "retried, not served from cache"
        );
    }
}
