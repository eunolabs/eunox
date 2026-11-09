//! From a log line to a classified record.
//!
//! Each line is parsed, its signature verified at the log timestamp, and the
//! request classified. Reverse DNS runs only when it could change the answer:
//! the request claims an agent verified that way, and the IP checks alone
//! came out "missing data". Those lookups run in the background with a cap on
//! how many are in flight, so a slow resolver can't stall ingest; past the
//! cap the record goes out unverified (`unknown-bot`), never `spoofed`.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use eunox_core::{
    Catalog, Class, Failure, Observation, Outcome, Rdns, Reason, Request, Unverifiable,
    VerifyOptions, classify, signature_tags, verify,
};
use eunox_directory::rdns::DnsError;
use eunox_directory::{DnsLookup, FcrDns, Snapshot};
use tokio::sync::Semaphore;

use crate::record::{RequestRecord, json_payload, parse_nginx_json};

/// Who a request's session belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SessionKey {
    /// A verified signature: the operator and the key it signed with. Stable
    /// across IPs.
    Signed {
        /// Operator owning the key.
        operator: String,
        /// The signature's `keyid`.
        keyid: String,
    },
    /// No verified signature: client IP plus user agent. A heuristic only;
    /// agents behind shared cloud egress collide.
    Heuristic {
        /// Client IP.
        client_ip: IpAddr,
        /// User agent.
        user_agent: String,
    },
}

/// A request and how it was classified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassifiedRecord {
    /// The request.
    pub record: RequestRecord,
    /// Its class.
    pub class: Class,
    /// Catalog id of the verified or claimed agent.
    pub agent: Option<String>,
    /// Operator id, when known.
    pub operator: Option<String>,
    /// Why it got that class.
    pub reason: Reason,
    /// The request claimed more than one operator.
    pub claim_mismatch: bool,
    /// Why its signature didn't verify, if it had one.
    pub signature_failure: Option<Failure>,
    /// `tag` of each `Signature-Input` label, e.g. `web-bot-auth` or
    /// `agent-payer-auth`.
    pub signature_tags: Vec<String>,
    /// Session the request belongs to.
    pub session: SessionKey,
}

/// Where classified records go (counters, a printer, a test).
pub trait RecordSink: Send + Sync + 'static {
    /// Take one record. Called on ingest's own tasks; keep it cheap.
    fn accept(&self, record: ClassifiedRecord);
}

impl<F: Fn(ClassifiedRecord) + Send + Sync + 'static> RecordSink for F {
    fn accept(&self, record: ClassifiedRecord) {
        self(record)
    }
}

/// Ingest health, for the report page.
#[derive(Debug, Default)]
pub struct IngestCounters {
    /// Non-empty lines received.
    pub lines: AtomicU64,
    /// Lines turned into classified records.
    pub records: AtomicU64,
    /// Lines that couldn't be parsed.
    pub parse_errors: AtomicU64,
    /// Datagrams received over UDP syslog. UDP loss between the gateway and
    /// eunox leaves no trace, so the report flags counts that include these.
    pub udp_datagrams: AtomicU64,
    /// Reverse-DNS lookups started.
    pub rdns_lookups: AtomicU64,
    /// Records sent on without reverse DNS because too many were in flight.
    pub rdns_skipped: AtomicU64,
    /// The latest parse error, to show what's wrong with the log format.
    pub last_parse_error: Mutex<Option<String>>,
}

impl IngestCounters {
    fn parse_error(&self, why: String) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
        *self
            .last_parse_error
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(why);
    }
}

/// A resolver that never answers, for pipelines built without reverse DNS:
/// `Pipeline::<NoDns>::new(.., None, ..)`.
pub struct NoDns;

impl DnsLookup for NoDns {
    async fn ptr(&self, _: IpAddr) -> Result<Vec<String>, DnsError> {
        Err(DnsError::Unavailable("reverse DNS disabled".into()))
    }
    async fn addrs(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
        Err(DnsError::Unavailable("reverse DNS disabled".into()))
    }
}

/// Default cap on reverse-DNS lookups in flight.
pub const DEFAULT_RDNS_IN_FLIGHT: usize = 256;

/// Classifies log lines and hands the results to a sink.
pub struct Pipeline<L> {
    catalog: Arc<Catalog>,
    snapshots: Arc<dyn Fn() -> Arc<Snapshot> + Send + Sync>,
    rdns: Option<Arc<FcrDns<L>>>,
    rdns_slots: Arc<Semaphore>,
    sink: Arc<dyn RecordSink>,
    verify: VerifyOptions,
    counters: Arc<IngestCounters>,
}

impl<L: DnsLookup + 'static> Pipeline<L> {
    /// A pipeline over `catalog`, reading keys and ranges from `snapshots`
    /// (typically `move || directory.snapshot()`). Pass `rdns: None` to skip
    /// reverse DNS; agents verified only that way then come out unverifiable.
    pub fn new(
        catalog: Arc<Catalog>,
        snapshots: Arc<dyn Fn() -> Arc<Snapshot> + Send + Sync>,
        rdns: Option<Arc<FcrDns<L>>>,
        sink: Arc<dyn RecordSink>,
    ) -> Self {
        Self {
            catalog,
            snapshots,
            rdns,
            rdns_slots: Arc::new(Semaphore::new(DEFAULT_RDNS_IN_FLIGHT)),
            sink,
            verify: VerifyOptions::default(),
            counters: Arc::default(),
        }
    }

    /// Cap concurrent reverse-DNS lookups.
    pub fn with_rdns_in_flight(mut self, max: usize) -> Self {
        self.rdns_slots = Arc::new(Semaphore::new(max));
        self
    }

    /// Ingest health counters.
    pub fn counters(&self) -> &Arc<IngestCounters> {
        &self.counters
    }

    /// Handle one log line: a bare JSON object or a syslog message carrying
    /// one. Blank lines are ignored. Must run inside a Tokio runtime when
    /// reverse DNS is enabled.
    pub fn handle_line(&self, line: &[u8]) {
        if line.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        self.counters.lines.fetch_add(1, Ordering::Relaxed);
        let Some(json) = json_payload(line) else {
            self.counters.parse_error("no JSON object in line".into());
            return;
        };
        match parse_nginx_json(json) {
            Ok(record) => self.handle_record(record),
            Err(why) => self.counters.parse_error(why),
        }
    }

    /// Handle a record parsed by a receiver that doesn't deal in lines (OTLP,
    /// Kong): count it as a line, then classify it or count the error.
    pub fn handle_parsed(&self, parsed: Result<RequestRecord, String>) {
        match parsed {
            Ok(record) => {
                self.counters.lines.fetch_add(1, Ordering::Relaxed);
                self.handle_record(record);
            }
            Err(why) => self.reject_line(why),
        }
    }

    /// Count a line that was received but can't be used.
    pub fn reject_line(&self, why: String) {
        self.counters.lines.fetch_add(1, Ordering::Relaxed);
        self.counters.parse_error(why);
    }

    /// Classify one record from any source.
    pub fn handle_record(&self, record: RequestRecord) {
        let snapshot = (self.snapshots)();
        let outcome = verify(
            &core_request(&record),
            &*snapshot,
            record.timestamp_secs(),
            &self.verify,
        );
        let first = finish(&self.catalog, &snapshot, record, outcome, Rdns::NotChecked);

        let wants_rdns = first.reason == Reason::Unverifiable(Unverifiable::MissingData)
            && self.claim_uses_rdns(&first);
        let Some(rdns) = self.rdns.clone().filter(|_| wants_rdns) else {
            return self.emit(first);
        };
        let Ok(permit) = self.rdns_slots.clone().try_acquire_owned() else {
            self.counters.rdns_skipped.fetch_add(1, Ordering::Relaxed);
            return self.emit(first);
        };
        self.counters.rdns_lookups.fetch_add(1, Ordering::Relaxed);
        let (catalog, sink, counters) = (
            self.catalog.clone(),
            self.sink.clone(),
            self.counters.clone(),
        );
        tokio::spawn(async move {
            let result = rdns.check(first.record.client_ip).await;
            drop(permit);
            let outcome = outcome_of(&first);
            let second = finish(&catalog, &snapshot, first.record, outcome, result.as_rdns());
            counters.records.fetch_add(1, Ordering::Relaxed);
            sink.accept(second);
        });
    }

    fn claim_uses_rdns(&self, c: &ClassifiedRecord) -> bool {
        match (&c.agent, &c.operator) {
            (Some(id), _) => self.catalog.get(id).is_some_and(|a| a.uses_rdns()),
            (None, Some(op)) => self.catalog.by_operator(op).iter().any(|a| a.uses_rdns()),
            (None, None) => false,
        }
    }

    fn emit(&self, record: ClassifiedRecord) {
        self.counters.records.fetch_add(1, Ordering::Relaxed);
        self.sink.accept(record);
    }
}

fn core_request(r: &RequestRecord) -> Request<'_> {
    Request {
        method: &r.method,
        scheme: &r.scheme,
        authority: &r.authority,
        target: &r.target,
        signature: r.signature.as_deref(),
        signature_input: r.signature_input.as_deref(),
        signature_agent: r.signature_agent.as_deref(),
        ..Default::default()
    }
}

/// Rebuild the signature outcome from a first-pass result, so the second pass
/// after reverse DNS doesn't verify again. Only unverified requests get a
/// second pass, so this is never `Verified`.
fn outcome_of(c: &ClassifiedRecord) -> Outcome {
    match &c.signature_failure {
        Some(f) => Outcome::Failed(f.clone()),
        None => Outcome::Unsigned,
    }
}

fn finish(
    catalog: &Catalog,
    snapshot: &Snapshot,
    record: RequestRecord,
    outcome: Outcome,
    rdns: Rdns<'_>,
) -> ClassifiedRecord {
    let session = match &outcome {
        Outcome::Verified(v) => SessionKey::Signed {
            operator: v.operator.clone(),
            keyid: v.keyid.clone(),
        },
        _ => SessionKey::Heuristic {
            client_ip: record.client_ip,
            user_agent: record.user_agent.clone(),
        },
    };
    let signature_tags = record
        .signature_input
        .as_deref()
        .map(signature_tags)
        .unwrap_or_default();
    let obs = Observation {
        user_agent: &record.user_agent,
        client_ip: record.client_ip,
        signature_agent: record.signature_agent.as_deref(),
        signature: outcome,
        rdns,
    };
    let c = classify(&obs, catalog, snapshot);
    ClassifiedRecord {
        class: c.class,
        agent: c.agent.map(|a| a.id.clone()),
        operator: c.operator,
        reason: c.reason,
        claim_mismatch: c.claim_mismatch,
        signature_failure: c.signature_failure,
        signature_tags,
        session,
        record,
    }
}
