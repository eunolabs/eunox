//! Fetching sources on a timer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eunox_core::{IpNet, UnixSeconds};
use tokio::task::JoinSet;

use crate::parse::{parse_key_directory, parse_ranges};
use crate::snapshot::{KeyRecord, Snapshot, SourceStatus, merge_keys};
use crate::sources::Sources;

/// Largest body accepted from any source. The biggest seed file is under
/// 100 KB.
pub const MAX_BODY: usize = 4 * 1024 * 1024;

/// Tunables.
#[derive(Clone, Debug)]
pub struct Options {
    /// Time between full refreshes of every source.
    pub interval: Duration,
    /// First wait before retrying sources that failed to load. Doubles on
    /// each consecutive failure, up to `interval`. Only failing sources are
    /// retried, so an operator that's unreachable from this network isn't
    /// fetched more often than the rest.
    pub retry_interval: Duration,
    /// Per-request timeout.
    pub timeout: Duration,
    /// How long a withdrawn key keeps verifying requests logged before its
    /// withdrawal.
    pub key_retention: Duration,
    /// `User-Agent` sent to operators.
    pub user_agent: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(3600),
            retry_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(15),
            key_retention: Duration::from_secs(7 * 86_400),
            user_agent: concat!(
                "eunox-directory/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/eunolabs/eunox)"
            )
            .into(),
        }
    }
}

#[derive(Default)]
struct State {
    keys: HashMap<String, Vec<KeyRecord>>,
    ranges: HashMap<String, Vec<IpNet>>,
    status: HashMap<String, SourceStatus>,
}

/// Holds the latest [`Snapshot`] and refreshes it.
///
/// A failed fetch keeps the previous data for that source: stale ranges are
/// far better than none, since a missing set makes its agents unverifiable.
pub struct Directory {
    sources: Sources,
    options: Options,
    client: reqwest::Client,
    state: Mutex<State>,
    current: RwLock<Arc<Snapshot>>,
}

enum Body {
    Ranges(Vec<IpNet>),
    Keys(Vec<crate::parse::DirectoryKey>),
}

impl Directory {
    /// A directory with an HTTP client built from `options`. Uses the system
    /// trust store and the `HTTPS_PROXY` / `NO_PROXY` environment.
    pub fn new(sources: Sources, options: Options) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .user_agent(options.user_agent.clone())
            .timeout(options.timeout)
            .build()
            .map_err(|e| format!("can't set up the HTTP client: {}", with_causes(&e)))?;
        Ok(Self::with_client(sources, options, client))
    }

    /// A directory using the given client.
    pub fn with_client(sources: Sources, options: Options, client: reqwest::Client) -> Self {
        Self {
            sources,
            options,
            client,
            state: Mutex::new(State::default()),
            current: RwLock::new(Arc::new(Snapshot::default())),
        }
    }

    /// The latest snapshot. Cheap: clone the `Arc` once per batch of log
    /// lines, not per line.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Fetch every source once, concurrently, and publish a new snapshot.
    pub async fn refresh(&self, now: UnixSeconds) -> Arc<Snapshot> {
        self.fetch_where(now, |_| true).await
    }

    /// Fetch only the sources whose last attempt failed or that were never
    /// fetched, and publish a new snapshot.
    pub async fn refresh_failed(&self, now: UnixSeconds) -> Arc<Snapshot> {
        let ok: Vec<String> = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state
                .status
                .values()
                .filter(|s| s.last_error.is_none() && s.last_success.is_some())
                .map(|s| s.url.clone())
                .collect()
        };
        self.fetch_where(now, |url| !ok.iter().any(|u| u == url))
            .await
    }

    /// Whether any source's last attempt failed or it was never fetched.
    pub fn any_failing(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let loaded = state
            .status
            .values()
            .filter(|s| s.last_error.is_none() && s.last_success.is_some())
            .count();
        loaded < self.sources.ranges.len() + self.sources.keys.len()
    }

    async fn fetch_where(&self, now: UnixSeconds, wanted: impl Fn(&str) -> bool) -> Arc<Snapshot> {
        let mut tasks = JoinSet::new();
        for r in self.sources.ranges.iter().filter(|r| wanted(&r.url)) {
            let (client, id, url) = (self.client.clone(), r.id.clone(), r.url.clone());
            tasks.spawn(async move {
                let result = fetch(&client, &url)
                    .await
                    .and_then(|b| parse_ranges(&b).map(Body::Ranges));
                (id, url, result)
            });
        }
        for k in self.sources.keys.iter().filter(|k| wanted(&k.url)) {
            let (client, id, url) = (self.client.clone(), k.operator.clone(), k.url.clone());
            tasks.spawn(async move {
                let result = fetch(&client, &url)
                    .await
                    .and_then(|b| parse_key_directory(&b).map(Body::Keys));
                (id, url, result)
            });
        }

        let mut done = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            if let Ok(item) = joined {
                done.push(item);
            }
        }

        let retention = i64::try_from(self.options.key_retention.as_secs()).unwrap_or(i64::MAX);
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut *guard;
        for (id, url, result) in done {
            // Status and key history are per URL: one operator may publish
            // more than one directory.
            let entry = state
                .status
                .entry(url.clone())
                .or_insert_with(|| SourceStatus {
                    id: id.clone(),
                    url: url.clone(),
                    last_attempt: None,
                    last_success: None,
                    last_error: None,
                    items: 0,
                });
            entry.last_attempt = Some(now);
            let items = match result {
                Ok(Body::Ranges(nets)) => {
                    let n = nets.len();
                    state.ranges.insert(id, nets);
                    n
                }
                Ok(Body::Keys(keys)) => {
                    let previous = state.keys.get(&url).map(Vec::as_slice).unwrap_or_default();
                    let merged = merge_keys(previous, &keys, &id, now, retention);
                    let n = merged.len();
                    state.keys.insert(url, merged);
                    n
                }
                Err(e) => {
                    entry.last_error = Some(e);
                    continue;
                }
            };
            entry.last_success = Some(now);
            entry.last_error = None;
            entry.items = items;
        }

        let mut status: Vec<SourceStatus> = state.status.values().cloned().collect();
        status.sort_by(|a, b| a.id.cmp(&b.id).then(a.url.cmp(&b.url)));
        let snapshot = Arc::new(Snapshot::new(
            state.keys.values().flatten().cloned(),
            state.ranges.clone(),
            status,
        ));
        drop(guard);
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = snapshot.clone();
        snapshot
    }

    /// Refresh every source now and then every `interval`, forever, and in
    /// between retry failing sources with backoff (see
    /// [`Options::retry_interval`]). Spawn this on the runtime; it never
    /// blocks the caller's threads.
    pub async fn run(self: Arc<Self>) {
        let (interval, retry) = (self.options.interval, self.options.retry_interval);
        let mut next_full = tokio::time::Instant::now();
        let mut backoff = retry;
        loop {
            let now = tokio::time::Instant::now();
            if now >= next_full {
                self.refresh(unix_now()).await;
                next_full = now + interval;
            } else {
                self.refresh_failed(unix_now()).await;
            }
            let until_full = next_full.saturating_duration_since(tokio::time::Instant::now());
            let wait = if self.any_failing() {
                let (wait, next) = next_retry(backoff, interval);
                backoff = next;
                wait.min(until_full)
            } else {
                backoff = retry;
                until_full
            };
            tokio::time::sleep(wait).await;
        }
    }
}

/// The wait before the next retry, and the backoff after it: the current
/// backoff now, doubled next time, never longer than a full refresh interval.
pub fn next_retry(backoff: Duration, interval: Duration) -> (Duration, Duration) {
    let wait = backoff.min(interval);
    (wait, wait.saturating_mul(2).min(interval))
}

/// An error and its chain of causes, `outer: inner: innermost`. reqwest's
/// own messages ("builder error") don't say what went wrong.
fn with_causes(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        source = s.source();
    }
    msg
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> UnixSeconds {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let mut response = client.get(url).send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_BODY as u64)
    {
        return Err(format!("body larger than {MAX_BODY} bytes"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(format!("body larger than {MAX_BODY} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
