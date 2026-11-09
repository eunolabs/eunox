//! The running pieces, wired together.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eunox_core::Catalog;
use eunox_directory::{Directory, FcrDns, Options};
use eunox_ingest::{ClassifiedRecord, Pipeline};
use eunox_stats::Stats;
use hickory_resolver::TokioResolver;

use crate::config::Config;
use crate::render::{IngestTotals, ReportData};

/// Paths and networks shown per row.
pub const TOP_PER_ROW: usize = 5;

/// Catalog, directory, pipeline and counters.
pub struct App {
    /// Known agents.
    pub catalog: Arc<Catalog>,
    /// Keys and IP ranges, refreshed in the background.
    pub directory: Arc<Directory>,
    /// Log lines in, classified records out to `stats`.
    pub pipeline: Arc<Pipeline<TokioResolver>>,
    /// Counters.
    pub stats: Arc<Mutex<Stats>>,
}

impl App {
    /// Build everything; nothing is fetched or bound yet.
    pub fn new(config: &Config) -> Result<Self, String> {
        let catalog = Arc::new(Catalog::seed());
        let directory = Arc::new(Directory::new(
            config.sources(),
            Options {
                interval: config.refresh,
                ..Options::default()
            },
        )?);
        let rdns = if config.rdns {
            match FcrDns::system() {
                Ok(r) => Some(Arc::new(r)),
                Err(e) => {
                    eprintln!("eunox: reverse DNS disabled: {e}");
                    None
                }
            }
        } else {
            None
        };
        let stats = Arc::new(Mutex::new(Stats::new()));
        let sink = stats.clone();
        let dir = directory.clone();
        let pipeline = Arc::new(Pipeline::new(
            catalog.clone(),
            Arc::new(move || dir.snapshot()),
            rdns,
            Arc::new(move |r: ClassifiedRecord| lock(&sink).record(&r, now_ms())),
        ));
        Ok(Self {
            catalog,
            directory,
            pipeline,
            stats,
        })
    }

    /// Render a report from the current counters.
    pub fn render<T>(&self, f: impl FnOnce(&ReportData<'_>) -> T) -> T {
        let (summary, lifetime) = {
            let stats = lock(&self.stats);
            let lifetime: Vec<_> = stats.lifetime().map(|(k, n)| (k.clone(), n)).collect();
            (stats.summary(TOP_PER_ROW), lifetime)
        };
        let snapshot = self.directory.snapshot();
        let c = self.pipeline.counters();
        let ingest = IngestTotals {
            lines: c.lines.load(Ordering::Relaxed),
            records: c.records.load(Ordering::Relaxed),
            parse_errors: c.parse_errors.load(Ordering::Relaxed),
            udp_datagrams: c.udp_datagrams.load(Ordering::Relaxed),
            last_parse_error: c
                .last_parse_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            rdns_lookups: c.rdns_lookups.load(Ordering::Relaxed),
            rdns_skipped: c.rdns_skipped.load(Ordering::Relaxed),
        };
        f(&ReportData {
            summary: &summary,
            lifetime: &lifetime,
            sources: snapshot.status(),
            ingest: &ingest,
            catalog: &self.catalog,
        })
    }

    /// Wait until every received line is classified or rejected, for up to
    /// `max`. Reverse-DNS lookups finish in the background.
    pub async fn settle(&self, max: Duration) {
        let c = self.pipeline.counters();
        let deadline = tokio::time::Instant::now() + max;
        while tokio::time::Instant::now() < deadline {
            let done = c.records.load(Ordering::Relaxed) + c.parse_errors.load(Ordering::Relaxed);
            if done >= c.lines.load(Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Wall clock in Unix milliseconds.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
