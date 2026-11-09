//! An immutable view of everything fetched, which `core` reads through its
//! `KeyStore` and `IpRanges` traits.
//!
//! Keys keep history. Verification runs against the log timestamp, which can
//! be minutes behind, so a key an operator has just rotated out must still
//! verify requests logged while it was published. A key that disappears from
//! its directory is marked withdrawn at the time we noticed, stays valid for
//! requests logged up to then, and is forgotten after a retention period.

use std::collections::HashMap;
use std::net::IpAddr;

use eunox_core::{IpNet, IpRanges, Key, KeyStore, UnixSeconds};

use crate::parse::DirectoryKey;

/// A key and the window it was valid in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    /// The key and its operator.
    pub key: Key,
    /// Thumbprint, the primary id.
    pub thumbprint: String,
    /// Directory `kid`, if it differs from the thumbprint.
    pub kid: Option<String>,
    /// `nbf` from the directory.
    pub not_before: Option<UnixSeconds>,
    /// `exp` from the directory.
    pub expires: Option<UnixSeconds>,
    /// When we first saw it.
    pub first_seen: UnixSeconds,
    /// When we noticed it gone from the directory, if it has gone.
    pub withdrawn_at: Option<UnixSeconds>,
}

impl KeyRecord {
    /// Whether the key was usable at `at`.
    pub fn valid_at(&self, at: UnixSeconds) -> bool {
        self.not_before.is_none_or(|nbf| at >= nbf)
            && self.expires.is_none_or(|exp| at < exp)
            && self.withdrawn_at.is_none_or(|w| at <= w)
    }
}

/// Merge a fresh fetch of one directory into its previous records.
///
/// Keys still listed are refreshed (and un-withdrawn if they came back), new
/// keys are added, missing keys are marked withdrawn at `now`, and keys
/// withdrawn more than `retention` seconds ago are dropped.
pub fn merge_keys(
    previous: &[KeyRecord],
    fetched: &[DirectoryKey],
    operator: &str,
    now: UnixSeconds,
    retention: i64,
) -> Vec<KeyRecord> {
    let mut out: Vec<KeyRecord> = fetched
        .iter()
        .map(|k| {
            let first_seen = previous
                .iter()
                .find(|p| p.thumbprint == k.thumbprint)
                .map_or(now, |p| p.first_seen);
            KeyRecord {
                key: Key {
                    operator: operator.to_owned(),
                    public_key: k.public_key,
                },
                thumbprint: k.thumbprint.clone(),
                kid: k.kid.clone(),
                not_before: k.not_before,
                expires: k.expires,
                first_seen,
                withdrawn_at: None,
            }
        })
        .collect();
    for p in previous {
        if out.iter().any(|k| k.thumbprint == p.thumbprint) {
            continue;
        }
        let withdrawn_at = p.withdrawn_at.unwrap_or(now);
        if now - withdrawn_at <= retention {
            out.push(KeyRecord {
                withdrawn_at: Some(withdrawn_at),
                ..p.clone()
            });
        }
    }
    out
}

/// Freshness of one source, for the report page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceStatus {
    /// Range set id or key operator.
    pub id: String,
    /// The URL fetched.
    pub url: String,
    /// When the last attempt finished.
    pub last_attempt: Option<UnixSeconds>,
    /// When the last successful fetch finished.
    pub last_success: Option<UnixSeconds>,
    /// The last error, cleared on success.
    pub last_error: Option<String>,
    /// Prefixes or keys currently held from this source.
    pub items: usize,
}

/// Everything fetched so far.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    keys: HashMap<String, Vec<KeyRecord>>,
    ranges: HashMap<String, Vec<IpNet>>,
    status: Vec<SourceStatus>,
}

impl Snapshot {
    /// Build from per-source state. Each key is indexed by thumbprint and by
    /// `kid`.
    pub fn new(
        keys: impl IntoIterator<Item = KeyRecord>,
        ranges: HashMap<String, Vec<IpNet>>,
        status: Vec<SourceStatus>,
    ) -> Self {
        let mut index: HashMap<String, Vec<KeyRecord>> = HashMap::new();
        for record in keys {
            if let Some(kid) = &record.kid {
                index.entry(kid.clone()).or_default().push(record.clone());
            }
            index
                .entry(record.thumbprint.clone())
                .or_default()
                .push(record);
        }
        Self {
            keys: index,
            ranges,
            status,
        }
    }

    /// Per-source freshness.
    pub fn status(&self) -> &[SourceStatus] {
        &self.status
    }

    /// Range sets loaded.
    pub fn range_sets(&self) -> impl Iterator<Item = (&str, usize)> {
        self.ranges
            .iter()
            .map(|(id, nets)| (id.as_str(), nets.len()))
    }

    /// All key records, once each.
    pub fn key_records(&self) -> impl Iterator<Item = &KeyRecord> {
        self.keys
            .iter()
            .flat_map(|(id, records)| records.iter().filter(move |r| r.thumbprint == *id))
    }
}

impl KeyStore for Snapshot {
    fn lookup(&self, keyid: &str, at: UnixSeconds) -> Option<&Key> {
        self.keys
            .get(keyid)?
            .iter()
            .find(|r| r.valid_at(at))
            .map(|r| &r.key)
    }
}

impl IpRanges for Snapshot {
    fn contains(&self, set: &str, ip: IpAddr) -> Option<bool> {
        self.ranges.contains(set, ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dk(thumb: &str, byte: u8) -> DirectoryKey {
        DirectoryKey {
            thumbprint: thumb.into(),
            kid: None,
            public_key: [byte; 32],
            not_before: None,
            expires: None,
        }
    }

    const DAY: i64 = 86_400;

    #[test]
    fn rotated_key_still_verifies_requests_logged_before_rotation() {
        let v1 = merge_keys(&[], &[dk("old", 1)], "op", 1_000, DAY);
        // Rotation noticed at t=2000.
        let v2 = merge_keys(&v1, &[dk("new", 2)], "op", 2_000, DAY);
        let snap = Snapshot::new(v2.clone(), HashMap::new(), vec![]);

        assert!(
            snap.lookup("old", 1_500).is_some(),
            "logged before rotation"
        );
        assert!(
            snap.lookup("old", 2_000).is_some(),
            "logged at the boundary"
        );
        assert!(snap.lookup("old", 2_001).is_none(), "logged after rotation");
        assert!(snap.lookup("new", 2_500).is_some());

        // Forgotten after the retention period.
        let v3 = merge_keys(&v2, &[dk("new", 2)], "op", 2_000 + DAY + 1, DAY);
        assert!(v3.iter().all(|r| r.thumbprint != "old"));
        // The withdrawal time doesn't move on later refreshes.
        let v2b = merge_keys(&v2, &[dk("new", 2)], "op", 3_000, DAY);
        let old = v2b.iter().find(|r| r.thumbprint == "old").unwrap();
        assert_eq!(old.withdrawn_at, Some(2_000));
    }

    #[test]
    fn returning_key_is_reinstated() {
        let v1 = merge_keys(&[], &[dk("k", 1)], "op", 1_000, DAY);
        let v2 = merge_keys(&v1, &[], "op", 2_000, DAY);
        let v3 = merge_keys(&v2, &[dk("k", 1)], "op", 3_000, DAY);
        assert_eq!(v3.len(), 1);
        assert_eq!(v3[0].withdrawn_at, None);
        assert_eq!(v3[0].first_seen, 1_000);
    }

    #[test]
    fn nbf_and_exp_are_honoured() {
        let mut k = dk("k", 1);
        k.not_before = Some(100);
        k.expires = Some(200);
        let snap = Snapshot::new(merge_keys(&[], &[k], "op", 0, DAY), HashMap::new(), vec![]);
        assert!(snap.lookup("k", 99).is_none());
        assert!(snap.lookup("k", 100).is_some());
        assert!(snap.lookup("k", 199).is_some());
        assert!(snap.lookup("k", 200).is_none());
    }

    #[test]
    fn lookup_by_kid_or_thumbprint() {
        let mut k = dk("thumb", 1);
        k.kid = Some("short".into());
        let snap = Snapshot::new(
            merge_keys(&[], &[k], "google", 0, DAY),
            HashMap::new(),
            vec![],
        );
        assert_eq!(snap.lookup("thumb", 5).unwrap().operator, "google");
        assert_eq!(snap.lookup("short", 5).unwrap().operator, "google");
        assert_eq!(snap.key_records().count(), 1);
    }
}
