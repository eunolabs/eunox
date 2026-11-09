//! eunox directory: the I/O that `eunox-core` deliberately doesn't do.
//!
//! - Fetches operators' published IP range files and Web Bot Auth key
//!   directories on a timer, from a fixed list of sources.
//! - Keeps key history so out-of-band verification survives key rotation.
//! - Does forward-confirmed reverse DNS, cached.
//!
//! Everything runs on the async runtime in the background; readers take an
//! immutable [`Snapshot`] and never wait on the network.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod fetch;
pub mod parse;
pub mod rdns;
pub mod snapshot;
pub mod sources;

pub use fetch::{Directory, Options, unix_now};
pub use rdns::{DnsLookup, FcrDns, RdnsResult};
pub use snapshot::{KeyRecord, Snapshot, SourceStatus};
pub use sources::{KeySource, RangeSource, Sources};
