//! eunox core: pure, I/O-free logic for classifying inbound agent traffic and
//! for signing an operator's own requests and key directory.
//!
//! This crate must stay free of network, file and clock access. It will later
//! back an ext_authz server, an Envoy dynamic module and LuaJIT FFI for Kong,
//! where blocking on a gateway worker thread is not acceptable. Everything
//! time-dependent takes the time as an argument, and everything fetched
//! (keys, IP ranges, reverse DNS) is passed in by the caller.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod catalog;
pub mod classify;
pub mod ip;
pub mod sign;
pub mod signature;

pub use catalog::{Agent, Catalog, CatalogError};
pub use classify::{Class, Classification, Observation, Rdns, Reason, Unverifiable, classify};
pub use ip::{IpNet, IpRanges};
pub use sign::{
    DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, DIRECTORY_TAG, OperatorKey, RequestToSign, SignError,
    SignedDirectory, SignedHeaders, content_digest, directory_jwks, jwk_thumbprint, sign_directory,
    sign_request,
};
pub use signature::{
    Failure, Key, KeyStore, Outcome, Request, UnixSeconds, Verified, VerifyOptions,
    WEB_BOT_AUTH_TAG, signature_tags, verify,
};
