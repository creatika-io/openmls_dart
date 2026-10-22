//! openmls_frb - Rust bridge layer for openmls.
//!
//! Dart wrapper for OpenMLS — a Rust implementation of the Messaging Layer Security (MLS) protocol (RFC 9420)

#![allow(dead_code)]

mod encrypted_db;
#[cfg(feature = "all-ciphersuites")]
mod hybrid_crypto;
#[cfg(not(feature = "all-ciphersuites"))]
mod mandatory_ciphersuite_crypto;
mod snapshot_storage;

#[cfg(feature = "all-ciphersuites")]
pub(crate) use hybrid_crypto::HybridCrypto as CryptoBackend;
#[cfg(not(feature = "all-ciphersuites"))]
pub(crate) use mandatory_ciphersuite_crypto::MandatoryCiphersuiteCrypto as CryptoBackend;
// The FRB-generated bridge and encrypted_db's WASM `unsafe impl Send/Sync` are
// the only two places that legitimately need unsafe, and each opts out with an
// item-level `#[allow(unsafe_code)]` — here on the module, there on the two
// impls. Neither opt-out is module-wide, so no file gets a blanket exemption.
// Everything else is covered by `unsafe_code = "deny"` in Cargo.toml.
#[allow(unsafe_code)]
mod frb_generated;
#[cfg(test)]
mod test_support;
mod utils;
// Cross-tab single-writer lock. Web-only: the native build takes a sidecar
// lock file instead (`encrypted_db::acquire_single_writer_lock`).
#[cfg(target_arch = "wasm32")]
mod web_lock;
mod wire_decode;

pub mod api;

pub use utils::current_time;
// Exposed so `rust/fuzz` can fuzz the decoders through this crate's openmls.
pub use wire_decode::fuzz_decode_wire_types;
