//! # Tokens using pairing
//!
//! These tokens use elliptic curve pairings.
//! An advantage is that it is possible to verify tokens using the public key.
//!
//! ## Usage
//!
//! ```
//!     // Use the trait to get access to the methods
//!     use atpmd::TokenEngine;
//!     // The actual structs
//!     use atpmd::atpm_pairing::{
//!         keys::{PrivateKey, PublicKey},
//!         tokens::PairingTokenEngine,
//!     };
//!
//!     // This is public metadata, will be available to everyone
//!     let metadata = b"This is metadata that both the signer and verifier may see";
//!     // This is hidden public metadata, will only be available to user and verifier, not signer
//!     let hidden_metadata = b"This is metadata that only verifier may see";
//!
//!     // Secret key, only for signer
//!     let secret_key = PrivateKey::new();
//!     // Public key, for user and verifier
//!     let public_key = PublicKey::from(&secret_key);
//!
//!     // User creates an unsiged token
//!     let unsigned_token = PairingTokenEngine::generate_with_hidden(&metadata[..], hidden_metadata);
//!
//!     // Sign the unsigned token
//!     let signed = PairingTokenEngine::sign(
//!         unsigned_token,
//!         &public_key,
//!         |randomized_unsigned| PairingTokenEngine::sign_randomized(randomized_unsigned, &secret_key)
//!     ).unwrap();
//!
//!     // The verifier may verify that the token is signed
//!     let is_properly_signed = PairingTokenEngine::verify(&signed, &public_key);
//!     assert!(is_properly_signed);
//! ```

pub(crate) use super::common::*;

mod util;
pub mod keys;
pub mod tokens;
pub mod tokens_batched; 
