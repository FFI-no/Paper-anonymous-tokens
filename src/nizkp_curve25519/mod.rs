//! # Anonymous tokens
//!
//! These are nonymous tokens, where the tokens are on the elliptic curve [K256](https://docs.rs/k256)
//!
//! ## Usage
//!
//! ```
//!     // Use the trait to get access to the methods
//!     use atpmd::TokenEngine;
//!     // The actual structs
//!     use atpmd::nizkp_curve25519::{
//!         keys::{PrivateKey, PublicKey},
//!         tokens::NizkpTokenEngine,
//!     };
//!  // This is public metadata, will be available to everyone
//!     let metadata = b"This is metadata that both the signer and verifier may see";
//!     // This is hidden public metadata, will only be available to user and verifier, not signer
//!     let hidden_metadata = b"This is metadata that only verifier may see";
//!
//!     // Secret key, for signer and verifier
//!     let secret_key = PrivateKey::new();
//!     // Public key, only for user
//!     let public_key = PublicKey::from(&secret_key);
//!
//!     // User creates an unsiged token
//!     let unsigned_token = NizkpTokenEngine::generate_with_hidden(&metadata[..], hidden_metadata);
//!
//!     // Sign the unsigned token
//!     let signed = NizkpTokenEngine::sign(
//!         unsigned_token,
//!         &public_key,
//!         |randomized_unsigned| NizkpTokenEngine::sign_randomized(randomized_unsigned, &secret_key)
//!     ).unwrap();
//!
//!     // The verifier may verify that the token is signed
//!     let is_properly_signed = NizkpTokenEngine::verify(&signed, &secret_key);
//!     assert!(is_properly_signed);
//! ```

pub (crate) use super::common::*;

mod util;
pub mod tokens;
pub mod keys;
pub mod tokens_batched;
