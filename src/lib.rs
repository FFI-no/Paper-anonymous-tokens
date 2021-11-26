//! # Anonymous tokens with public metadata
//!
//! ## Public verifiability
//!
//! This protocol uses elliptic curve pairings.
//! The advantage is that it is possible to verify a token with only the public key.
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
//!
//! ## Without elliptic curve pairings
//!
//! This is without elliptic curve pairings.
//! This is quite similar to the above code, but the verifier needs the private key.
//!
//! ```
//!     // Use the trait to get access to the methods
//!     use atpmd::TokenEngine;
//!     // The actual structs
//!     use atpmd::nizkp_curve25519::{
//!         keys::{PrivateKey, PublicKey},
//!         tokens::NizkpTokenEngine,
//!     };
//!
//!     // This is public metadata, will be available to everyone
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

#![no_std]

extern crate bls12_381;
extern crate pairing;
extern crate rand;
#[macro_use]
extern crate serde;
extern crate alloc;
extern crate core;
extern crate serde_json;
extern crate sha2;
extern crate subtle;

#[cfg(feature = "nizkp")]
pub mod atpm_nizkp;

#[cfg(feature = "pairing")]
pub mod atpm_pairing;

#[cfg(feature = "curve25519")]
pub mod nizkp_curve25519;

pub(crate) mod common;

pub use common::{RandomizedUnsignedToken, SignedToken, TokenEngine, UnsignedToken};
