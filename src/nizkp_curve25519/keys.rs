//! # Keys for atpmd_nizkp
//!
//! Usage:
//! ```
//!     use atpmd::nizkp_curve25519::keys::{PrivateKey, PublicKey};
//!
//!     let private_key = PrivateKey::new();
//!     let public_key = PublicKey::from(&private_key);
//! ```

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

#[derive(Debug, Clone)]
/// The private key for the nizkp protocol
pub struct PrivateKey {
    scalar: Scalar,
}

impl PrivateKey {
    pub fn to_scalar(&self) -> Scalar {
        self.scalar
    }
}

impl PrivateKey {
    pub fn new() -> Self {
        Self {
            scalar: Scalar::random(&mut rand::thread_rng()),
        }
    }
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

/// The public key for the nizkp protocol
pub struct PublicKey {
    point: RistrettoPoint,
}

impl PublicKey {
    pub fn to_affine(&self) -> RistrettoPoint {
        self.point
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(key: &PrivateKey) -> Self {
        Self {
            point: &key.to_scalar() * &RISTRETTO_BASEPOINT_TABLE,
        }
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(key: PrivateKey) -> Self {
        Self::from(&key)
    }
}
