//! # Keys for atpmd_nizkp
//!
//! Usage:
//! ```
//!     use atpmd::atpm_nizkp::keys::{PrivateKey, PublicKey};
//!     use k256::Secp256k1;
//!
//!     let private_key = PrivateKey::<Secp256k1>::new();
//!     let public_key = PublicKey::from(&private_key);
//! ```

use elliptic_curve::{
    group::Curve as Crv, AffineArithmetic, AffinePoint, Curve, Group, ProjectiveArithmetic,
    ProjectivePoint, Scalar, ScalarArithmetic,
};

use super::util::gen_vartime;

#[derive(Debug, Clone)]
/// The private key for the nizkp protocol
pub struct PrivateKey<C: Curve + ScalarArithmetic> {
    scalar: Scalar<C>,
}

impl<C: Curve + ScalarArithmetic> PrivateKey<C> {
    pub fn to_scalar(&self) -> Scalar<C> {
        self.scalar
    }
}

impl<C: Curve + ProjectiveArithmetic> PrivateKey<C> {
    pub fn new() -> Self {
        Self {
            scalar: gen_vartime::<C, _>(&mut rand::thread_rng()),
        }
    }
}

impl<C: Curve + ProjectiveArithmetic> Default for PrivateKey<C> {
    fn default() -> Self {
        Self::new()
    }
}

/// The public key for the nizkp protocol
pub struct PublicKey<C: Curve + AffineArithmetic> {
    point: AffinePoint<C>,
}

impl<C: Curve + AffineArithmetic> PublicKey<C> {
    pub fn to_affine(&self) -> AffinePoint<C> {
        self.point
    }
}

impl<C: Curve + AffineArithmetic + ProjectiveArithmetic> From<&PrivateKey<C>> for PublicKey<C> {
    fn from(key: &PrivateKey<C>) -> Self {
        Self {
            point: (ProjectivePoint::<C>::generator() * key.to_scalar()).to_affine(),
        }
    }
}

impl<C: Curve + ProjectiveArithmetic> From<PrivateKey<C>> for PublicKey<C> {
    fn from(key: PrivateKey<C>) -> Self {
        Self::from(&key)
    }
}
