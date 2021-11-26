use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use sha2::{Digest, Sha512};

/// hash the input bytes uniformly to a scalar
///
/// This is a variable time implementation, to get uniform randomness by rejection sampling
pub fn hash_to_scalar(data: impl AsRef<[u8]>) -> Scalar {
    let mut hasher = Sha512::new();
    // domain of the oracle, to have separate oracles
    hasher.update(b"This is hash_to_scalar hash");

    // input data
    hasher.update(data);

    Scalar::from_hash(hasher)
}

/// hash to the curve
///
/// This uses a variable time hash to scalar, and multiplies the generator by this scalar to get a
/// curve point
pub fn h_t(t: impl AsRef<[u8]>, m: impl AsRef<[u8]>) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    // domain of the oracle, to have separate oracles
    hasher.update(b"This is h_t hash");

    // Input the data to the oracle
    hasher.update(t);
    hasher.update(m);

    RistrettoPoint::from_hash(hasher)
}
