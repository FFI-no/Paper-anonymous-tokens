use core::convert::TryFrom;

use elliptic_curve::{
    AffineArithmetic, AffinePoint, Curve, FieldBytes, ProjectiveArithmetic,
    Scalar, ScalarBytes,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// hash the input bytes uniformly to a scalar
///
/// This is a variable time implementation, to get uniform randomness by rejection sampling
pub fn hash_to_scalar<C: Curve + ProjectiveArithmetic, D: AsRef<[u8]>>(data: D) -> Scalar<C> {
    let mut hasher = Sha256::new();
    // domain of the oracle, to have separate oracles
    hasher.update(b"This is hash_to_scalar hash");

    // input data
    hasher.update(data);

    // extract bytes
    let b = hasher.finalize();

    let bytes: &'_ [u8] = b.as_ref();

    // Try to get a scalar
    // This is tail recursive, so should be compiled to replace the stack frame
    let scalar_bytes = ScalarBytes::<C>::try_from(bytes);
    if scalar_bytes.is_ok() {
        scalar_bytes.unwrap().into_scalar()
    } else {
        // If there was not a scalar, try again recursivly
        hash_to_scalar::<C, _>(b)
    }
}

/// hash to the curve
///
/// This uses a variable time hash to scalar, and multiplies the generator by this scalar to get a
/// curve point
pub fn h_t<C: Curve + AffineArithmetic, T: AsRef<[u8]>, M: AsRef<[u8]>>(
    t: T,
    m: M,
) -> AffinePoint<C> {
    let mut hasher = Sha256::new();
    // domain of the oracle, to have separate oracles
    hasher.update(b"This is h_t hash");

    // Input the data to the oracle
    hasher.update(t);
    hasher.update(m);

    let bytes = hasher.finalize();

    if let Some(point) = bytes_to_curve::<C, _>(&bytes) {
        point
    } else {
        hash_to_curve::<C, _>(bytes)
    }
}

fn hash_to_curve<C: Curve + AffineArithmetic, T: AsRef<[u8]>>(t: T) -> AffinePoint<C> {
    let mut hasher = Sha256::new();
    // domain of the oracle, to have separate oracles
    hasher.update(b"This is hash to curve");

    // Input the data to the oracle
    hasher.update(t);

    let bytes = hasher.finalize();

    if let Some(point) = bytes_to_curve::<C, _>(&bytes) {
        point
    } else {
        hash_to_curve::<C, _>(bytes)
    }
}

fn bytes_to_curve<C: Curve + AffineArithmetic, T: AsRef<[u8]>>(_t: T) -> Option<AffinePoint<C>> {
    unimplemented!()
}
//     let x = FieldBytes::<C>::from_slice(t.as_ref());

//     let point = DecompactPoint::decompact(x);
//     if bool::from(point.is_some()) {
//         Some(point.unwrap())
//     } else {
//         None
//     }
// }

pub fn gen_vartime<C: Curve + ProjectiveArithmetic, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Scalar<C> {
    let mut bytes = FieldBytes::<C>::default();

    rng.fill_bytes(&mut bytes);

    let scalar_bytes = ScalarBytes::<C>::new(bytes);

    if bool::from(scalar_bytes.is_some()) {
        scalar_bytes.unwrap().into_scalar()
    } else {
        gen_vartime::<C, _>(rng)
    }
}
