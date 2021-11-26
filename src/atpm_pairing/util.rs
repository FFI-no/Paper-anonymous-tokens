use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{G1Affine, G1Projective, Scalar};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

use alloc::{format, vec::Vec};
use core::{convert::TryInto, fmt};

use serde::de::MapAccess;
use serde::de::{self, Deserialize, Visitor};
use serde::ser::{Serialize, SerializeStruct};

use super::fill_bytes;

/// Generates a uniformly distributed random scalar, but with variable time
pub fn random_vartime<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
    // generate some random bytes
    let mut rand_bytes = [0u8; 32];
    fill_bytes(rng, &mut rand_bytes);

    // try to create a scalar
    let s = Scalar::from_bytes(&rand_bytes);

    // potentially retry with tail recursion
    if bool::from(s.is_some()) {
        s.unwrap()
    } else {
        random_vartime(rng)
    }
}

#[allow(dead_code)]
/// Generates a radnom scalar in constant time (I believe), but it is not uniform
pub fn random_biased<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
    // generate some random bytes
    let mut rand_bytes = [0u8; 64];
    fill_bytes(rng, &mut rand_bytes);

    // create a scalar, reduce by modulus
    Scalar::from_bytes_wide(&rand_bytes)
}

#[allow(dead_code)]
/// Variable time hash to get uniformity
fn h_m_uniform(md: impl AsRef<[u8]>) -> Scalar {
    let mut hasher = Sha256::new();

    // Separate the domains of the random oracles
    hasher.update(b"this is h_m_uniform");

    hasher.update(md);

    let bytes = &hasher.finalize()[..];

    let scalar = Scalar::from_bytes(bytes.try_into().unwrap());

    // If not sucessful, try again recursivly
    // This is tail recursive, so should be compiled to replace the stack frame
    if bool::from(scalar.is_some()) {
        scalar.unwrap()
    } else {
        h_m(bytes)
    }
}

#[allow(dead_code)]
/// Constant time implementation, is not uniform
fn h_m_reduce_modulus(md: impl AsRef<[u8]>) -> Scalar {
    let mut hasher = Sha512::new();

    // Separate the domains of the random oracles
    hasher.update(b"this is h_m_biased");

    hasher.update(md);

    Scalar::from_bytes_wide(&hasher.finalize()[..].try_into().unwrap())
}

/// Hash a message into a scalar
///
/// I am not sure if this scalar is uniformly distributed
pub fn h_m(md: impl AsRef<[u8]>) -> Scalar {
    #[cfg(feature = "uniform_hm")]
    {
        h_m_uniform(md)
    }

    #[cfg(not(feature = "uniform_hm"))]
    {
        h_m_reduce_modulus(md)
    }
}

/// hash some bytes to a curve point in the G1 group.
pub fn h_1<'a>(t: impl AsRef<[u8]>, md: impl AsRef<[u8]>) -> G1Affine {
    // Domain of the random oracle
    const DOMAIN: &[u8] = b"This is h_1 hash to curve thingy";

    let bytes = t
        .as_ref()
        .iter()
        .chain(md.as_ref().iter())
        .cloned()
        .collect::<Vec<u8>>();
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(bytes, DOMAIN).into()
}

// {{{ Cruve Point

#[derive(Clone, PartialEq, Debug)]
// pub(crate) struct CurvePoint {
pub struct CurvePoint {
    point: G1Affine,
}

impl From<&CurvePoint> for G1Affine {
    fn from(point: &CurvePoint) -> G1Affine {
        point.point
    }
}

impl From<G1Projective> for CurvePoint {
    fn from(point: G1Projective) -> Self {
        Self {
            point: point.into(),
        }
    }
}

impl From<G1Affine> for CurvePoint {
    fn from(point: G1Affine) -> Self {
        Self { point }
    }
}

impl From<&G1Affine> for CurvePoint {
    fn from(point: &G1Affine) -> Self {
        Self {
            point: point.clone(),
        }
    }
}

impl Serialize for CurvePoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("CurvePoint", 1)?;
        let bytes: &[u8] = &self.point.to_compressed();
        s.serialize_field("point", &bytes)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for CurvePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum CP {
            Point,
        }

        struct CurvePointVisitor;
        impl<'de> Visitor<'de> for CurvePointVisitor {
            type Value = CurvePoint;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CurvePoint")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CurvePoint, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut point = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        CP::Point => {
                            if point.is_some() {
                                return Err(de::Error::duplicate_field("point"));
                            }
                            point = Some(map.next_value()?);
                        }
                    }
                }
                let point_bytes: Vec<u8> =
                    point.ok_or_else(|| de::Error::missing_field("point"))?;

                let point_bytes: &[u8; 48] = (&point_bytes as &[u8]).try_into().map_err(|_e| {
                    de::Error::custom(
                        format!("point bytes has to be 48 bytes, not {}", point_bytes.len())
                            .as_str(),
                    )
                })?;

                let maybe_point = G1Affine::from_compressed(&point_bytes);

                let point = if bool::from(maybe_point.is_some()) {
                    Ok(maybe_point.unwrap())
                } else {
                    Err(de::Error::custom("Failed to decompress token point"))
                }?;

                Ok(CurvePoint { point })
            }
        }

        const FIELDS: &[&str] = &["point"];
        deserializer.deserialize_struct("CurvePoint", FIELDS, CurvePointVisitor)
    }
}

// }}}

#[cfg(test)]
mod tests {
    use bls12_381::{G1Affine, Scalar};

    use super::*;

    #[test]
    fn test_serialization() {
        let point = G1Affine::generator() * Scalar::from(123);

        let cp = CurvePoint::from(point);

        let serialized = serde_json::to_string(&cp).unwrap();

        let deserialized: CurvePoint = serde_json::from_str(&serialized).unwrap();

        // Assert that the serialization and deserialization works
        assert!(G1Affine::from(point) == deserialized.point);
    }
}
