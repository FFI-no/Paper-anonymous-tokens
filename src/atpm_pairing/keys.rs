use core::convert::TryInto;
use core::fmt;

use alloc::{format, vec::Vec};

use super::util::random_vartime;
use bls12_381::{G2Affine, Scalar};

use serde::de::MapAccess;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};

#[derive(Debug, Clone)]
/// The pivate key for the pairing protocol
pub struct PrivateKey {
    key: Scalar,
}

impl PrivateKey {
    /// Generate a new random private key
    pub fn new() -> Self {
        PrivateKey {
            key: random_vartime(&mut rand::thread_rng()),
        }
    }
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&PrivateKey> for Scalar {
    /// get the scalar from the private key
    fn from(sk: &PrivateKey) -> Self {
        sk.key
    }
}

#[derive(Debug)]
/// The public key for the pairing protocol
pub struct PublicKey {
    key: G2Affine,
}

impl From<&PrivateKey> for PublicKey {
    fn from(sk: &PrivateKey) -> Self {
        PublicKey {
            key: (G2Affine::generator() * sk.key).into(),
        }
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(key: PrivateKey) -> Self {
        Self::from(&key)
    }
}

impl From<&PublicKey> for G2Affine {
    fn from(pk: &PublicKey) -> Self {
        pk.key
    }
}

impl From<G2Affine> for PublicKey {
    fn from(key: G2Affine) -> Self {
        PublicKey { key }
    }
}

// {{{ serialization

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("PublicKey", 1)?;
        let bytes: &[u8] = &self.key.to_compressed();
        s.serialize_field("key", &bytes)?;
        s.end()
        // serializer.serialize_bytes()
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum PK {
            Key,
        }

        struct PublicKeyVisitor;
        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct PublicKey")
            }

            fn visit_map<V>(self, mut map: V) -> Result<PublicKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_field = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        PK::Key => {
                            if key_field.is_some() {
                                return Err(de::Error::duplicate_field("key"));
                            }
                            key_field = Some(map.next_value()?);
                        }
                    }
                }
                let key_bytes: Vec<u8> =
                    key_field.ok_or_else(|| de::Error::missing_field("key"))?;

                let key_bytes: &[u8; 96] = (&key_bytes as &[u8]).try_into().map_err(|_e| {
                    de::Error::custom(
                        format!("key bytes has to be 96 bytes, not {}", key_bytes.len()).as_str(),
                    )
                })?;

                let maybe_point = G2Affine::from_compressed(&key_bytes);

                let key_point = if bool::from(maybe_point.is_some()) {
                    Ok(maybe_point.unwrap())
                } else {
                    Err(de::Error::custom("Failed to decompress key"))
                }?;

                Ok(PublicKey::from(key_point))
            }
        }

        const FIELDS: &[&str] = &["key"];
        deserializer.deserialize_struct("PublicKey", FIELDS, PublicKeyVisitor)
    }
}

// }}}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_public_relation() {
        let sk = PrivateKey::default();
        let pk = PublicKey::from(&sk);

        let sec: Scalar = (&sk).into();

        let pb: G2Affine = (&pk).into();

        assert!(pb == (G2Affine::generator() * sec).into());
    }

    #[test]
    fn test_serde() {
        let sk = PrivateKey::default();
        let pk = PublicKey::from(&sk);

        let serialized = serde_json::to_string(&pk).unwrap();

        let deserialized: PublicKey = serde_json::from_str(&serialized).unwrap();

        assert!(deserialized.key == pk.key);
    }

    #[test]
    fn test_serde_fail() {
        let deserialized: Result<PublicKey, serde_json::Error> = serde_json::from_str(
            r#"{"keys": [123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123,123]}"#,
        );

        assert!(deserialized.is_err());
    }
}
