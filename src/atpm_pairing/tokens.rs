use bls12_381::{Bls12, G1Affine, G2Affine, G2Projective, Scalar};
use pairing::Engine;
use serde::{Deserialize, Serialize};
use subtle::CtOption;

use alloc::boxed::Box;
use core::marker::PhantomData;

use super::keys::{PrivateKey, PublicKey};
use super::util::{h_1, h_m, random_vartime, CurvePoint};
use super::{SignedToken, TokenEngine, TokenIdentifier, UnsignedToken};

// {{{ Signed Token

#[derive(Serialize, Deserialize, Debug)]
pub struct PairingSignedToken<M: AsRef<[u8]>> {
    id: TokenIdentifier<M>,
    metadata: M,
    signature: CurvePoint,
}

impl<M: AsRef<[u8]>> PartialEq for PairingSignedToken<M> {
    fn eq(&self, other: &Self) -> bool {
        // has to have the same id
        let same_id = self.id == other.id;

        // has to have the same signature
        let same_signature = self.signature == other.signature;

        // Has to have the same metadata.
        // will compare all bytes, and not exit early (i think).
        let same_metadata = self
            .metadata
            .as_ref()
            .iter()
            .zip(other.metadata.as_ref().iter())
            .fold(true, |s, (l, r)| l == r && s);

        // all conditions has to be true
        same_signature && same_id && same_metadata
    }
}

impl<M: AsRef<[u8]>> SignedToken for PairingSignedToken<M> {
    type VerificationKey = PublicKey;

    fn verify(&self, verification_key: &Self::VerificationKey) -> bool {
        // Get out the id
        let t: [u8; 16] = (&self.id).into();

        // create the point on the cuve
        let t_point = h_1(&t, &self.metadata);

        // get the public key and other useful points on the curve
        let pk: G2Affine = <&PublicKey>::into(verification_key);
        let u: G2Projective = G2Affine::generator() * h_m(&self.metadata) + pk;

        // Verify that the signature is from the provided public key
        Bls12::pairing(&G1Affine::from(&self.signature), &u.into())
            == Bls12::pairing(&t_point, &G2Affine::generator())
    }
}

impl<M: AsRef<[u8]>> PairingSignedToken<M> {
    pub(crate) fn create(id: TokenIdentifier<M>, signature: CurvePoint, metadata: M) -> Self {
        Self {
            id,
            signature,
            metadata,
        }
    }

    pub(crate) fn unpack(self) -> (TokenIdentifier<M>, CurvePoint, M) {
        let PairingSignedToken {
            id,
            metadata,
            signature,
        } = self;

        (id, signature, metadata)
    }
}

// }}}

// {{{ UnsignedToken

#[derive(Serialize, Deserialize)]
pub struct PairingUnsignedToken<M: AsRef<[u8]>> {
    id: TokenIdentifier<M>,
    metadata: M,
}

impl<M: AsRef<[u8]>> UnsignedToken for PairingUnsignedToken<M> {
    type HiddenMetadata = M;
    type Metadata = M;

    fn new(metadata: Self::Metadata) -> Self {
        Self {
            id: TokenIdentifier::new(),
            metadata,
        }
    }

    fn with_hidden(metadata: Self::Metadata, hidden: Self::HiddenMetadata) -> Self {
        Self {
            id: TokenIdentifier::with_hidden(hidden),
            metadata,
        }
    }
}

impl<M: AsRef<[u8]> + Clone> From<&PairingUnsignedToken<M>> for TokenIdentifier<M> {
    fn from(token: &PairingUnsignedToken<M>) -> Self {
        token.id.clone()
    }
}

impl<M: AsRef<[u8]>> From<&PairingUnsignedToken<M>> for G1Affine {
    fn from(token: &PairingUnsignedToken<M>) -> Self {
        let t: [u8; 16] = (&token.id).into();
        h_1(t, &token.metadata)
    }
}

impl<M: AsRef<[u8]>> PairingUnsignedToken<M> {
    pub fn get_signed(self, signature: CurvePoint) -> PairingSignedToken<M> {
        PairingSignedToken {
            id: self.id,
            signature,
            metadata: self.metadata,
        }
    }
}

// }}}

// {{{ RandomizedUnsignedToken

#[derive(Serialize, Deserialize, Clone)]
pub struct RandomizedUnsignedToken<M> {
    point: CurvePoint,
    metadata: Box<[u8]>,
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>> crate::common::RandomizedUnsignedToken for RandomizedUnsignedToken<M> {
    fn metadata(&self) -> Box<[u8]> {
        self.metadata.clone()
    }
}

impl<M: AsRef<[u8]>> RandomizedUnsignedToken<M> {
    pub fn new(point: G1Affine, metadata: M) -> Self {
        Self {
            point: CurvePoint::from(point),
            metadata: Box::from(metadata.as_ref()),
            _m: PhantomData {},
        }
    }
}

// }}}

// {{{ RandomizedSignedToken

#[derive(Serialize, Deserialize)]
pub struct RandomizedSignedToken<M> {
    point: CurvePoint,
    metadata: Box<[u8]>,
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>> Default for RandomizedSignedToken<M> {
    fn default() -> Self {
        Self {
            point: CurvePoint::from(G1Affine::identity()),
            metadata: Box::from([]),
            _m: PhantomData {},
        }
    }
}

impl<M: AsRef<[u8]>> From<&RandomizedSignedToken<M>> for G1Affine {
    fn from(tok: &RandomizedSignedToken<M>) -> Self {
        G1Affine::from(&tok.point)
    }
}

// }}}

// {{{ Token Engine

pub struct PairingTokenEngine<M: AsRef<[u8]>> {
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>> TokenEngine for PairingTokenEngine<M> {
    type UnsignedToken = PairingUnsignedToken<M>;
    type RandomizedUnsignedToken = RandomizedUnsignedToken<M>;
    type RandomizedSignedToken = RandomizedSignedToken<M>;
    type SignedToken = PairingSignedToken<M>;
    type Randomization = Scalar;
    type UserVerification = PublicKey;
    type SignKey = PrivateKey;

    fn randomize(
        unsigned_token: &Self::UnsignedToken,
    ) -> (Self::Randomization, Self::RandomizedUnsignedToken) {
        let t: [u8; 16] = (&unsigned_token.id).into();
        let t = h_1(&t, &unsigned_token.metadata);

        loop {
            // Pick random stuff until it is invertible (should be the first)
            let r = random_vartime(&mut rand::thread_rng());
            let result = r.invert();

            if bool::from(result.is_some()) {
                let rinv = result.unwrap();
                let rut = RandomizedUnsignedToken {
                    metadata: Box::from(unsigned_token.metadata.as_ref()),
                    point: CurvePoint::from(t * rinv),
                    _m: PhantomData {},
                };
                return (r, rut);
            }
        }
    }

    fn sign_randomized(
        t_prime: &Self::RandomizedUnsignedToken,
        sign_key: &Self::SignKey,
    ) -> CtOption<Self::RandomizedSignedToken> {
        // This should be a constant time implementation
        let d = h_m(&t_prime.metadata);
        let k: Scalar = <&PrivateKey>::into(sign_key);
        (d + k)
            .invert()
            .map(|inverse| (G1Affine::from(&t_prime.point) * inverse))
            .map(|point| RandomizedSignedToken {
                metadata: t_prime.metadata.clone(),
                point: CurvePoint::from(point),
                _m: PhantomData {},
            })
    }

    fn verify_signature_and_unrandomize(
        unsigned_token: Self::UnsignedToken,
        _randomized_unsigned_token: Self::RandomizedUnsignedToken,
        signed_token: Self::RandomizedSignedToken,
        verification_data: &Self::UserVerification,
        randomization: Self::Randomization,
    ) -> Option<Self::SignedToken> {
        // the public key point
        let pk: G2Affine = <&PublicKey>::into(verification_data);
        let u_point: G2Projective = G2Affine::generator() * h_m(&unsigned_token.metadata) + pk;

        // remove randomization
        let w = (G1Affine::from(&signed_token.point) * randomization).into();

        // The token identifier
        let t: [u8; 16] = (&unsigned_token.id).into();

        // Verify that the signature is correct
        if Bls12::pairing(&w, &u_point.into())
            == Bls12::pairing(&h_1(&t, &unsigned_token.metadata), &G2Affine::generator())
        {
            Some(Self::SignedToken {
                signature: w.into(),
                id: unsigned_token.id,
                metadata: unsigned_token.metadata,
            })
        } else {
            None
        }
    }
}

// }}}

// {{{ Tests

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::{
        keys::{PrivateKey, PublicKey},
        UnsignedToken,
    };

    #[test]
    fn test_all() {
        let message = b"this is public metadata";

        let secret_key = PrivateKey::new();
        let public_key = PublicKey::from(&secret_key);

        let unsigned_token = PairingUnsignedToken::new(message);

        let (r, anonymized_token) = PairingTokenEngine::randomize(&unsigned_token);

        let signed = PairingTokenEngine::sign_randomized(&anonymized_token, &secret_key).unwrap();

        let signed_token = PairingTokenEngine::verify_signature_and_unrandomize(
            unsigned_token,
            anonymized_token,
            signed,
            &public_key,
            r,
        )
        .unwrap();

        assert!(signed_token.verify(&public_key));
    }

    #[test]
    fn test_wrong_sign_key() {
        let message = b"this is public metadata";

        let secret_key = PrivateKey::new();
        let public_key = PublicKey::from(&secret_key);

        let unsigned_token = UnsignedToken::new(message);

        let (r, anonymized_token) = PairingTokenEngine::randomize(&unsigned_token);

        let wrong_secret_key = PrivateKey::new();

        let signed =
            PairingTokenEngine::sign_randomized(&anonymized_token, &wrong_secret_key).unwrap();

        let signed_token = PairingTokenEngine::verify_signature_and_unrandomize(
            unsigned_token,
            anonymized_token,
            signed,
            &public_key,
            r,
        );

        assert!(signed_token.is_none())
    }

    #[test]
    fn test_wrong_verification_key() {
        let message = b"this is public metadata";

        let secret_key = PrivateKey::new();
        let public_key = PublicKey::from(&secret_key);

        let unsigned_token = UnsignedToken::new(&message[..]);

        let (r, anonymized_token) = PairingTokenEngine::randomize(&unsigned_token);

        let signed = PairingTokenEngine::sign_randomized(&anonymized_token, &secret_key).unwrap();

        let signed_token = PairingTokenEngine::verify_signature_and_unrandomize(
            unsigned_token,
            anonymized_token,
            signed,
            &public_key,
            r,
        )
        .unwrap();

        let secret_key = PrivateKey::new();
        let wrong_public_key = PublicKey::from(&secret_key);

        assert!(!signed_token.verify(&wrong_public_key));
    }
}

// }}}
