use alloc::boxed::Box;
use core::marker::PhantomData;

use super::{
    keys::{PrivateKey, PublicKey},
    SignedToken, TokenEngine, TokenIdentifier, UnsignedToken,
};

use sha2::{Digest, Sha512};
use subtle::{Choice, CtOption};

use super::util::{h_t, hash_to_scalar};

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};

// {{{ DLEQProof

#[derive(Clone)]
struct DLEQProof {
    c: Scalar,
    z: Scalar,
}

impl DLEQProof {
    fn hash_data(
        u: &RistrettoPoint,
        t: &RistrettoPoint,
        w: &RistrettoPoint,
        a: &RistrettoPoint,
        b: &RistrettoPoint,
    ) -> Scalar {
        let mut hasher = Sha512::new();

        // domain of the oracle, to have separate oracles
        hasher.update(b"This is DLEQ_PROOF hash");

        hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
        hasher.update(u.compress().as_bytes());
        hasher.update(t.compress().as_bytes());
        hasher.update(w.compress().as_bytes());
        hasher.update(a.compress().as_bytes());
        hasher.update(b.compress().as_bytes());

        // Turn the bytes uniformly and deterministically into a scalar
        Scalar::from_hash(hasher)
    }

    /// Create a proof of the fact that log_w t = k
    ///
    /// If you create w=(d+k)^{-1} t, then create this proof with create(t, w, d + k)
    pub fn create(t: RistrettoPoint, w: RistrettoPoint, k: Scalar) -> Self {
        let r = Scalar::random(&mut rand::thread_rng());
        let a = &RISTRETTO_BASEPOINT_TABLE * &r;
        let b = w * r;

        let c = DLEQProof::hash_data(&(&RISTRETTO_BASEPOINT_TABLE * &k), &t, &w, &a, &b);

        let z = r - k * c;

        Self { c, z }
    }

    /// Verify the proof that log_w t = k
    ///
    /// If w was created as w=(d+k)^{-1} t, and have U=(d+k)G, then call as verify(t, w, u)
    pub fn verify(
        &self,
        t: RistrettoPoint,
        w: RistrettoPoint,
        public_key: RistrettoPoint,
    ) -> bool {
        let a = &RISTRETTO_BASEPOINT_TABLE * &self.z + public_key * self.c;
        let b = w * self.z + t * self.c;
        let c = DLEQProof::hash_data(&public_key, &t, &w, &a, &b);

        c == self.c
    }
}

// }}}

// {{{ UnsignedToken

pub struct NizkpUnsignedToken<M: AsRef<[u8]>> {
    id: TokenIdentifier<M>,
    metadata: M,
}

impl<M: AsRef<[u8]>> NizkpUnsignedToken<M> {
    pub fn get_point(&self) -> RistrettoPoint {
        let t: [u8; 16] = (&self.id).into();

        h_t(t, &self.metadata)
    }
}

impl<M: AsRef<[u8]>> UnsignedToken for NizkpUnsignedToken<M> {
    type Metadata = M;
    type HiddenMetadata = M;

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

// }}}

// {{{   Randomized signed

pub struct RandomizedSignedToken<M: AsRef<[u8]>> {
    point: RistrettoPoint,
    proof: DLEQProof,
    _m: PhantomData<M>,
}

// }}}

// {{{ randomized unsigned

pub struct RandomizedUnsignedToken<M: AsRef<[u8]>> {
    point: RistrettoPoint,
    metadata: Box<[u8]>,
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>> crate::common::RandomizedUnsignedToken for RandomizedUnsignedToken<M> {
    fn metadata(&self) -> Box<[u8]> {
        self.metadata.clone()
    }
}

// }}}

// {{{ Signed token

pub struct NizkpSignedToken<M: AsRef<[u8]>> {
    id: TokenIdentifier<M>,
    metadata: M,
    point: RistrettoPoint,
}

impl<M: AsRef<[u8]>> SignedToken for NizkpSignedToken<M> {
    type VerificationKey = PrivateKey;

    fn verify(&self, verification_key: &Self::VerificationKey) -> bool {
        let t: [u8; 16] = (&self.id).into();
        let t = h_t(t, &self.metadata);

        // We may do this, since
        // w == e * t is the same as e^-1 w == t
        // We then do not need to do the inversion step, and maybe it could be easier to build
        // batch verification
        let e_inverse = hash_to_scalar(&self.metadata) + verification_key.to_scalar();

        let signed = self.point * e_inverse;

        signed == t
    }
}

// }}}

// {{{ Token engine

pub struct NizkpTokenEngine<M: AsRef<[u8]>> {
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>> TokenEngine for NizkpTokenEngine<M> {
    type UnsignedToken = NizkpUnsignedToken<M>;
    type RandomizedUnsignedToken = RandomizedUnsignedToken<M>;
    type RandomizedSignedToken = RandomizedSignedToken<M>;
    type SignedToken = NizkpSignedToken<M>;
    type Randomization = Scalar;
    type UserVerification = PublicKey;
    type SignKey = PrivateKey;

    //For batched tokens we generate a seed for an rng to reduce memory usage. It had to be verified that all scalars are invertible
    fn randomize(
        unsigned_token: &Self::UnsignedToken,
    ) -> (Self::Randomization, Self::RandomizedUnsignedToken) {
        let r = Scalar::random(&mut rand::thread_rng());
        let inverse = r.invert();
        (
            r,
            Self::RandomizedUnsignedToken {
                point: unsigned_token.get_point() * inverse,
                metadata: Box::from(unsigned_token.metadata.as_ref()),
                _m: PhantomData {},
            },
        )
    }

    fn verify_signature_and_unrandomize(
        unsigned_token: Self::UnsignedToken,
        randomized_unsigned_token: Self::RandomizedUnsignedToken,
        signed_token: Self::RandomizedSignedToken,
        verification_data: &Self::UserVerification,
        randomization: Self::Randomization,
    ) -> Option<Self::SignedToken> {
        // get the public key
        let u = &RISTRETTO_BASEPOINT_TABLE * &hash_to_scalar(&unsigned_token.metadata)
            + verification_data.to_affine();

        // verify proof
        if signed_token
            .proof
            .verify(randomized_unsigned_token.point, signed_token.point, u)
        {
            // Remove randomization
            Some(Self::SignedToken {
                point: signed_token.point * randomization,
                metadata: unsigned_token.metadata,
                id: unsigned_token.id,
            })
        } else {
            None
        }
    }

    fn sign_randomized(
        t_prime: &Self::RandomizedUnsignedToken,
        sign_key: &Self::SignKey,
    ) -> CtOption<Self::RandomizedSignedToken> {
        // This should be a constant time implementation
        let d = hash_to_scalar(&t_prime.metadata);
        let e = (d + sign_key.to_scalar()).invert();

        let w = t_prime.point * e;

        CtOption::new(
            Self::RandomizedSignedToken {
                point: w,
                proof: DLEQProof::create(t_prime.point, w, d + sign_key.to_scalar()),
                _m: PhantomData {},
            },
            Choice::from(1),
        )
    }
}

// }}}

// {{{ tests

#[cfg(test)]
mod tests {
    use super::super::keys::{PrivateKey, PublicKey};
    use super::*;

    #[test]
    fn test_proof() {
        // setup
        let mut rng = rand::thread_rng();

        // create keys
        let private_key = Scalar::random(&mut rng);
        let public_key = &RISTRETTO_BASEPOINT_TABLE * &private_key;

        // token metadata
        let metadata = b"kake";
        let d = hash_to_scalar(metadata);

        // create token
        let t = &RISTRETTO_BASEPOINT_TABLE * &(Scalar::random(&mut rng) + d);

        // create u
        let u = &RISTRETTO_BASEPOINT_TABLE * &d + public_key;

        // sign token
        let e = (private_key + d).invert();
        let w = t * e;

        // create proof
        let proof = DLEQProof::create(t, w, private_key + d);

        // verify
        assert!(proof.verify(t, w, u));
    }

    #[test]
    fn test_all() {
        // generate keys
        let private = PrivateKey::new();
        let public_key = PublicKey::from(&private);

        // generate a new token
        let metadata = b"This is my metadata";
        let token = NizkpTokenEngine::generate(metadata);

        // randomize token
        let (r, anon_token) = NizkpTokenEngine::randomize(&token);

        // sign randomized token
        let signed = NizkpTokenEngine::sign_randomized(&anon_token, &private).unwrap();

        // Verify signature and remove randomization
        let signed = NizkpTokenEngine::verify_signature_and_unrandomize(
            token,
            anon_token,
            signed,
            &public_key,
            r,
        );
        assert!(signed.is_some());

        // verify personalized token
        assert!(signed.unwrap().verify(&private));
    }

    #[test]
    fn test_hidden() {
        // generate keys
        let private = PrivateKey::new();
        let public_key = PublicKey::from(&private);

        // generate a new token
        let metadata = b"This is my metadata";
        let hidden_metadata = b"This is my hidden metadata";
        let token = NizkpTokenEngine::generate_with_hidden(&metadata[..], &hidden_metadata[..]);

        // randomize token
        let (r, anon_token) = NizkpTokenEngine::randomize(&token);

        // sign randomized token
        let signed = NizkpTokenEngine::sign_randomized(&anon_token, &private).unwrap();

        // verify the signature and remove the randomization
        let signed = NizkpTokenEngine::verify_signature_and_unrandomize(
            token,
            anon_token,
            signed,
            &public_key,
            r,
        );

        assert!(signed.is_some());

        // verify personalized token
        assert!(signed.unwrap().verify(&private));
    }

    #[test]
    fn fail_bad_signkey() {
        // generate keys
        let private = PrivateKey::new();
        let public_key = PublicKey::from(&private);

        // generate a new token
        let metadata = b"This is my metadata";
        let token = NizkpTokenEngine::generate(metadata);

        let bad = PrivateKey::new();

        let signed = NizkpTokenEngine::sign(token, &public_key, |randomized| {
            NizkpTokenEngine::sign_randomized(randomized, &bad)
        });

        assert!(signed.is_none());
    }

    #[test]
    fn fail_bad_verification_key() {
        // generate keys
        let private = PrivateKey::new();
        let public_key = PublicKey::from(&private);

        // generate a new token
        let metadata = b"This is my metadata";
        let token = NizkpTokenEngine::generate(metadata);

        let signed = NizkpTokenEngine::sign(token, &public_key, |randomized| {
            NizkpTokenEngine::sign_randomized(randomized, &private)
        })
        .unwrap();

        let bad = PrivateKey::new();

        assert!(!signed.verify(&bad));
    }
}

// }}}
