use alloc::{boxed::Box, vec::Vec};
use core::{convert::TryInto, iter::repeat_with, marker::PhantomData};
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::Identity,
};
use rand::{prelude::StdRng, SeedableRng};
// use serde::{Deserialize, Serialize};

use crate::common::fill_bytes;

use super::{
    keys::{PrivateKey, PublicKey},
    SignedToken, TokenEngine, TokenIdentifier, UnsignedToken,
};

use sha2::{Digest, Sha256, Sha512};
use subtle::{Choice, CtOption};

use super::util::{h_t, hash_to_scalar};

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
        hasher.update(b"This is DLEQ_PROOF hash");
        hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
        hasher.update(u.compress().as_bytes());
        hasher.update(t.compress().as_bytes());
        hasher.update(w.compress().as_bytes());
        hasher.update(a.compress().as_bytes());
        hasher.update(b.compress().as_bytes());

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

struct DLEQProofBatched {
    proof: DLEQProof,
}

impl DLEQProofBatched {
    fn hash_data(
        unsignedvec: impl AsRef<[RistrettoPoint]>,
        signedvec: impl AsRef<[RistrettoPoint]>,
        public_key: RistrettoPoint,
    ) -> StdRng {
        let mut hasher = Sha256::new();
        hasher.update(b"This is DLEQ_PROOF hash");
        hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
        hasher.update(public_key.compress().as_bytes());
        unsignedvec.as_ref().iter().for_each(|thing| {
            hasher.update(thing.compress().as_bytes());
        });

        signedvec.as_ref().iter().for_each(|item| {
            hasher.update(item.compress().as_bytes());
        });

        // seedable determinizstic rng
        StdRng::from_seed(hasher.finalize().into())
    }

    ///For use in batched verification
    /// Creates a random linear combination of the batch of tokens given trough use of hash function which seeds an rng
    fn hash_random_linear_combination(
        t_list: impl AsRef<[RistrettoPoint]>,
        w_list: impl AsRef<[RistrettoPoint]>,
        public_key: RistrettoPoint,
    ) -> (RistrettoPoint, RistrettoPoint) {
        let mut c = DLEQProofBatched::hash_data(&t_list, &w_list, public_key);
        let (newt, neww) = t_list
            .as_ref()
            .iter()
            .zip(w_list.as_ref().iter())
            .map(|(t, w)| {
                let c = Scalar::random(&mut c);
                (t * c, w * c)
            })
            .fold(
                (RistrettoPoint::identity(), RistrettoPoint::identity()),
                |(tsum, wsum), (t, w)| (tsum + t, wsum + w),
            );
        (newt, neww)
    }

    pub fn create(
        t_list: impl AsRef<[RistrettoPoint]>,
        w_list: impl AsRef<[RistrettoPoint]>,
        k: Scalar,
    ) -> Self {
        let (m, z) = DLEQProofBatched::hash_random_linear_combination(
            t_list,
            w_list,
            &RISTRETTO_BASEPOINT_TABLE * &k,
        );
        let proof = DLEQProof::create(m, z, k);
        Self { proof }
    }
    /// Verifies the proof for the linear combination of the tokens in the batch
    /// If w was created as w=(d+k)^{-1} t, and have U=(d+k)G, then call as verify(t, w, u)
    pub fn verify<const N: usize>(
        &self,
        unsignedvec: [RistrettoPoint; N],
        signedvec: [RistrettoPoint; N],
        public_key: RistrettoPoint,
    ) -> bool {
        let (m, z) =
            DLEQProofBatched::hash_random_linear_combination(unsignedvec, signedvec, public_key);
        self.proof.verify(m, z, public_key)
    }
}

// }}}

// {{{ UnsignedToken

pub struct NizkpUnsignedTokenBatched<M: AsRef<[u8]>, const N: usize> {
    ids: [TokenIdentifier<M>; N],
    metadata: M,
}
impl<M: AsRef<[u8]>, const N: usize> From<&NizkpUnsignedTokenBatched<M, N>>
    for [RistrettoPoint; N]
{
    fn from(token: &NizkpUnsignedTokenBatched<M, N>) -> Self {
        let points: [RistrettoPoint; N] = (&token.ids)
            .iter()
            .map(|id| {
                let t: [u8; 16] = id.into();
                h_t(t, &token.metadata)
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        points
    }
}

impl<M: AsRef<[u8]>, const N: usize> UnsignedToken for NizkpUnsignedTokenBatched<M, N> {
    type Metadata = M;
    type HiddenMetadata = M;

    fn new(metadata: Self::Metadata) -> Self {
        Self {
            ids: TokenIdentifier::generate(),
            metadata,
        }
    }

    // needs thinking
    fn with_hidden(_metadata: Self::Metadata, _hidden: Self::HiddenMetadata) -> Self {
        todo!()
    }
}

// }}}

// {{{   Randomized signed

pub struct RandomizedSignedTokenBatched<M: AsRef<[u8]>, const N: usize> {
    points: [RistrettoPoint; N],
    proof: DLEQProofBatched,
    _m: PhantomData<M>,
}

pub struct RandomizedUnsignedTokenBatched<M: AsRef<[u8]>, const N: usize> {
    points: [RistrettoPoint; N],
    metadata: Box<[u8]>,
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>, const N: usize> crate::common::RandomizedUnsignedToken
    for RandomizedUnsignedTokenBatched<M, N>
{
    fn metadata(&self) -> Box<[u8]> {
        self.metadata.clone()
    }
}

// }}}

// {{{ Signed token

pub struct NizkpSignedTokenBatched<M: AsRef<[u8]>, const N: usize> {
    ids: [TokenIdentifier<M>; N],
    metadata: M,
    points: [RistrettoPoint; N],
}

impl<M: AsRef<[u8]>, const N: usize> SignedToken for NizkpSignedTokenBatched<M, N> {
    type VerificationKey = PrivateKey;

    fn verify(&self, verification_key: &Self::VerificationKey) -> bool {
        let tpoints: [RistrettoPoint; N] = (&self.ids)
            .iter()
            .map(|id| {
                let t: [u8; 16] = id.into();
                h_t(t, &self.metadata)
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        // We may do this, since
        // w == e * t is the same as e^-1 w == t
        // We then do not need to do the inversion step, and maybe it could be easier to build
        // batch verification
        let e_inverse = hash_to_scalar(&self.metadata) + verification_key.to_scalar();
        //prove that this is valid
        (self
            .points
            .iter()
            .fold(RistrettoPoint::identity(), |sum, point| sum + point)
            * e_inverse)
            == tpoints
                .iter()
                .fold(RistrettoPoint::identity(), |sum, point| sum + point)
    }
}

// }}}

// {{{ Token engine

pub struct BatchedNizkpTokenEngine<M: AsRef<[u8]>, const N: usize> {
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>, const N: usize> TokenEngine for BatchedNizkpTokenEngine<M, N> {
    type UnsignedToken = NizkpUnsignedTokenBatched<M, N>;
    type RandomizedUnsignedToken = RandomizedUnsignedTokenBatched<M, N>;
    type RandomizedSignedToken = RandomizedSignedTokenBatched<M, N>;
    type SignedToken = NizkpSignedTokenBatched<M, N>;
    type Randomization = [u8; 32];
    type UserVerification = PublicKey;
    type SignKey = PrivateKey;

    //For batched tokens we generate a seed for an rng to reduce memory usage. It had to be verified that all scalars are invertible
    fn randomize(
        unsigned_token: &Self::UnsignedToken,
    ) -> (Self::Randomization, Self::RandomizedUnsignedToken) {
        // create random seed
        let mut randomization = [0; 32];
        fill_bytes(&mut rand::thread_rng(), &mut randomization);

        // seed an rng for the series of r
        let mut rng = StdRng::from_seed(randomization);

        (
            randomization,
            Self::RandomizedUnsignedToken {
                points: repeat_with(|| Scalar::random(&mut rng)) // generate random r's
                    .take(N)
                    .map(|r| r.invert())
                    .zip(unsigned_token.ids.iter())
                    .map(|(r, id)| {
                        let t: [u8; 16] = id.into();
                        // T' = [r]T
                        h_t(t, &unsigned_token.metadata) * r
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .ok()
                    .unwrap(),
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
            .verify(randomized_unsigned_token.points, signed_token.points, u)
        {
            // needs fix
            // Remove randomization

            let mut rng = StdRng::from_seed(randomization);
            let rlist = repeat_with(|| Scalar::random(&mut rng)).take(N);
            Some(Self::SignedToken {
                points: (signed_token
                    .points
                    .iter()
                    .zip(rlist)
                    .map(|(point, r)| point * r)
                    .collect::<Vec<_>>()
                    .try_into()
                    .ok()
                    .unwrap()),
                metadata: unsigned_token.metadata,
                ids: unsigned_token.ids,
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
        // list of W'
        let w_prime_list = t_prime
            .points
            .iter()
            .map(|t_prime| t_prime * e)
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();

        //

        let proof =
            DLEQProofBatched::create(&t_prime.points, &w_prime_list, d + sign_key.to_scalar());

        CtOption::new(
            RandomizedSignedTokenBatched {
                points: w_prime_list,
                proof,
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
        let token = BatchedNizkpTokenEngine::<_, 5>::generate(metadata);

        // randomize token
        let (r, anon_token) = BatchedNizkpTokenEngine::randomize(&token);

        // sign randomized token
        let signed = BatchedNizkpTokenEngine::sign_randomized(&anon_token, &private).unwrap();

        // Verify signature and remove randomization
        let signed = BatchedNizkpTokenEngine::verify_signature_and_unrandomize(
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
        let token = BatchedNizkpTokenEngine::<_, 5>::generate(metadata);

        let bad = PrivateKey::new();

        // sign randomized token
        let signed = BatchedNizkpTokenEngine::sign(token, &public_key, |randomized| {
            BatchedNizkpTokenEngine::sign_randomized(randomized, &bad)
        });

        assert!(signed.is_none());
    }

    #[test]
    fn fail_bad_verf_key() {
        // generate keys
        let private = PrivateKey::new();
        let public_key = PublicKey::from(&private);

        // generate a new token
        let metadata = b"This is my metadata";
        let token = BatchedNizkpTokenEngine::<_, 5>::generate(metadata);

        let signed = BatchedNizkpTokenEngine::sign(token, &public_key, |randomized| {
            BatchedNizkpTokenEngine::sign_randomized(randomized, &private)
        })
        .unwrap();

        let bad = PrivateKey::new();

        assert!(!signed.verify(&bad));
    }
}

// }}}
