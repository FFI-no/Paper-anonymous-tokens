use alloc::{boxed::Box, vec::Vec};
use core::{convert::TryInto, iter::repeat_with, marker::PhantomData};
use rand::{prelude::StdRng, SeedableRng};
// use serde::{Deserialize, Serialize};

use crate::common::fill_bytes;

use super::{
    keys::{PrivateKey, PublicKey},
    util::gen_vartime,
    SignedToken, TokenEngine, TokenIdentifier, UnsignedToken,
};

use elliptic_curve::{
    group::Curve as Crv, group::GroupEncoding, ops::Invert, AffinePoint, Curve, Group,
    ProjectiveArithmetic, ProjectivePoint, Scalar,
};

use sha2::{Digest, Sha256};
use subtle::CtOption;

use super::util::{h_t, hash_to_scalar};

// {{{ DLEQProof

#[derive(Clone)]
struct DLEQProof<C: Curve + ProjectiveArithmetic> {
    c: Scalar<C>,
    z: Scalar<C>,
}

impl<C: Curve + ProjectiveArithmetic> DLEQProof<C>
where
    AffinePoint<C>: GroupEncoding,
{
    fn hash_data(
        u: AffinePoint<C>,
        t: AffinePoint<C>,
        w: AffinePoint<C>,
        a: AffinePoint<C>,
        b: AffinePoint<C>,
    ) -> Scalar<C> {
        let mut hasher = Sha256::new();
        hasher.update(b"This is DLEQ_PROOF hash");
        hasher.update(GroupEncoding::to_bytes(
            &ProjectivePoint::<C>::generator().to_affine(),
        ));
        hasher.update(GroupEncoding::to_bytes(&u));
        hasher.update(GroupEncoding::to_bytes(&t));
        hasher.update(GroupEncoding::to_bytes(&w));
        hasher.update(GroupEncoding::to_bytes(&a));
        hasher.update(GroupEncoding::to_bytes(&b));

        hash_to_scalar::<C, _>(&hasher.finalize())
    }

    /// Create a proof of the fact that log_w t = k
    ///
    /// If you create w=(d+k)^{-1} t, then create this proof with create(t, w, d + k)
    pub fn create(t: AffinePoint<C>, w: AffinePoint<C>, k: Scalar<C>) -> Self {
        let r = gen_vartime::<C, _>(&mut rand::thread_rng());
        let a = ProjectivePoint::<C>::generator() * r;
        let b = ProjectivePoint::<C>::from(w) * r;

        let c = DLEQProof::<C>::hash_data(
            (ProjectivePoint::<C>::generator() * k).to_affine(),
            t,
            w,
            a.to_affine(),
            b.to_affine(),
        );

        let z = r - k * c;

        Self { c, z }
    }

    /// Verify the proof that log_w t = k
    ///
    /// If w was created as w=(d+k)^{-1} t, and have U=(d+k)G, then call as verify(t, w, u)
    pub fn verify(
        &self,
        t: AffinePoint<C>,
        w: AffinePoint<C>,
        public_key: AffinePoint<C>,
    ) -> bool {
        let a = ProjectivePoint::<C>::generator() * self.z
            + ProjectivePoint::<C>::from(public_key) * self.c;
        let b = ProjectivePoint::<C>::from(w) * self.z + ProjectivePoint::<C>::from(t) * self.c;
        let c = DLEQProof::<C>::hash_data(public_key, t, w, a.to_affine(), b.to_affine());

        c == self.c
    }
}

struct DLEQProofBatched<C: Curve + ProjectiveArithmetic> {
    proof: DLEQProof<C>,
}

impl<C: Curve + ProjectiveArithmetic> DLEQProofBatched<C>
where
    AffinePoint<C>: GroupEncoding,
{
    fn hash_data(
        unsignedvec: impl AsRef<[AffinePoint<C>]>,
        signedvec: impl AsRef<[AffinePoint<C>]>,
        public_key: AffinePoint<C>,
    ) -> StdRng {
        let mut hasher = Sha256::new();
        hasher.update(b"This is DLEQ_PROOF hash");
        hasher.update(GroupEncoding::to_bytes(
            &ProjectivePoint::<C>::generator().to_affine(),
        ));
        hasher.update(GroupEncoding::to_bytes(&public_key));
        unsignedvec.as_ref().iter().for_each(|thing| {
            hasher.update(GroupEncoding::to_bytes(thing));
        });

        signedvec.as_ref().iter().for_each(|item| {
            hasher.update(GroupEncoding::to_bytes(item));
        });

        // seedable determinizstic rng
        StdRng::from_seed(hasher.finalize().into())
    }

    ///For use in batched verification
    /// Creates a random linear combination of the batch of tokens given trough use of hash function which seeds an rng
    fn hash_random_linear_combination(
        t_list: impl AsRef<[AffinePoint<C>]>,
        w_list: impl AsRef<[AffinePoint<C>]>,
        public_key: AffinePoint<C>,
    ) -> (AffinePoint<C>, AffinePoint<C>) {
        let mut c = DLEQProofBatched::<C>::hash_data(&t_list, &w_list, public_key);
        let (newt, neww) = t_list
            .as_ref()
            .iter()
            .zip(w_list.as_ref().iter())
            .map(|(t, w)| {
                let c = gen_vartime::<C, _>(&mut c);
                (
                    ((ProjectivePoint::<C>::from(*t)) * c).to_affine(),
                    (ProjectivePoint::<C>::from(*w) * c).to_affine(),
                )
            })
            .fold(
                (
                    ProjectivePoint::<C>::identity(),
                    ProjectivePoint::<C>::identity(),
                ),
                |(tsum, wsum), (t, w)| (tsum + t, wsum + w),
            );
        (newt.to_affine(), neww.to_affine())
    }

    pub fn create(
        t_list: impl AsRef<[AffinePoint<C>]>,
        w_list: impl AsRef<[AffinePoint<C>]>,
        k: Scalar<C>,
    ) -> Self {
        let (m, z) = DLEQProofBatched::<C>::hash_random_linear_combination(
            t_list,
            w_list,
            (ProjectivePoint::<C>::generator() * k).to_affine(),
        );
        let proof = DLEQProof::create(m, z, k);
        Self { proof }
    }
    /// Verifies the proof for the linear combination of the tokens in the batch
    /// If w was created as w=(d+k)^{-1} t, and have U=(d+k)G, then call as verify(t, w, u)
    pub fn verify<const N: usize>(
        &self,
        unsignedvec: [AffinePoint<C>; N],
        signedvec: [AffinePoint<C>; N],
        public_key: AffinePoint<C>,
    ) -> bool {
        let (m, z) = DLEQProofBatched::<C>::hash_random_linear_combination(
            unsignedvec,
            signedvec,
            public_key,
        );
        self.proof.verify(m, z, public_key)
    }
}

// }}}

// {{{ UnsignedToken

pub struct NizkpUnsignedTokenBatched<
    M: AsRef<[u8]>,
    C: Curve + ProjectiveArithmetic,
    const N: usize,
> {
    ids: [TokenIdentifier<M>; N],
    metadata: M,
    _c: PhantomData<C>,
}
impl<M: AsRef<[u8]>, C: Curve + ProjectiveArithmetic, const N: usize>
    From<&NizkpUnsignedTokenBatched<M, C, N>> for [AffinePoint<C>; N]
{
    fn from(token: &NizkpUnsignedTokenBatched<M, C, N>) -> Self {
        let points: [AffinePoint<C>; N] = (&token.ids)
            .iter()
            .map(|id| {
                let t: [u8; 16] = id.into();
                h_t::<C, _, _>(t, &token.metadata)
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        points
    }
}

impl<M: AsRef<[u8]>, C: Curve + ProjectiveArithmetic, const N: usize> UnsignedToken
    for NizkpUnsignedTokenBatched<M, C, N>
{
    type Metadata = M;
    type HiddenMetadata = M;

    fn new(metadata: Self::Metadata) -> Self {
        Self {
            ids: TokenIdentifier::generate(),
            metadata,
            _c: PhantomData {},
        }
    }

    // needs thinking
    fn with_hidden(_metadata: Self::Metadata, _hidden: Self::HiddenMetadata) -> Self {
        todo!()
    }
}

// }}}

// {{{   Randomized signed

pub struct RandomizedSignedTokenBatched<
    M: AsRef<[u8]>,
    C: Curve + ProjectiveArithmetic,
    const N: usize,
> {
    points: [AffinePoint<C>; N],
    proof: DLEQProofBatched<C>,
    _m: PhantomData<M>,
}

pub struct RandomizedUnsignedTokenBatched<
    M: AsRef<[u8]>,
    C: Curve + ProjectiveArithmetic,
    const N: usize,
> {
    points: [AffinePoint<C>; N],
    metadata: Box<[u8]>,
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>, C: Curve + ProjectiveArithmetic, const N: usize>
    crate::common::RandomizedUnsignedToken for RandomizedUnsignedTokenBatched<M, C, N>
{
    fn metadata(&self) -> Box<[u8]> {
        self.metadata.clone()
    }
}

// }}}

// {{{ Signed token

pub struct NizkpSignedTokenBatched<M: AsRef<[u8]>, C: Curve + ProjectiveArithmetic, const N: usize>
{
    ids: [TokenIdentifier<M>; N],
    metadata: M,
    points: [AffinePoint<C>; N],
}

impl<M: AsRef<[u8]>, C: Curve + ProjectiveArithmetic, const N: usize> SignedToken
    for NizkpSignedTokenBatched<M, C, N>
where
    Scalar<C>: Invert<Output = Scalar<C>>,
    AffinePoint<C>: PartialEq,
{
    type VerificationKey = PrivateKey<C>;

    fn verify(&self, verification_key: &Self::VerificationKey) -> bool {
        let tpoints: [AffinePoint<C>; N] = (&self.ids)
            .iter()
            .map(|id| {
                let t: [u8; 16] = id.into();
                h_t::<C, _, _>(t, &self.metadata)
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        // We may do this, since
        // w == e * t is the same as e^-1 w == t
        // We then do not need to do the inversion step, and maybe it could be easier to build
        // batch verification
        let e_inverse = hash_to_scalar::<C, _>(&self.metadata) + verification_key.to_scalar();
        //prove that this is valid
        (self
            .points
            .iter()
            .fold(ProjectivePoint::<C>::identity(), |sum, point| sum + point)
            * e_inverse)
            .to_affine()
            == tpoints
                .iter()
                .fold(ProjectivePoint::<C>::identity(), |sum, point| sum + point)
                .to_affine()
    }
}

// }}}

// {{{ Token engine

pub struct BatchedNizkpTokenEngine<M: AsRef<[u8]>, C: Curve + ProjectiveArithmetic, const N: usize>
where
    AffinePoint<C>: GroupEncoding + PartialEq,
{
    _m: PhantomData<M>,
    _c: PhantomData<C>,
}

impl<M: AsRef<[u8]>, C: Curve + ProjectiveArithmetic, const N: usize> TokenEngine
    for BatchedNizkpTokenEngine<M, C, N>
where
    AffinePoint<C>: GroupEncoding + PartialEq,
    Scalar<C>: Invert<Output = Scalar<C>>,
{
    type UnsignedToken = NizkpUnsignedTokenBatched<M, C, N>;
    type RandomizedUnsignedToken = RandomizedUnsignedTokenBatched<M, C, N>;
    type RandomizedSignedToken = RandomizedSignedTokenBatched<M, C, N>;
    type SignedToken = NizkpSignedTokenBatched<M, C, N>;
    type Randomization = [u8; 32];
    type UserVerification = PublicKey<C>;
    type SignKey = PrivateKey<C>;

    //For batched tokens we generate a seed for an rng to reduce memory usage. It had to be verified that all scalars are invertible
    fn randomize(
        unsigned_token: &Self::UnsignedToken,
    ) -> (Self::Randomization, Self::RandomizedUnsignedToken) {
        // create random seed
        let mut randomization = [0; 32];
        fill_bytes(&mut rand::thread_rng(), &mut randomization);

        // seed an rng for the series of r
        let mut rng = StdRng::from_seed(randomization);

        let nums = repeat_with(|| gen_vartime::<C, _>(&mut rng)) // generate random r's
            .take(N)
            .map(|r| r.invert())
            .fold(Some(Vec::new()), |v, e| match v {
                // Fold down the list to remove failed random numbers,
                // should be None
                Some(mut v) => {
                    if bool::from(e.is_some()) {
                        v.push(e.unwrap());
                        Some(v)
                    } else {
                        None
                    }
                }
                None => None,
            });

        if nums.is_none() {
            Self::randomize(unsigned_token)
        } else {
            (
                randomization,
                Self::RandomizedUnsignedToken {
                    points: nums
                        .unwrap()
                        .into_iter()
                        .zip(unsigned_token.ids.iter())
                        .map(|(r, id)| {
                            let t: [u8; 16] = id.into();
                            // T' = [r]T
                            (ProjectivePoint::<C>::from(h_t::<C, _, _>(
                                t,
                                &unsigned_token.metadata,
                            )) * r)
                                .to_affine()
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
    }

    fn verify_signature_and_unrandomize(
        unsigned_token: Self::UnsignedToken,
        randomized_unsigned_token: Self::RandomizedUnsignedToken,
        signed_token: Self::RandomizedSignedToken,
        verification_data: &Self::UserVerification,
        randomization: Self::Randomization,
    ) -> Option<Self::SignedToken> {
        // get the public key
        let u = ProjectivePoint::<C>::generator()
            * hash_to_scalar::<C, _>(&unsigned_token.metadata)
            + verification_data.to_affine();

        // verify proof
        if signed_token.proof.verify(
            randomized_unsigned_token.points,
            signed_token.points,
            u.to_affine(),
        ) {
            // needs fix
            // Remove randomization

            let mut rng = StdRng::from_seed(randomization);
            let rlist = repeat_with(|| gen_vartime::<C, _>(&mut rng)).take(N);
            Some(Self::SignedToken {
                points: (signed_token
                    .points
                    .iter()
                    .zip(rlist)
                    .map(|(point, r)| (ProjectivePoint::<C>::from(*point) * r).to_affine())
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
        let d = hash_to_scalar::<C, _>(&t_prime.metadata);
        (d + sign_key.to_scalar()).invert().map(|e| {
            // list of W'
            let w_prime_list = t_prime
                .points
                .iter()
                .map(|t_prime| (ProjectivePoint::<C>::from(*t_prime) * e).to_affine())
                .collect::<Vec<_>>()
                .try_into()
                .ok()
                .unwrap();

            //

            let proof =
                DLEQProofBatched::create(&t_prime.points, &w_prime_list, d + sign_key.to_scalar());
            RandomizedSignedTokenBatched {
                points: w_prime_list,
                proof,
                _m: PhantomData {},
            }
        })
    }
}

// }}}

// {{{ tests

#[cfg(test)]
mod tests {
    use super::super::keys::{PrivateKey, PublicKey};
    use super::*;

    use elliptic_curve::group::prime::PrimeCurveAffine;
    use k256::{AffinePoint, ProjectivePoint, Scalar, Secp256k1};

    #[test]
    fn test_proof() {
        // setup
        let mut rng = rand::thread_rng();

        // create keys
        let private_key = Scalar::generate_biased(&mut rng);
        let public_key = AffinePoint::generator() * private_key;
        let public_key = public_key.to_affine();

        // token metadata
        let metadata = b"kake";
        let d = hash_to_scalar::<Secp256k1, _>(metadata);

        // create token
        let t = ProjectivePoint::generator() * (Scalar::generate_biased(&mut rng) + d);
        let t = t.to_affine();

        // create u
        let u = ProjectivePoint::generator() * d + public_key;
        let u = u.to_affine();

        // sign token
        let e = (private_key + d).invert().unwrap();
        let w = t * e;
        let w = w.to_affine();

        // create proof
        let proof = DLEQProof::<Secp256k1>::create(t, w, private_key + d);

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
        let token = BatchedNizkpTokenEngine::<_, Secp256k1, 5>::generate(metadata);

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
        let token = BatchedNizkpTokenEngine::<_, Secp256k1, 5>::generate(metadata);

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
        let token = BatchedNizkpTokenEngine::<_, Secp256k1, 5>::generate(metadata);

        let signed = BatchedNizkpTokenEngine::sign(token, &public_key, |randomized| {
            BatchedNizkpTokenEngine::sign_randomized(randomized, &private)
        })
        .unwrap();

        let bad = PrivateKey::new();

        assert!(!signed.verify(&bad));
    }
}

// }}}
