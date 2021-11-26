use core::{convert::TryInto, iter::repeat_with, marker::PhantomData};

use alloc::{boxed::Box, vec::Vec};
use bls12_381::{Bls12, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use pairing::Engine;
use rand::{prelude::StdRng, SeedableRng};
// use serde::{Deserialize, Serialize};

use crate::{
    atpm_pairing::util::random_vartime, common::fill_bytes, RandomizedUnsignedToken, SignedToken,
    TokenEngine, UnsignedToken,
};

use super::{
    keys::{PrivateKey, PublicKey},
    tokens::PairingSignedToken,
    util::{h_1, h_m, random_biased, CurvePoint},
    TokenIdentifier,
};

// {{{ Unsigned token

// #[derive(Serialize, Deserialize)]
pub struct BatchedPairingUnsignedToken<M: AsRef<[u8]>, const N: usize> {
    ids: [TokenIdentifier<M>; N],
    metadata: M,
}

impl<M: AsRef<[u8]>, const N: usize> UnsignedToken for BatchedPairingUnsignedToken<M, N> {
    type HiddenMetadata = M;
    type Metadata = M;

    fn new(metadata: Self::Metadata) -> Self {
        Self {
            ids: TokenIdentifier::generate(),
            metadata,
        }
    }

    /// This is unimplemented, since there is some trouble that the hidden metadata is used in
    /// several tokenidentifiers
    fn with_hidden(_metadata: Self::Metadata, _hidden: Self::HiddenMetadata) -> Self {
        todo!()
        // Self {
        //     ids: repeat_with(move || TokenIdentifier::with_hidden(&hidden))
        //         .take(N)
        //         .collect::<Vec<_>>()
        //         .try_into()
        //         .ok()
        //         .unwrap(),
        //     metadata,
        // }
    }
}

// }}}

// {{{ Randomized unsigned

pub struct BatchedRandomizedUnsignedToken<M, const N: usize> {
    points: [CurvePoint; N],
    metadata: Box<[u8]>,
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>, const N: usize> RandomizedUnsignedToken
    for BatchedRandomizedUnsignedToken<M, N>
{
    fn metadata(&self) -> Box<[u8]> {
        self.metadata.clone()
    }
}

// }}}

// {{{ Randomized Signed token

pub struct BatchedRandomizedSignedToken<M, const N: usize> {
    points: [CurvePoint; N],
    // metadata: Box<[u8]>,
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>, const N: usize> Default for BatchedRandomizedSignedToken<M, N> {
    fn default() -> Self {
        Self {
            points: repeat_with(|| CurvePoint::from(G1Affine::identity()))
                .take(N)
                .collect::<Vec<_>>()
                .try_into()
                .ok()
                .unwrap(),
            // metadata: Box::from([]),
            _m: PhantomData {},
        }
    }
}

// }}}

// {{{ Signed token

pub struct BatchedPairingSignedToken<M: AsRef<[u8]>, const N: usize> {
    ids: [TokenIdentifier<M>; N],
    metadata: M,
    signatures: [CurvePoint; N],
}

impl<M: AsRef<[u8]>, const N: usize> BatchedPairingSignedToken<M, N> {
    pub fn iter<'a>(&'a self) -> BatchedPairingSignedTokenIterator<'a, M, N> {
        BatchedPairingSignedTokenIterator {
            tokens: self,
            place: 0,
        }
    }
}

impl<M: AsRef<[u8]> + core::fmt::Debug, const N: usize> From<[PairingSignedToken<M>; N]>
    for BatchedPairingSignedToken<M, N>
{
    fn from(tokens: [PairingSignedToken<M>; N]) -> Self {
        let (ids, signatures, metadata) = IntoIterator::into_iter(tokens).fold(
            (Vec::new(), Vec::new(), None),
            |(mut ids, mut signs, _metadata), s| {
                let (id, point, metadata) = s.unpack();
                ids.push(id);
                signs.push(point);
                (ids, signs, Some(metadata))
            },
        );

        // Is ok to unwrap, since there are exactly N elements in array
        Self {
            ids: ids.try_into().unwrap(),
            signatures: signatures.try_into().unwrap(),
            metadata: metadata.unwrap(),
        }
    }
}

impl<M: AsRef<[u8]>, const N: usize> SignedToken for BatchedPairingSignedToken<M, N> {
    type VerificationKey = PublicKey;

    fn verify(&self, verification_key: &Self::VerificationKey) -> bool {
        let mut rng = rand::thread_rng();

        let (t, w) = self
            .ids
            .iter()
            .zip(self.signatures.iter())
            .zip(core::iter::repeat_with(|| random_biased(&mut rng))) // may use biased, since it only needs to be unpredictable
            .fold(
                (G1Projective::identity(), G1Projective::identity()),
                |(tsum, wsum), ((id, w), r)| {
                    let t: [u8; 16] = id.into();
                    (
                        tsum + h_1(t, &self.metadata) * r,
                        wsum + G1Affine::from(w) * r,
                    )
                },
            );

        // get the public key and other useful points on the curve
        let pk = G2Affine::from(verification_key);
        let u = (G2Affine::generator() * h_m(&self.metadata) + pk).into();

        // Verify that the signature is from the provided public key
        Bls12::pairing(&G1Affine::from(w), &u)
            == Bls12::pairing(&G1Affine::from(t), &G2Affine::generator())
    }
}

#[allow(unused)]
fn verify_no_lin_comb<M: AsRef<[u8]>, const N: usize>(
    token: &BatchedPairingSignedToken<M, N>,
    key: &PublicKey,
) -> bool {
    let (t, w) = token
        .ids
        .iter()
        .zip(token.signatures.iter())
        // .zip(core::iter::repeat_with(|| Scalar::one())) // may use biased, since it only needs to be unpredictable
        .fold(
            (G1Projective::identity(), G1Projective::identity()),
            |(tsum, wsum), (id, w)| {
                let t: [u8; 16] = id.into();
                (tsum + h_1(t, &token.metadata), wsum + G1Affine::from(w))
            },
        );

    // get the public key and other useful points on the curve
    let pk = G2Affine::from(key);
    let u = (G2Affine::generator() * h_m(&token.metadata) + pk).into();

    // Verify that the signature is from the provided public key
    Bls12::pairing(&G1Affine::from(&w), &u)
        == Bls12::pairing(&G1Affine::from(&t), &G2Affine::generator())
}

pub struct BatchedPairingSignedTokenIterator<'a, M: AsRef<[u8]>, const N: usize> {
    tokens: &'a BatchedPairingSignedToken<M, N>,
    place: usize,
}

impl<'a, M: AsRef<[u8]> + Clone, const N: usize> Iterator
    for BatchedPairingSignedTokenIterator<'a, M, N>
{
    type Item = PairingSignedToken<M>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.place < N {
            let token = PairingSignedToken::create(
                self.tokens.ids[self.place].clone(),
                self.tokens.signatures[self.place].clone(),
                self.tokens.metadata.clone(),
            );
            self.place += 1;
            Some(token)
        } else {
            None
        }
    }
}

// }}}

// {{{ Token engine

pub struct BatchedPairingTokenEngine<M: AsRef<[u8]> + Clone, const N: usize> {
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]> + Clone, const N: usize> TokenEngine for BatchedPairingTokenEngine<M, N> {
    type UnsignedToken = BatchedPairingUnsignedToken<M, N>;
    type RandomizedUnsignedToken = BatchedRandomizedUnsignedToken<M, N>;
    type RandomizedSignedToken = BatchedRandomizedSignedToken<M, N>;
    type SignedToken = BatchedPairingSignedToken<M, N>;
    type Randomization = [u8; 32];

    type UserVerification = PublicKey;
    type SignKey = PrivateKey;

    fn randomize(
        unsigned_token: &Self::UnsignedToken,
    ) -> (Self::Randomization, Self::RandomizedUnsignedToken) {
        // create random seed
        let mut randomization = [0; 32];
        fill_bytes(&mut rand::thread_rng(), &mut randomization);

        // seed an rng for the series of r
        let mut rng = StdRng::from_seed(randomization);

        let nums = repeat_with(|| random_vartime(&mut rng)) // generate random r's
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
                BatchedRandomizedUnsignedToken {
                    points: nums
                        .unwrap()
                        .into_iter()
                        .zip(unsigned_token.ids.iter())
                        .map(|(r, id)| {
                            let t: [u8; 16] = id.into();
                            // T' = [r]T
                            h_1(t, &unsigned_token.metadata) * r
                        })
                        .map(|t| G1Affine::from(t).into())
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

    fn sign_randomized(
        randomized_unsigned: &Self::RandomizedUnsignedToken,
        sign_key: &Self::SignKey,
    ) -> subtle::CtOption<Self::RandomizedSignedToken> {
        // This should be a constant time implementation
        let d = h_m(&randomized_unsigned.metadata);
        let k: Scalar = <&PrivateKey>::into(sign_key);
        (d + k)
            .invert()
            .map(|inverse| BatchedRandomizedSignedToken {
                // metadata: randomized_unsigned.metadata.clone(),
                _m: PhantomData {},
                points: randomized_unsigned
                    .points
                    .iter()
                    .map(|point| G1Affine::from(point) * inverse)
                    .map(|w_prime| G1Affine::from(w_prime).into())
                    .collect::<Vec<_>>()
                    .try_into()
                    .ok()
                    .unwrap(),
            })
    }

    fn verify_signature_and_unrandomize(
        unsigned_token: Self::UnsignedToken,
        _randomized_unsigned: Self::RandomizedUnsignedToken,
        signed_token: Self::RandomizedSignedToken,
        verification_data: &Self::UserVerification,
        randomization: Self::Randomization,
    ) -> Option<Self::SignedToken> {
        // the public key point
        let pk: G2Affine = <&PublicKey>::into(verification_data);
        let u_point: G2Projective = G2Affine::generator() * h_m(&unsigned_token.metadata) + pk;

        // seed an rng for the series of r
        let mut rng = StdRng::from_seed(randomization);

        // remove randomization from w
        // this will in addition work as a random linear combination of the signatures to make sure
        // that the signer has not given a bad batch
        let signatures = repeat_with(|| random_vartime(&mut rng))
            .take(N)
            .zip(signed_token.points.iter())
            .map(|(r, w_prime)| G1Affine::from(w_prime) * r)
            .collect::<Vec<_>>();

        // sum the w's
        let w = signatures
            .iter()
            .fold(G1Projective::identity(), |s, w| s + w);

        // Sum the t's
        let t = unsigned_token
            .ids
            .iter()
            .map(|id| {
                let t: [u8; 16] = id.into();
                h_1(t, &unsigned_token.metadata)
            })
            .fold(G1Projective::identity(), |s, t| s + t);

        // Verify that the signature is correct
        if Bls12::pairing(&w.into(), &u_point.into())
            == Bls12::pairing(&G1Affine::from(t), &G2Affine::generator())
        {
            Some(BatchedPairingSignedToken {
                signatures: signatures
                    .iter()
                    .map(|w| G1Affine::from(w).into())
                    .collect::<Vec<_>>()
                    .try_into()
                    .ok()
                    .unwrap(),
                metadata: unsigned_token.metadata,
                ids: unsigned_token.ids,
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
    use crate::atpm_pairing::tokens::{PairingTokenEngine, RandomizedUnsignedToken};

    use super::*;

    #[test]
    fn test_all() {
        // generate keys
        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);

        // generate tokens
        let tokens = BatchedPairingTokenEngine::<_, 5>::generate(b"metadata");

        let signed = BatchedPairingTokenEngine::sign(tokens, &public_key, |tokens| {
            BatchedPairingTokenEngine::sign_randomized(tokens, &private_key)
        })
        .unwrap();

        assert!(BatchedPairingTokenEngine::verify(&signed, &public_key));

        for token in signed.iter() {
            assert!(PairingTokenEngine::verify(&token, &public_key));
        }
    }

    #[test]
    fn fail_bad_signkey() {
        // generate keys
        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);

        // generate tokens
        let tokens = BatchedPairingTokenEngine::<_, 5>::generate(b"metadata");

        // generate keys
        let wrong_private_key = PrivateKey::new();

        assert!(
            BatchedPairingTokenEngine::sign(tokens, &public_key, |tokens| {
                BatchedPairingTokenEngine::sign_randomized(tokens, &wrong_private_key)
            })
            .is_none()
        );
    }

    #[test]
    fn fail_bad_verify_key() {
        // generate keys
        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);

        // generate tokens
        let tokens = BatchedPairingTokenEngine::<_, 5>::generate(b"metadata");

        let signed = BatchedPairingTokenEngine::sign(tokens, &public_key, |tokens| {
            BatchedPairingTokenEngine::sign_randomized(tokens, &private_key)
        })
        .unwrap();

        let fake_private = PrivateKey::new();
        let fake_public = PublicKey::from(&fake_private);

        assert!(!BatchedPairingTokenEngine::verify(&signed, &fake_public));

        for token in signed.iter() {
            assert!(!PairingTokenEngine::verify(&token, &fake_public));
        }
    }

    #[test]
    fn attack_no_lincomb() {
        const N: usize = 50;

        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);

        let metadata = b"sample metadata";

        let (s, l) = core::iter::repeat_with(|| PairingTokenEngine::generate(metadata))
            .take(N)
            .fold((G1Projective::identity(), Vec::new()), |(s, mut l), t| {
                let point = G1Affine::from(&t);
                l.push(t);
                (s + point, l)
            });

        let mut rng = rand::thread_rng();

        let r = random_biased(&mut rng);

        let sum_t = G1Affine::from(s * r.invert().unwrap());

        let r_token = RandomizedUnsignedToken::new(sum_t, metadata);

        // sign one token
        let s_token = PairingTokenEngine::sign_randomized(&r_token, &private_key).unwrap();

        let w = G1Affine::from(&s_token) * r;

        let (s, mut a) = core::iter::repeat_with(|| {
            G1Affine::from(G1Affine::identity() * random_biased(&mut rng))
        })
        .take(N - 2)
        .fold(
            (G1Projective::identity(), Vec::new()),
            |(mut s, mut l), t| {
                s += t;
                l.push(t);
                (s, l)
            },
        );
        a.push(G1Affine::from(-s));

        let tokens: [PairingSignedToken<_>; N] = [G1Affine::from(w)]
            .iter()
            .chain(a.iter())
            .zip(l.into_iter())
            .map(|(w, t)| t.get_signed(CurvePoint::from(w)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let btoken = BatchedPairingSignedToken::<_, N>::from(tokens);

        assert!(!btoken.verify(&public_key));
        assert!(verify_no_lin_comb(&btoken, &public_key));
    }
}

// }}}
