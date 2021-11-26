use alloc::boxed::Box;
use core::marker::PhantomData;

use super::{
    keys::{PrivateKey, PublicKey},
    util::gen_vartime,
    SignedToken, TokenEngine, TokenIdentifier, UnsignedToken,
};

use elliptic_curve::{
    group::{Curve as Cur, GroupEncoding},
    ops::Invert,
    AffineArithmetic, AffinePoint, Curve, Group, ProjectiveArithmetic, ProjectivePoint, Scalar,
    ScalarArithmetic,
};

use sha2::{Digest, Sha256};
use subtle::CtOption;

use super::util::{h_t, hash_to_scalar};

// {{{ DLEQProof

#[derive(Clone)]
struct DLEQProof<C: Curve + ScalarArithmetic> {
    c: Scalar<C>,
    z: Scalar<C>,
}

impl<C: Curve + AffineArithmetic + ProjectiveArithmetic> DLEQProof<C>
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

        // domain of the oracle, to have separate oracles
        hasher.update(b"This is DLEQ_PROOF hash");

        hasher.update(GroupEncoding::to_bytes(
            &ProjectivePoint::<C>::generator().to_affine(),
        ));
        hasher.update(GroupEncoding::to_bytes(&u));
        hasher.update(GroupEncoding::to_bytes(&t));
        hasher.update(GroupEncoding::to_bytes(&w));
        hasher.update(GroupEncoding::to_bytes(&a));
        hasher.update(GroupEncoding::to_bytes(&b));

        // Turn the bytes uniformly and deterministically into a scalar
        hash_to_scalar::<C, _>(&hasher.finalize())
    }

    /// Create a proof of the fact that log_w t = k
    ///
    /// If you create w=(d+k)^{-1} t, then create this proof with create(t, w, d + k)
    pub fn create(t: AffinePoint<C>, w: AffinePoint<C>, k: Scalar<C>) -> Self {
        let r: Scalar<C> = gen_vartime::<C, _>(&mut rand::thread_rng());
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

// }}}

// {{{ UnsignedToken

pub struct NizkpUnsignedToken<M: AsRef<[u8]>, C: Curve> {
    id: TokenIdentifier<M>,
    metadata: M,
    _c: PhantomData<C>,
}

impl<M: AsRef<[u8]>, C: Curve + AffineArithmetic> NizkpUnsignedToken<M, C> {
    pub fn get_point(&self) -> AffinePoint<C> {
        let t: [u8; 16] = (&self.id).into();

        h_t::<C, _, _>(t, &self.metadata)
    }
}

impl<M: AsRef<[u8]>, C: Curve> UnsignedToken for NizkpUnsignedToken<M, C> {
    type Metadata = M;
    type HiddenMetadata = M;

    fn new(metadata: Self::Metadata) -> Self {
        Self {
            id: TokenIdentifier::new(),
            metadata,
            _c: PhantomData {},
        }
    }

    fn with_hidden(metadata: Self::Metadata, hidden: Self::HiddenMetadata) -> Self {
        Self {
            id: TokenIdentifier::with_hidden(hidden),
            metadata,
            _c: PhantomData {},
        }
    }
}

// }}}

// {{{   Randomized signed

pub struct RandomizedSignedToken<M: AsRef<[u8]>, C: Curve + AffineArithmetic> {
    point: AffinePoint<C>,
    proof: DLEQProof<C>,
    _m: PhantomData<M>,
}

// }}}

// {{{ randomized unsigned

pub struct RandomizedUnsignedToken<M: AsRef<[u8]>, C: Curve + AffineArithmetic> {
    point: AffinePoint<C>,
    metadata: Box<[u8]>,
    _m: PhantomData<M>,
}

impl<M: AsRef<[u8]>, C: Curve + AffineArithmetic> crate::common::RandomizedUnsignedToken
    for RandomizedUnsignedToken<M, C>
{
    fn metadata(&self) -> Box<[u8]> {
        self.metadata.clone()
    }
}

// }}}

// {{{ Signed token

pub struct NizkpSignedToken<M: AsRef<[u8]>, C>
where
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>>,
{
    id: TokenIdentifier<M>,
    metadata: M,
    point: AffinePoint<C>,
}

impl<M: AsRef<[u8]>, C> SignedToken for NizkpSignedToken<M, C>
where
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>>,
{
    type VerificationKey = PrivateKey<C>;

    fn verify(&self, verification_key: &Self::VerificationKey) -> bool {
        let t: [u8; 16] = (&self.id).into();
        let t: AffinePoint<C> = h_t::<C, _, _>(t, &self.metadata);

        // We may do this, since
        // w == e * t is the same as e^-1 w == t
        // We then do not need to do the inversion step, and maybe it could be easier to build
        // batch verification
        let e_inverse: Scalar<C> =
            hash_to_scalar::<C, _>(&self.metadata) + verification_key.to_scalar();

        let signed: ProjectivePoint<C> = ProjectivePoint::<C>::from(self.point) * e_inverse;

        signed == ProjectivePoint::<C>::from(t)
    }
}

// }}}

// {{{ Token engine

pub struct NizkpTokenEngine<M: AsRef<[u8]>, C>
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: GroupEncoding,
    Scalar<C>: Invert<Output = Scalar<C>>,
{
    _m: PhantomData<M>,
    _c: PhantomData<C>,
}

impl<M: AsRef<[u8]>, C> TokenEngine for NizkpTokenEngine<M, C>
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: GroupEncoding,
    Scalar<C>: Invert<Output = Scalar<C>>,
{
    type UnsignedToken = NizkpUnsignedToken<M, C>;
    type RandomizedUnsignedToken = RandomizedUnsignedToken<M, C>;
    type RandomizedSignedToken = RandomizedSignedToken<M, C>;
    type SignedToken = NizkpSignedToken<M, C>;
    type Randomization = Scalar<C>;
    type UserVerification = PublicKey<C>;
    type SignKey = PrivateKey<C>;

    //For batched tokens we generate a seed for an rng to reduce memory usage. It had to be verified that all scalars are invertible
    fn randomize(
        unsigned_token: &Self::UnsignedToken,
    ) -> (Self::Randomization, Self::RandomizedUnsignedToken) {
        let r = gen_vartime::<C, _>(&mut rand::thread_rng());
        let inverse = r.invert().unwrap();
        (
            r,
            Self::RandomizedUnsignedToken {
                point: (ProjectivePoint::<C>::from(unsigned_token.get_point()) * inverse)
                    .to_affine(),
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
        let u: ProjectivePoint<C> = ProjectivePoint::<C>::generator()
            * hash_to_scalar::<C, _>(&unsigned_token.metadata)
            + verification_data.to_affine();

        // verify proof
        if signed_token.proof.verify(
            randomized_unsigned_token.point,
            signed_token.point,
            u.to_affine(),
        ) {
            // Remove randomization
            Some(Self::SignedToken {
                point: (ProjectivePoint::<C>::from(signed_token.point) * randomization)
                    .to_affine(),
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
        let d = hash_to_scalar::<C, _>(&t_prime.metadata);
        (d + sign_key.to_scalar())
            .invert()
            .map(|e| (ProjectivePoint::<C>::from(t_prime.point) * e).to_affine())
            .map(|w| Self::RandomizedSignedToken {
                point: w,
                proof: DLEQProof::create(t_prime.point, w, d + sign_key.to_scalar()),
                _m: PhantomData {},
            })
    }
}

// }}}

// {{{ tests

#[cfg(test)]
mod tests {
    use elliptic_curve::group::prime::PrimeCurveAffine;

    use super::super::keys::{PrivateKey, PublicKey};
    use super::*;

    use k256::{AffinePoint, ProjectivePoint, Scalar, Secp256k1};

    #[test]
    fn test_proof() {
        // setup
        let mut rng = rand::thread_rng();

        // create keys
        let private_key: Scalar = Scalar::generate_biased(&mut rng);
        let public_key: AffinePoint = (AffinePoint::generator() * private_key).to_affine();

        // token metadata
        let metadata = b"kake";
        let d: Scalar = hash_to_scalar::<Secp256k1, _>(metadata);

        // create token
        let t =
            (ProjectivePoint::generator() * (Scalar::generate_biased(&mut rng) + d)).to_affine();

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
        let private = PrivateKey::<Secp256k1>::new();
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
        let private = PrivateKey::<Secp256k1>::new();
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
        let private = PrivateKey::<Secp256k1>::new();
        let public_key = PublicKey::from(&private);

        // generate a new token
        let metadata = b"This is my metadata";
        let token = NizkpTokenEngine::generate(metadata);

        let bad = PrivateKey::<Secp256k1>::new();

        let signed = NizkpTokenEngine::sign(token, &public_key, |randomized| {
            NizkpTokenEngine::sign_randomized(randomized, &bad)
        });

        assert!(signed.is_none());
    }

    #[test]
    fn fail_bad_verification_key() {
        // generate keys
        let private = PrivateKey::<Secp256k1>::new();
        let public_key = PublicKey::from(&private);

        // generate a new token
        let metadata = b"This is my metadata";
        let token = NizkpTokenEngine::generate(metadata);

        let signed = NizkpTokenEngine::sign(token, &public_key, |randomized| {
            NizkpTokenEngine::sign_randomized(randomized, &private)
        })
        .unwrap();

        let bad = PrivateKey::<Secp256k1>::new();

        assert!(!signed.verify(&bad));
    }
}

// }}}
