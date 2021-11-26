//! Common traits and functions used in the protocols

use core::{convert::TryInto, iter::repeat_with};

use alloc::{boxed::Box, vec::Vec};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use subtle::CtOption;

/// Fill some bytes with random data
///
/// Uses thread_rng, wich in turn uses the chacha20 cipher as a random byte stream, seeded from the osrng
pub fn fill_bytes<R: CryptoRng + RngCore>(rng: &mut R, mut bytes: impl AsMut<[u8]>) {
    bytes.as_mut().iter_mut().for_each(|byte| *byte = rng.gen());
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// The identifier for the tokens
///
/// This identifier may have two states:
/// It may only be a random id, or it may be a random id with some additional hidden public metadata
/// It is hidden from the signer, but not from the verifier.
pub enum TokenIdentifier<T: AsRef<[u8]>> {
    Id([u8; 16]),
    WithHidden([u8; 16], T),
}

impl<T: AsRef<[u8]>> Into<[u8; 16]> for &TokenIdentifier<T> {
    fn into(self) -> [u8; 16] {
        let mut arr = [0u8; 16];
        match self {
            TokenIdentifier::Id(t) => {
                for (src, dst) in t.iter().zip(arr.iter_mut()) {
                    *dst = *src;
                }
            }
            TokenIdentifier::WithHidden(t, data) => {
                let mut hasher = Sha512::new();

                // Domain separation of random oracles
                hasher.update(b"Domain of hidden metadata");

                hasher.update(data);
                hasher.update(t);
                // this will take the first 16 bytes of the hash, but this is ok from the
                // specification. See [SHS](https://doi.org/10.6028/NIST.FIPS.180-4), section 7.
                for (dst, src) in arr.iter_mut().zip(hasher.finalize().iter()) {
                    *dst = *src;
                }
            }
        }

        arr
    }
}

impl<T: AsRef<[u8]>> TokenIdentifier<T> {
    /// Create a new random token identifier
    pub fn new() -> Self {
        let mut t = [0; 16];
        fill_bytes(&mut rand::thread_rng(), &mut t);

        Self::Id(t)
    }

    /// Create a new random token identifier with some hidden public metadata
    pub fn with_hidden(hidden: T) -> Self {
        let mut t = [0; 16];
        fill_bytes(&mut rand::thread_rng(), &mut t);

        Self::WithHidden(t, hidden)
    }

    pub fn generate<const N: usize>() -> [Self; N] {
        repeat_with(|| Self::new())
            .take(N)
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap()
    }
}

impl<T: AsRef<[u8]>> PartialEq for TokenIdentifier<T> {
    fn eq(&self, other: &Self) -> bool {
        let lhs: [u8; 16] = self.into();
        let rhs: [u8; 16] = other.into();
        // i think this should be a constant time comparison thingy
        lhs.iter().zip(rhs).fold(true, |s, (l, r)| l ^ r == 0 && s)
    }
}

/// An unsigned token is a token that is not signed.
/// This token consists of the token identifier and the metadata.
/// SInce this contains the token identifier, this should not be shared directly (that would be
/// loss of anonymity). If the token identifier is turned into a curve point, this curve point
/// could be shared.
pub trait UnsignedToken {
    /// The metadata connected to the token.
    type Metadata;

    /// Metadata connected to the token that is hidden from the signer
    type HiddenMetadata;

    /// Create a new unsigned token
    fn new(metadata: Self::Metadata) -> Self;

    /// create a new unsigned token with hidden metadata
    fn with_hidden(metadata: Self::Metadata, hidden: Self::HiddenMetadata) -> Self;
}

/// This is a signed token.
/// It contains the token identification, metadata and a signature point.
pub trait SignedToken {
    type VerificationKey;

    fn verify(&self, verification_key: &Self::VerificationKey) -> bool;
}

/// A randomized unsigned token contains the blinded curve point of the token and the metadata.
/// This is safe to transfer without loss of anonymity.
pub trait RandomizedUnsignedToken {
    fn metadata(&self) -> Box<[u8]>;
}

/// The token engine is the glue of the types.
///
/// Creating a signed token is split up into 4 parts; randomize, (create signature), verify
/// signature and personalize.
///
/// ```
///     # use atpmd::TokenEngine as TE;
///     # use atpmd::atpm_pairing::{
///     #    keys::{PrivateKey as SignKey, PublicKey as UserVerification},
///     #    tokens::PairingTokenEngine as TokenEngine,
///     # };
///     // generate a new token
///     let unsigned_token = TokenEngine::generate(b"meatadata");
///
///     // Randomize token.
///     // A random scalar is generated and multiplied with the ec point
///     let (r, randomized_unsigned_token) = TokenEngine::randomize(&unsigned_token);
///
///     # let sign_key = SignKey::new();
///     # let public_key = UserVerification::from(&sign_key);
///     // sign token
///     let randomized_signed_token = TokenEngine::sign_randomized(
///         &randomized_unsigned_token,
///         &sign_key
///     ).unwrap();
///
///     // Remove randomization and verify the signature
///     let signed_token = TokenEngine::verify_signature_and_unrandomize(
///         unsigned_token,
///         randomized_unsigned_token,
///         randomized_signed_token,
///         &public_key,
///         r
///     ).unwrap();
///
///     # let verification_key = public_key;
///     // verifier verifies the signature
///     assert!(TokenEngine::verify(&signed_token, &verification_key))
/// ```
///
/// See examples for usage.
pub trait TokenEngine {
    /// An unsigned token
    type UnsignedToken: UnsignedToken;

    /// An anonymous unsigned token
    type RandomizedUnsignedToken: RandomizedUnsignedToken;

    /// A signed token that is anonymous
    type RandomizedSignedToken;

    /// A signed token
    type SignedToken: SignedToken;

    /// This is the randomization data.
    /// If the signer gets this information, he might be able to identify the user.
    type Randomization;

    /// The key the user uses to verify the validity of a signed token
    type UserVerification: From<Self::SignKey>;
    /// The key the signer uses to sign a token
    type SignKey: Default + Clone;

    /// Generate a new unsigned token
    fn generate(
        metadata: <Self::UnsignedToken as UnsignedToken>::Metadata,
    ) -> Self::UnsignedToken {
        UnsignedToken::new(metadata)
    }

    /// Generate a new unsigned token with hidden metadata
    fn generate_with_hidden(
        metadata: <Self::UnsignedToken as UnsignedToken>::Metadata,
        hidden: <Self::UnsignedToken as UnsignedToken>::HiddenMetadata,
    ) -> Self::UnsignedToken {
        UnsignedToken::with_hidden(metadata, hidden)
    }

    /// Randomize an unsigned token
    fn randomize(
        unsigned_token: &Self::UnsignedToken,
    ) -> (Self::Randomization, Self::RandomizedUnsignedToken);

    /// Sign a randomized unsigned token
    fn sign_randomized(
        randomized_unsigned: &Self::RandomizedUnsignedToken,
        sign_key: &Self::SignKey,
    ) -> CtOption<Self::RandomizedSignedToken>;

    /// Verify that the signature is a valid signature, and remove the randomization
    fn verify_signature_and_unrandomize(
        unsigned_token: Self::UnsignedToken,
        randomized_unsigned: Self::RandomizedUnsignedToken,
        signed_token: Self::RandomizedSignedToken,
        verification_data: &Self::UserVerification,
        randomization: Self::Randomization,
    ) -> Option<Self::SignedToken>;

    /// Sign a token
    ///
    /// This is not a constant time implementation
    fn sign<F>(
        unsigned_token: Self::UnsignedToken,
        verification_data: &Self::UserVerification,
        sign_func: F,
    ) -> Option<Self::SignedToken>
    where
        F: Fn(&Self::RandomizedUnsignedToken) -> CtOption<Self::RandomizedSignedToken>,
    {
        let (r, randomized_unsigned) = Self::randomize(&unsigned_token);

        // use the sign_func as an oracle to get a CtOption<RandomizedSignedToken>
        let randomized_signed = sign_func(&randomized_unsigned);

        if bool::from(randomized_signed.is_none()) {
            return None;
        }

        Self::verify_signature_and_unrandomize(
            unsigned_token,
            randomized_unsigned,
            randomized_signed.unwrap(),
            verification_data,
            r,
        )
    }

    /// Verify a token
    fn verify(
        token: &Self::SignedToken,
        verification_key: &<Self::SignedToken as SignedToken>::VerificationKey,
    ) -> bool {
        token.verify(verification_key)
    }
}

#[cfg(test)]
mod tests {
    use super::fill_bytes;
    #[test]
    fn fill_bytes_test() {
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        let mut rng = rand::thread_rng();
        fill_bytes(&mut rng, &mut b1);
        fill_bytes(&mut rng, &mut b2);
        // probability of a collision is really small (2^{-256})
        assert_ne!(b1, b2);
    }
}
