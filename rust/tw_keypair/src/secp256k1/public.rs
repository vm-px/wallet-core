// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

use crate::secp256k1::signature::VerifySignature;
use crate::secp256k1::EcdsaCurve;
use crate::traits::VerifyingKeyTrait;
use crate::KeyPairError;
use ecdsa::elliptic_curve::AffinePoint;
use ecdsa::hazmat::VerifyPrimitive;
use ecdsa::signature::hazmat::PrehashVerifier;
use ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tw_encoding::hex;
use tw_hash::{H256, H264, H520};
use tw_misc::traits::ToBytesVec;

/// Represents a `secp256k1` public key.
pub struct PublicKey<C>
where
    C: EcdsaCurve,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    pub(crate) public: VerifyingKey<C>,
}

/// cbindgen:ignore
impl<C> PublicKey<C>
where
    C: EcdsaCurve,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    /// The number of bytes in a compressed public key.
    pub const COMPRESSED: usize = H264::len();
    /// The number of bytes in an uncompressed public key.
    pub const UNCOMPRESSED: usize = H520::len();

    /// Creates a public key from the given [`VerifyingKey`].
    pub(crate) fn new(public: VerifyingKey<C>) -> PublicKey<C> {
        PublicKey { public }
    }

    /// Returns the raw data of the compressed public key (33 bytes).
    pub fn compressed(&self) -> H264 {
        let compressed = true;
        H264::try_from(self.public.to_encoded_point(compressed).as_bytes())
            .expect("Expected 33 byte array Public Key")
    }

    /// Returns the raw data of the uncompressed public key (65 bytes).
    pub fn uncompressed(&self) -> H520 {
        let compressed = false;
        H520::try_from(self.public.to_encoded_point(compressed).as_bytes())
            .expect("Expected 65 byte array Public Key")
    }
}

impl<C> VerifyingKeyTrait for PublicKey<C>
where
    C: EcdsaCurve,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type SigningMessage = H256;
    type VerifySignature = VerifySignature<C>;

    fn verify(&self, sign: Self::VerifySignature, message: Self::SigningMessage) -> bool {
        self.public
            .verify_prehash(message.as_slice(), &sign.signature)
            .is_ok()
    }
}

impl<'a, C> TryFrom<&'a str> for PublicKey<C>
where
    C: EcdsaCurve,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Error = KeyPairError;

    fn try_from(hex: &'a str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(hex).map_err(|_| KeyPairError::InvalidPublicKey)?;
        Self::try_from(bytes.as_slice())
    }
}

impl<'a, C> TryFrom<&'a [u8]> for PublicKey<C>
where
    C: EcdsaCurve,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Error = KeyPairError;

    /// Expected either `H264` or `H520` slice.
    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(PublicKey {
            public: VerifyingKey::from_sec1_bytes(data)
                .map_err(|_| KeyPairError::InvalidPublicKey)?,
        })
    }
}

/// Return the compressed bytes representation by default.
/// Consider using [`PublicKey::compressed`] or [`PublicKey::uncompressed`] instead.
impl<C> ToBytesVec for PublicKey<C>
where
    C: EcdsaCurve,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn to_vec(&self) -> Vec<u8> {
        self.compressed().to_vec()
    }
}
