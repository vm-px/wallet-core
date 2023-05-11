// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

use crate::secp256k1::private::PrivateKey;
use crate::secp256k1::public::PublicKey;
use crate::secp256k1::signature::{Signature, VerifySignature};
use crate::secp256k1::EcdsaCurve;
use crate::traits::{KeyPairTrait, SigningKeyTrait, VerifyingKeyTrait};
use crate::{KeyPairError, KeyPairResult};
use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use ecdsa::elliptic_curve::{AffinePoint, Scalar};
use ecdsa::hazmat::{SignPrimitive, VerifyPrimitive};
use tw_encoding::hex;
use tw_hash::H256;
use zeroize::Zeroizing;

/// Represents a pair of `secp256k1` private and public keys.
pub struct KeyPair<C>
where
    C: EcdsaCurve,
    Scalar<C>: SignPrimitive<C>,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    private: PrivateKey<C>,
    public: PublicKey<C>,
}

impl<C> KeyPairTrait for KeyPair<C>
where
    C: EcdsaCurve,
    Scalar<C>: SignPrimitive<C>,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Private = PrivateKey<C>;
    type Public = PublicKey<C>;

    fn public(&self) -> &Self::Public {
        &self.public
    }

    fn private(&self) -> &Self::Private {
        &self.private
    }
}

impl<C> SigningKeyTrait for KeyPair<C>
where
    C: EcdsaCurve,
    Scalar<C>: SignPrimitive<C>,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type SigningMessage = H256;
    type Signature = Signature<C>;

    fn sign(&self, message: Self::SigningMessage) -> KeyPairResult<Self::Signature> {
        self.private.sign(message)
    }
}

impl<C> VerifyingKeyTrait for KeyPair<C>
where
    C: EcdsaCurve,
    Scalar<C>: SignPrimitive<C>,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type SigningMessage = H256;
    type VerifySignature = VerifySignature<C>;

    fn verify(&self, signature: Self::VerifySignature, message: Self::SigningMessage) -> bool {
        self.public.verify(signature, message)
    }
}

impl<'a, C> TryFrom<&'a [u8]> for KeyPair<C>
where
    C: EcdsaCurve,
    Scalar<C>: SignPrimitive<C>,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Error = KeyPairError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let private = PrivateKey::try_from(bytes)?;
        let public = private.public();
        Ok(KeyPair { private, public })
    }
}

impl<'a, C> TryFrom<&'a str> for KeyPair<C>
where
    C: EcdsaCurve,
    Scalar<C>: SignPrimitive<C>,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Error = KeyPairError;

    fn try_from(hex: &'a str) -> Result<Self, Self::Error> {
        let bytes = Zeroizing::new(hex::decode(hex).map_err(|_| KeyPairError::InvalidSecretKey)?);
        Self::try_from(bytes.as_slice())
    }
}
