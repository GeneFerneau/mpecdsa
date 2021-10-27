/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

use std::ops::Sub;

/// MtA is descrbied in https://eprint.iacr.org/2019/114.pdf section 3
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use curv::BigInt;
use paillier::traits::EncryptWithChosenRandomness;
use paillier::{Add, Decrypt, Mul};
use paillier::{DecryptionKey, EncryptionKey, Paillier, Randomness, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::Error::{self, InvalidKey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageA {
    pub c: BigInt, // paillier encryption
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageB {
    pub c: BigInt, // paillier encryption
    pub b_proof: DLogProof<Secp256k1, Sha256>,
    pub beta_tag_proof: DLogProof<Secp256k1, Sha256>,
}

impl MessageA {
    pub fn a(a: &Scalar<Secp256k1>, alice_ek: &EncryptionKey) -> (Self, BigInt) {
        let randomness = BigInt::sample_below(&alice_ek.n);
        let c_a = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(a.to_bigint()),
            &Randomness::from(randomness.clone()),
        );
        (
            Self {
                c: c_a.0.clone().into_owned(),
            },
            randomness,
        )
    }

    pub fn a_with_predefined_randomness(
        a: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        randomness: &BigInt,
    ) -> Self {
        let c_a = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(a.to_bigint()),
            &Randomness::from(randomness.clone()),
        );

        Self {
            c: c_a.0.clone().into_owned(),
        }
    }
}

impl MessageB {
    pub fn b(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        c_a: MessageA,
    ) -> (Self, Scalar<Secp256k1>, BigInt, BigInt) {
        let beta_tag = BigInt::sample_below(&alice_ek.n);
        let beta_tag_fe: Scalar<Secp256k1> = Scalar::<Secp256k1>::from(&beta_tag);
        let randomness = BigInt::sample_below(&alice_ek.n);
        let c_beta_tag = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(beta_tag.clone()),
            &Randomness::from(randomness.clone()),
        );

        let b_bn = b.to_bigint();
        let b_c_a = Paillier::mul(
            alice_ek,
            RawCiphertext::from(c_a.c),
            RawPlaintext::from(b_bn),
        );
        let c_b = Paillier::add(alice_ek, b_c_a, c_beta_tag);
        let beta = Scalar::<Secp256k1>::zero() - &beta_tag_fe;
        let dlog_proof_b = DLogProof::prove(b);
        let dlog_proof_beta_tag = DLogProof::prove(&beta_tag_fe);

        (
            Self {
                c: c_b.0.clone().into_owned(),
                b_proof: dlog_proof_b,
                beta_tag_proof: dlog_proof_beta_tag,
            },
            beta,
            randomness,
            beta_tag,
        )
    }

    pub fn b_with_predefined_randomness(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        c_a: MessageA,
        randomness: &BigInt,
        beta_tag: &BigInt,
    ) -> (Self, Scalar<Secp256k1>) {
        let beta_tag_fe: Scalar<Secp256k1> = Scalar::<Secp256k1>::from(beta_tag);
        let c_beta_tag = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(beta_tag),
            &Randomness::from(randomness.clone()),
        );

        let b_bn = b.to_bigint();
        let b_c_a = Paillier::mul(
            alice_ek,
            RawCiphertext::from(c_a.c),
            RawPlaintext::from(b_bn),
        );
        let c_b = Paillier::add(alice_ek, b_c_a, c_beta_tag);
        let beta = Scalar::<Secp256k1>::zero().sub(&beta_tag_fe);
        let dlog_proof_b = DLogProof::prove(b);
        let dlog_proof_beta_tag = DLogProof::prove(&beta_tag_fe);

        (
            Self {
                c: c_b.0.clone().into_owned(),
                b_proof: dlog_proof_b,
                beta_tag_proof: dlog_proof_beta_tag,
            },
            beta,
        )
    }

    pub fn verify_proofs_get_alpha(
        &self,
        dk: &DecryptionKey,
        a: &Scalar<Secp256k1>,
    ) -> Result<(Scalar<Secp256k1>, BigInt), Error> {
        let alice_share = Paillier::decrypt(dk, &RawCiphertext::from(self.c.clone()));
        let g = Point::<Secp256k1>::generator().to_point();
        let alpha = Scalar::<Secp256k1>::from(alice_share.0.clone().into_owned());
        let g_alpha = &g * &alpha;
        let ba_btag = &self.b_proof.pk * a + &self.beta_tag_proof.pk;
        if DLogProof::verify(&self.b_proof).is_ok()
            && DLogProof::verify(&self.beta_tag_proof).is_ok()
            // we prove the correctness of the ciphertext using this check and the proof of knowledge of dlog of beta_tag
            && ba_btag == g_alpha
        {
            Ok((alpha, alice_share.0.into_owned()))
        } else {
            Err(InvalidKey)
        }
    }
}

#[cfg(test)]
mod test;
