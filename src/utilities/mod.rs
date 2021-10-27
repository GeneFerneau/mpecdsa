pub mod mta;
pub mod zk_pdl_with_slack;

use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::BigInt;
use sha2::Sha256;

pub fn create_hash(big_ints: &[&BigInt]) -> BigInt {
    let mut hasher = Sha256::new();

    for value in big_ints {
        hasher = hasher.chain_bigint(value);
    }

    hasher.result_bigint()
}
