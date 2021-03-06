use crate::utilities::mta::*;
use curv::elliptic::curves::{Scalar, Secp256k1};
use paillier::traits::KeyGeneration;

#[test]
fn test_mta() {
    let alice_input = Scalar::<Secp256k1>::random();
    let (ek_alice, dk_alice) = Paillier::keypair().keys();
    let bob_input = Scalar::<Secp256k1>::random();
    let (m_a, _r) = MessageA::a(&alice_input, &ek_alice);
    let (m_b, beta, _, _) = MessageB::b(&bob_input, &ek_alice, m_a);
    let alpha = m_b
        .verify_proofs_get_alpha(&dk_alice, &alice_input)
        .expect("wrong dlog or m_b");

    let left = alpha.0 + beta;
    let right = alice_input * bob_input;
    assert_eq!(left, right);
}
