use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use merlin::Transcript;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

#[derive(Copy, Clone)]
pub enum Card {
    Skull,
    Rose,
}

#[derive(Copy, Clone)]
pub struct Revelation {
    pub r: Scalar,
    c: Card,
}

#[derive(Copy, Clone)]
pub struct Commitment(RistrettoPoint);

pub struct SchnorrSignature {
    s: Scalar,
    e: Scalar,
}

pub fn init_gh() -> (RistrettoPoint, RistrettoPoint) {
    (
        RistrettoPoint::hash_from_bytes::<Sha512>("AMONI".as_bytes()),
        RistrettoPoint::hash_from_bytes::<Sha512>("SAGOD".as_bytes()),
    )
}

pub fn schnorr_sign(h: RistrettoPoint, rs: &[Scalar]) -> SchnorrSignature {
    let tail = &rs[1..];
    let key = tail.into_iter().fold(rs[0], |acc, x| acc + x);
    let k = Scalar::random(&mut OsRng);
    let hasher = Sha512::new().chain((h * k).compress().as_bytes());
    let e = Scalar::from_hash(hasher);
    SchnorrSignature {
        s: k - key * e,
        e: e,
    }
}

pub fn check_schnorr_signature(
    gh: (RistrettoPoint, RistrettoPoint),
    cs: &[Commitment],
    sig: SchnorrSignature,
) -> bool {
    let (g, h) = gh;
    let tail = &cs[1..];
    let y = tail.into_iter().fold(cs[0].0, |acc, x| acc + x.0) - g;
    let r = h * sig.s + y * sig.e;
    let hasher = Sha512::new().chain(r.compress().as_bytes());
    Scalar::from_hash(hasher) == sig.e
}



pub const DEFAULT_DECK: [Card; 4] = [Card::Skull, Card::Rose, Card::Rose, Card::Rose];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulletproof() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(8, 1);
        let secret = 0u64;
        let blinding = Scalar::random(&mut OsRng);

        let mut prover_transcript = Transcript::new(b"doctest example");
        let (proof, committed_value) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            secret,
            &blinding,
            8,
        )
        .expect("oopsie");
        let mut verifier_transcript = Transcript::new(b"doctest example");
        assert!(proof
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut verifier_transcript,
                &committed_value,
                8,
            )
            .is_ok());
        assert!(pc_gens.commit(Scalar::zero(), blinding).compress() == committed_value); 
    }
}
