use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

#[derive(Copy, Clone)]
pub enum Card {
    Skull,
    Rose,
}

impl Card {
    fn to_scalar(self) -> Scalar {
        match self {
            Card::Skull => Scalar::one(),
            Card::Rose => Scalar::zero(),
        }
    }
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

pub fn commit(gh: (RistrettoPoint, RistrettoPoint), c: Card) -> (Commitment, Revelation) {
    let (g, h) = gh;
    let r = Scalar::random(&mut OsRng);
    let commitment = Commitment(g * c.to_scalar() + r * h);
    (commitment, Revelation { r: r, c: c })
}

pub fn decommit(gh: (RistrettoPoint, RistrettoPoint), com: Commitment, rev: Revelation) -> bool {
    let (g, h) = gh;
    let (r, c) = (rev.r, rev.c);
    com.0 == Commitment(g * c.to_scalar() + r * h).0
}

pub fn commit_deck(
    gh: (RistrettoPoint, RistrettoPoint),
    d: &[Card],
) -> (Vec<Commitment>, Vec<Revelation>) {
    let mut coms = Vec::<Commitment>::with_capacity(d.len());
    let mut revs = Vec::<Revelation>::with_capacity(d.len());
    for (com, rev) in d.into_iter().map(|x| commit(gh, *x)) {
        revs.push(rev);
        coms.push(com);
    }
    (coms, revs)
}

pub const DEFAULT_DECK: [Card; 4] = [Card::Skull, Card::Rose, Card::Rose, Card::Rose];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_fair_deck() {
        let gh = init_gh();
        let (_g, h) = gh;
        let (coms, revs) = commit_deck(gh, &DEFAULT_DECK);
        for (&com, &rev) in coms.iter().zip(revs.iter()) {
            assert!(decommit(gh, com, rev));
        }
        let rs: Vec<Scalar> = revs.iter().map(|x| x.r).collect();
        let sig = schnorr_sign(h, &rs);
        assert!(check_schnorr_signature(gh, &coms, sig));
    }

    #[test]
    fn sign_cheat_deck() {
        const CHEAT_DECK: [Card; 4] = [Card::Skull, Card::Skull, Card::Rose, Card::Rose];
        let gh = init_gh();
        let (_g, h) = gh;
        let (coms, revs) = commit_deck(gh, &CHEAT_DECK);
        for (&com, &rev) in coms.iter().zip(revs.iter()) {
            assert!(decommit(gh, com, rev));
        }
        let rs: Vec<Scalar> = revs.iter().map(|x| x.r).collect();
        let sig = schnorr_sign(h, &rs);
        assert!(!check_schnorr_signature(gh, &coms, sig));
    }
}
