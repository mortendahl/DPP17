#[macro_use]
extern crate bencher;
extern crate paillier;

use bencher::Bencher;
use paillier::*;

pub trait TestKeyGeneration
where
    Self : PartiallyHomomorphicScheme
{
    fn test_keypair() -> (Self::EncryptionKey, Self::DecryptionKey);
}

// 1024 bit primes
static P: &'static str = "148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517";
static Q: &'static str = "158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463";

impl TestKeyGeneration for PackedPaillier {
    fn test_keypair() -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        let ref p = str::parse(P).unwrap();
        let ref q = str::parse(Q).unwrap();
        let ref n = p * q;
        let plainek = <PlainPaillier as PartiallyHomomorphicScheme>::EncryptionKey::from(n);
        let plaindk = <PlainPaillier as PartiallyHomomorphicScheme>::DecryptionKey::from(p, q);
        let ek = <PackedPaillier as PartiallyHomomorphicScheme>::EncryptionKey::from(plainek, 50, 32);
        let dk = <PackedPaillier as PartiallyHomomorphicScheme>::DecryptionKey::from(plaindk, 50, 32);
        (ek, dk)
    }
}

pub fn paillier_encryption<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<Vec<u64>>
{
    let secrets: Vec<u64> = vec![125; 100];
    let (ek, _) = PHE::test_keypair();
    b.iter(|| {
        let _: Vec<PHE::Ciphertext> = secrets.chunks(50)
                .map(|batch| {
                    let m = PHE::Plaintext::from(batch.to_vec());
                    PHE::encrypt(&ek, &m)
                })
                .collect();
    });
}

benchmark_group!(paillier,
    paillier_encryption<PackedPaillier>
);

benchmark_main!(paillier);
