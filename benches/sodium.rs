
#[macro_use]
extern crate bencher;

#[cfg(feature="benchsodium")]
extern crate sodiumoxide;

#[cfg(feature="benchsodium")]
mod foo {

    use bencher::Bencher;
    use sodiumoxide::crypto;

    pub fn sodium_encryption(b: &mut Bencher) {
        let secrets: Vec<u8> = vec![125; 4*26*10];
        let (ek, _) = crypto::box_::gen_keypair();
        b.iter(|| {
            let _ = crypto::sealedbox::seal(&secrets, &ek);
        });
    }

    pub fn sodium_decryption(b: &mut Bencher) {
        let secrets: Vec<u8> = vec![125; 4*26*10];
        let (ek, dk) = crypto::box_::gen_keypair();
        let enc = crypto::sealedbox::seal(&secrets, &ek);
        b.iter(|| {
            let _ = crypto::sealedbox::open(&enc, &ek, &dk).unwrap();
        });
    }



}

#[cfg(feature="benchsodium")]
use self::foo::*;
#[cfg(feature="benchsodium")]
benchmark_group!(sodium,
    sodium_encryption,
    sodium_decryption
);

#[cfg(not(feature="benchsodium"))]
pub fn dummy(_: &mut bencher::Bencher) {}
#[cfg(not(feature="benchsodium"))]
benchmark_group!(sodium, dummy);

benchmark_main!(sodium);
