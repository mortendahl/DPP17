
#[macro_use]
extern crate bencher;

#[cfg(feature="inclsodium")]
extern crate sodiumoxide;

#[cfg(feature="inclsodium")]
mod foo {

    use bencher::Bencher;
    use sodiumoxide::crypto;

    pub fn sodium_encryption(b: &mut Bencher) {
        let secrets: Vec<u8> = vec![125; 8*10000];
        let (ek, _) = crypto::box_::gen_keypair();
        b.iter(|| {
            let _ = crypto::sealedbox::seal(&secrets, &ek);
        });
    }

    pub fn sodium_decryption(b: &mut Bencher) {
        let secrets: Vec<u8> = vec![125; 8*10000];
        let (ek, dk) = crypto::box_::gen_keypair();
        let enc = crypto::sealedbox::seal(&secrets, &ek);
        b.iter(|| {
            let _ = crypto::sealedbox::open(&enc, &ek, &dk).unwrap();
        });
    }



}

#[cfg(feature="inclsodium")]
use self::foo::*;
#[cfg(feature="inclsodium")]
benchmark_group!(sodium,
    sodium_encryption,
    sodium_decryption
);

#[cfg(not(feature="inclsodium"))]
pub fn dummy(_: &mut bencher::Bencher) {}
#[cfg(not(feature="inclsodium"))]
benchmark_group!(sodium, dummy);

benchmark_main!(sodium);
