
#[macro_use]
extern crate bencher;
extern crate byteorder;
extern crate threshold_secret_sharing as tss;
extern crate sodiumoxide;

use bencher::Bencher;
use byteorder::{ByteOrder, LittleEndian};
use tss::packed::*;
use sodiumoxide::crypto;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{PublicKey, SecretKey};



fn share(pss: &PackedSecretSharing, secrets: &Vec<i64>) -> Vec<Vec<i64>> {
    secrets
        .chunks(pss.secret_count)
        .map(|batch| {
            let mut padded_batch = batch.to_vec();
            while padded_batch.len() < pss.secret_count { padded_batch.push(0); }
            padded_batch
        })
        .map(|batch| pss.share(&batch))
        .collect()
}

fn encrypt(ek: &PublicKey, plaintext: &Vec<i64>) -> Vec<u8> {
    let ref serialised: Vec<u8> = plaintext.iter()
        .flat_map(|v| {
            let mut buf = [0; 8];
            LittleEndian::write_i64(&mut buf, v.clone());
            buf.to_vec()
        })
        .collect();
    crypto::sealedbox::seal(serialised, ek)
}

fn decrypt(ek: &PublicKey, dk:&SecretKey, ciphertext: &[u8]) -> Vec<u8> {
    crypto::sealedbox::open(ciphertext, &ek, &dk).unwrap()
}



// generated via PackedSecretSharing::new_with_min_size(t, k, n, 500_000_000)
static PSS_SMALL: PackedSecretSharing = PackedSecretSharing { threshold: 5, share_count: 26, secret_count: 10, prime: 500001553, omega_secrets: 459204753, omega_shares: 405355582 };
static PSS_MEDIUM: PackedSecretSharing = PackedSecretSharing { threshold: 16, share_count: 80, secret_count: 47, prime: 500007169, omega_secrets: 31452382, omega_shares: 369291191 };
static PSS_LARGE: PackedSecretSharing = PackedSecretSharing { threshold: 145, share_count: 728, secret_count: 366, prime: 502765057, omega_secrets: 401243248, omega_shares: 457252994 };

static INPUT: [i64; 100] = [42; 100];



fn bench_share(b: &mut Bencher, pss: &PackedSecretSharing) {
    let ref secrets: Vec<i64> = INPUT.to_vec();
    b.iter(|| {
        let _shares_for_all: Vec<Vec<i64>> = share(pss, secrets);
    })
}

pub fn bench_share_small(b: &mut Bencher) { bench_share(b, &PSS_SMALL); }
pub fn bench_share_medium(b: &mut Bencher) { bench_share(b, &PSS_MEDIUM); }
pub fn bench_share_large(b: &mut Bencher) { bench_share(b, &PSS_LARGE); }
benchmark_group!(group_share,
    bench_share_small,
    bench_share_medium,
    bench_share_large
);



fn bench_encrypt(b: &mut Bencher, pss: &PackedSecretSharing) {
    let ref secrets: Vec<i64> = INPUT.to_vec();
    let ref shares_for_all: Vec<Vec<i64>> = share(pss, secrets);
    let ref shares_for_one: Vec<i64> = shares_for_all.iter()
        .map(|shares| shares[0])
        .collect();
    let (ref ek, ref _dk) = crypto::box_::gen_keypair();
    b.iter(|| {
        let _ciphertexts = encrypt(ek, shares_for_one);
    });
}

fn bench_encrypt_small(b: &mut Bencher) { bench_encrypt(b, &PSS_SMALL); }
fn bench_encrypt_medium(b: &mut Bencher) { bench_encrypt(b, &PSS_MEDIUM); }
fn bench_encrypt_large(b: &mut Bencher) { bench_encrypt(b, &PSS_LARGE); }
benchmark_group!(group_encrypt,
    bench_encrypt_small,
    bench_encrypt_medium,
    bench_encrypt_large
);



fn bench_decrypt(b: &mut Bencher, pss: &PackedSecretSharing) {
    let ref secrets: Vec<i64> = INPUT.to_vec();
    let ref shares_for_all: Vec<Vec<i64>> = share(pss, secrets);
    let ref shares_for_one: Vec<i64> = shares_for_all.iter()
        .map(|shares| shares[0])
        .collect();
    let (ref ek, ref dk) = crypto::box_::gen_keypair();
    let ref ciphertexts = encrypt(ek, shares_for_one);
    b.iter(|| {
        let _plaintexts = decrypt(ek, dk, ciphertexts);
    });
}

fn bench_decrypt_small(b: &mut Bencher) { bench_decrypt(b, &PSS_SMALL); }
fn bench_decrypt_medium(b: &mut Bencher) { bench_decrypt(b, &PSS_MEDIUM); }
fn bench_decrypt_large(b: &mut Bencher) { bench_decrypt(b, &PSS_LARGE); }
benchmark_group!(group_decrypt,
    bench_decrypt_small,
    bench_decrypt_medium,
    bench_decrypt_large
);



benchmark_main!(group_share, group_encrypt, group_decrypt);
