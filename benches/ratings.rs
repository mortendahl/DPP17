
#[macro_use]
extern crate bencher;
extern crate byteorder;
extern crate threshold_secret_sharing as tss;
extern crate paillier;

use bencher::Bencher;
use tss::packed::{PackedSecretSharing};
use paillier::*;
use paillier::coding::integral::vector;



// generated via PackedSecretSharing::new_with_min_size(t, k, n, 500_000_000)
static PSS_SMALL: PackedSecretSharing = PackedSecretSharing { threshold: 5, share_count: 26, secret_count: 10, prime: 500001553, omega_secrets: 459204753, omega_shares: 405355582 };
static PSS_MEDIUM: PackedSecretSharing = PackedSecretSharing { threshold: 16, share_count: 80, secret_count: 47, prime: 500007169, omega_secrets: 31452382, omega_shares: 369291191 };
static PSS_LARGE: PackedSecretSharing = PackedSecretSharing { threshold: 145, share_count: 728, secret_count: 366, prime: 502765057, omega_secrets: 401243248, omega_shares: 457252994 };

// 1024 bit primes
static P: &'static str = "148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517";
static Q: &'static str = "158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463";
static CIPHERTEXT_COMPONENT_SIZE: usize = 29+32;
static CIPHERTEXT_COMPONENT_COUNT: usize = 33;

static INPUT: [i64; 35_400] = [42; 35_400];



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

fn encrypt<EK>(ek: &EK, plaintexts: &Vec<u64>) -> Vec<vector::Ciphertext<BigInteger, u64>>
where Paillier : Encryption<EK, Vec<u64>, vector::Ciphertext<BigInteger, u64>>
{
    let ciphertexts: Vec<vector::Ciphertext<BigInteger, u64>> = plaintexts
        .chunks(CIPHERTEXT_COMPONENT_COUNT)
        .map(|batch| {
            let mut padded_batch = batch.to_vec();
            while padded_batch.len() < CIPHERTEXT_COMPONENT_COUNT { padded_batch.push(0); }
            padded_batch
        })
        .map(|batch| {
            Paillier::encrypt(ek, &batch)
        })
        .collect();
    ciphertexts
}

fn decrypt<DK>(dk: &DK, ciphertexts: &Vec<vector::Ciphertext<BigInteger, u64>>) -> Vec<Vec<u64>>
where Paillier : Decryption<DK, vector::Ciphertext<BigInteger, u64>, Vec<u64>>
{
    ciphertexts.iter()
        .map(|ciphertext| {
            Paillier::decrypt(dk, ciphertext)
        })
        .collect()
}

fn test_keypair() -> Keypair<BigInteger> {
    let ref p = str::parse(P).unwrap();
    let ref q = str::parse(Q).unwrap();
    Keypair::from((p, q))
}



fn bench_share(b: &mut Bencher, pss: &PackedSecretSharing) {
    let ref secrets = INPUT.to_vec();
    b.iter(|| {
        let _shares_for_all = share(pss, &secrets);
    })
}

pub fn bench_share_small(b: &mut Bencher) { bench_share(b, &PSS_SMALL); }
pub fn bench_share_medium(b: &mut Bencher) { bench_share(b, &PSS_MEDIUM); }
pub fn bench_share_large(b: &mut Bencher) { bench_share(b, &PSS_LARGE); }
benchmark_group!(group_share, bench_share_small, bench_share_medium, bench_share_large );



fn bench_encrypt(b: &mut Bencher, pss: &PackedSecretSharing) {
    let ref secrets: Vec<i64> = INPUT.to_vec();
    let ref shares_for_all: Vec<Vec<i64>> = share(pss, &secrets);
    let ref shares_for_one: Vec<u64> = shares_for_all.iter()
        .map(|shares| shares[0] as u64)
        .collect();

    let (ek, _) = test_keypair().keys();
    let ref code = integral::Code::new(CIPHERTEXT_COMPONENT_COUNT, CIPHERTEXT_COMPONENT_SIZE);
    let ref eek = ek.with_code(code);

    b.iter(|| {
        let _ciphertexts = encrypt(eek, shares_for_one);
    });
}

fn bench_encrypt_small(b: &mut Bencher) { bench_encrypt(b, &PSS_SMALL); }
fn bench_encrypt_medium(b: &mut Bencher) { bench_encrypt(b, &PSS_MEDIUM); }
fn bench_encrypt_large(b: &mut Bencher) { bench_encrypt(b, &PSS_LARGE); }
benchmark_group!(group_encrypt, bench_encrypt_small, bench_encrypt_medium, bench_encrypt_large );



fn bench_decrypt(b: &mut Bencher, pss: &PackedSecretSharing) {
    let ref secrets: Vec<i64> = INPUT.to_vec();
    let ref shares_for_all: Vec<Vec<i64>> = share(pss, &secrets);
    let ref shares_for_one: Vec<u64> = shares_for_all.iter()
        .map(|shares| shares[0] as u64)
        .collect();

    let (ek, dk) = test_keypair().keys();
    let ref code = integral::Code::new(CIPHERTEXT_COMPONENT_COUNT, CIPHERTEXT_COMPONENT_SIZE);
    let ref eek = ek.with_code(code);
    let ref ddk = dk.with_code(code);

    let ref ciphertexts = encrypt(eek, shares_for_one);
    b.iter(|| {
        let _plaintexts = decrypt(ddk, ciphertexts);
    });
}

fn bench_decrypt_small(b: &mut Bencher) { bench_decrypt(b, &PSS_SMALL); }
fn bench_decrypt_medium(b: &mut Bencher) { bench_decrypt(b, &PSS_MEDIUM); }
fn bench_decrypt_large(b: &mut Bencher) { bench_decrypt(b, &PSS_LARGE); }
benchmark_group!(group_decrypt, bench_decrypt_small, bench_decrypt_medium, bench_decrypt_large );



benchmark_main!(group_share, group_encrypt, group_decrypt);
