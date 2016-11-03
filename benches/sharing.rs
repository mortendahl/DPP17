#[macro_use]
extern crate bencher;
extern crate threshold_secret_sharing as tss;

use bencher::Bencher;
use tss::packed::*;

pub fn sharing_small(b: &mut Bencher) {
    // let ref pss = PackedSecretSharing::new_with_min_size(5, 10, 26, 500_000_000);
    let ref pss = PackedSecretSharing { threshold: 5, share_count: 26, secret_count: 10, prime: 500001553, omega_secrets: 459204753, omega_shares: 405355582 };
    let secrets: Vec<i64> = vec![5 ; 3540 * pss.secret_count];
    b.iter(|| {
        let _: Vec<Vec<i64>> = secrets.chunks(pss.secret_count)
                .map(|batch| pss.share(&batch))
                .collect();
    })
}

pub fn sharing_large(b: &mut Bencher) {
    // let ref pss = PackedSecretSharing::new_with_min_size(16, 47, 80, 500_000_000);
    let ref pss = PackedSecretSharing { threshold: 16, share_count: 80, secret_count: 47, prime: 500007169, omega_secrets: 31452382, omega_shares: 369291191 };
    let secrets: Vec<i64> = vec![5 ; 754 * pss.secret_count];
    b.iter(|| {
        let _: Vec<Vec<i64>> = secrets.chunks(pss.secret_count)
                .map(|batch| pss.share(&batch))
                .collect();
    })
}

benchmark_group!(sharing,
    sharing_small,
    sharing_large
);

benchmark_main!(sharing);
