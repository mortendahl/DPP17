#[macro_use]
extern crate bencher;
extern crate threshold_secret_sharing as tss;

use bencher::Bencher;
use tss::packed::*;

pub fn sharing_small(b: &mut Bencher) {
    let ref pss = PackedSecretSharing::new(5, 10, 26);
    let secrets: Vec<i64> = vec![5 ; 3540 * pss.secret_count];
    b.iter(|| {
        let _: Vec<Vec<i64>> = secrets.chunks(pss.secret_count)
                .map(|batch| pss.share(&batch))
                .collect();
    })
}

pub fn sharing_large(b: &mut Bencher) {
    let ref pss = PackedSecretSharing::new(16, 47, 80);
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
