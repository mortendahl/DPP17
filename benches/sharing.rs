#[macro_use]
extern crate bencher;
extern crate threshold_secret_sharing as tss;

use bencher::Bencher;
use tss::packed::*;

pub fn sharing_small(b: &mut Bencher) {
    let ref pss = PSS_4_26_3;
    let secrets: Vec<i64> = vec![5 ; 9999];
    b.iter(|| {
        let _: Vec<Vec<i64>> = secrets.chunks(pss.secret_count)
                .map(|batch| pss.share(&batch))
                .collect();
    })
}

pub fn sharing_large(b: &mut Bencher) {
    let ref pss = PSS_155_728_100;
    let secrets: Vec<i64> = vec![5 ; 10000];
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
