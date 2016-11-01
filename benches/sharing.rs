#[macro_use]
extern crate bencher;
extern crate threshold_secret_sharing as tss;

use bencher::Bencher;
use tss::packed::PSS_155_728_100 as pss;

pub fn sharing_pack(b: &mut Bencher) {
    let secrets: Vec<i64> = vec![5 ; 10000];
    b.iter(|| {
        let _: Vec<Vec<i64>> = secrets.chunks(pss.secret_count)
                .map(|batch| pss.share(&batch))
                .collect();
    })
}

benchmark_group!(sharing,
    sharing_pack
);

benchmark_main!(sharing);
