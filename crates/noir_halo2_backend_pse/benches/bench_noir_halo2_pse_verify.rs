use criterion::{criterion_group, criterion_main, Criterion};
use noir_halo2_backend_common::test_helpers::{
    install_nargo, run_nargo_verify, test_program_dir_path,
};

fn benchmark_tests_verify(c: &mut Criterion) {
    install_nargo("pse_halo2_backend");

    // 1_mul
    let path = test_program_dir_path("1_mul");
    c.bench_function("1_mul_verify", |b| {
        b.iter(|| run_nargo_verify(path.clone()))
    });

    // 2_div
    let path = test_program_dir_path("2_div");
    c.bench_function("2_div_verify", |b| {
        b.iter(|| run_nargo_verify(path.clone()))
    });

    // 3_add
    let path = test_program_dir_path("3_add");
    c.bench_function("3_add_verify", |b| {
        b.iter(|| run_nargo_verify(path.clone()))
    });

    // 4_sub
    let path = test_program_dir_path("4_sub");
    c.bench_function("4_sub_verify", |b| {
        b.iter(|| run_nargo_verify(path.clone()))
    });

    // 5_over
    let path = test_program_dir_path("5_over");
    c.bench_function("5_over_verify", |b| {
        b.iter(|| run_nargo_verify(path.clone()))
    });

    // 6_array
    let path = test_program_dir_path("6_array");
    c.bench_function("6_array_verify", |b| {
        b.iter(|| run_nargo_verify(path.clone()))
    });

    // 7_function
    let path = test_program_dir_path("7_function");
    c.bench_function("7_function_verify", |b| {
        b.iter(|| run_nargo_verify(path.clone()))
    });

    // bit_and
    let path = test_program_dir_path("8_bit_and");
    c.bench_function("8_bit_and_verify", |b| {
        b.iter(|| run_nargo_verify(path.clone()))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =  benchmark_tests_verify
}
criterion_main!(benches);
