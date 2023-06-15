#![feature(test)]
extern crate test;
use test::Bencher;
mod nargo_tests;
use nargo_tests::{install_nargo, run_nargo_tests, test_program_dir_path};

const BACKENDS: [&str; 2] = ["axiom_halo2_backend", "pse_halo2_backend"];
const HALO2_BACKEND: &str = BACKENDS[0];

#[bench]
fn mul(b: &mut Bencher) {
    install_nargo(HALO2_BACKEND);
    let path = test_program_dir_path("1_mul");
    b.iter(|| {
        run_nargo_tests(path.clone());
    });
}

#[bench]
fn div(b: &mut Bencher) {
    install_nargo(HALO2_BACKEND);
    let path = test_program_dir_path("2_div");
    b.iter(|| {
        run_nargo_tests(path.clone());
    });
}

#[bench]
fn add(b: &mut Bencher) {
    install_nargo(HALO2_BACKEND);
    let path = test_program_dir_path("3_add");
    b.iter(|| {
        run_nargo_tests(path.clone());
    });
}

#[bench]
fn sub(b: &mut Bencher) {
    install_nargo(HALO2_BACKEND);
    let path = test_program_dir_path("4_sub");
    b.iter(|| {
        run_nargo_tests(path.clone());
    });
}

#[bench]
fn over(b: &mut Bencher) {
    install_nargo(HALO2_BACKEND);
    let path = test_program_dir_path("5_over");
    b.iter(|| {
        run_nargo_tests(path.clone());
    });
}

#[bench]
fn array(b: &mut Bencher) {
    install_nargo(HALO2_BACKEND);
    let path = test_program_dir_path("6_array");
    b.iter(|| {
        run_nargo_tests(path.clone());
    });
}

#[bench]
fn function(b: &mut Bencher) {
    install_nargo(HALO2_BACKEND);
    let path = test_program_dir_path("7_function");
    b.iter(|| {
        run_nargo_tests(path.clone());
    });
}

#[bench]
fn bit_and(b: &mut Bencher) {
    install_nargo(HALO2_BACKEND);
    let path = test_program_dir_path("8_bit_and");
    b.iter(|| {
        run_nargo_tests(path.clone());
    });
}
