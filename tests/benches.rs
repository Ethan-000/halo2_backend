#![feature(test)]
extern crate test;
use test::Bencher;
mod nargo_tests;

const BACKENDS: [&str; 2] = ["axiom_halo2_backend", "pse_halo2_backend"];
const HALO2_BACKEND: &str = BACKENDS[0];

#[bench]
fn mul(b: &mut Bencher) {
    // Pass in Axiom Halo2 Backend as argument
    nargo_tests::install_nargo(HALO2_BACKEND);
    // b.iter(|| {
    //     let test_program_dirs = configure_test_dirs();
    //     run_nargo_tests(test_program_dirs);
    // });
}
