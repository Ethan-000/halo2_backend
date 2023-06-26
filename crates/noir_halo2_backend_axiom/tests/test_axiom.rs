use noir_halo2_backend_common::test_helpers::{
    configure_test_dirs, install_nargo, run_nargo_tests,
};

// TODO: Axiom is currently not working.
// tho tests passes the crs size does not
// change with each test.
#[test]
fn test_axiom_backend() {
    let test_program_dirs = configure_test_dirs();
    // Pass in Axiom Halo2 Backend as argument
    install_nargo("axiom_halo2_backend");
    for test_program in test_program_dirs {
        run_nargo_tests(test_program);
    }
}
