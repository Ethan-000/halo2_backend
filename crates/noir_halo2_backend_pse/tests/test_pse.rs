use noir_halo2_backend_common::test_helpers::{
    configure_test_dirs, install_nargo, run_nargo_tests,
};

#[test]
fn test_pse_backend() {
    let test_program_dirs = configure_test_dirs();
    // Pass in PSE Halo2 Backend as argument
    install_nargo("pse_halo2_backend");
    for test_program in test_program_dirs {
        run_nargo_tests(test_program);
    }
}
