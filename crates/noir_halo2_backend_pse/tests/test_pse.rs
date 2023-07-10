use std::{
    fs::{read, read_to_string},
    path::PathBuf,
};

use hex;
use noir_halo2_backend_common::test_helpers::{
    configure_test_dirs, install_nargo, run_nargo_check, run_nargo_contract, run_nargo_prove,
    run_nargo_tests,
};
use pse_halo2wrong::curves::bn256::Fr;
use pse_snark_verifier::loader::evm::{compile_yul, encode_calldata, Address, ExecutorBuilder};

#[test]
fn test_pse_backend() {
    let test_program_dirs = configure_test_dirs();
    // Pass in PSE Halo2 Backend as argument
    install_nargo("pse_halo2_backend");
    for test_program in test_program_dirs {
        run_nargo_tests(test_program);
    }
}

fn gen_nargo_files(test_program: PathBuf) {
    run_nargo_check(test_program.clone());
    run_nargo_contract(test_program.clone());
    run_nargo_prove(test_program.clone());
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();

        let caller = Address::from_low_u64_be(0xfe);
        let verifier = evm
            .deploy(caller, deployment_code.into(), 0.into())
            .address
            .unwrap();
        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

        dbg!(result.gas_used);

        !result.reverted
    };
    assert!(success);
}

// Set num instances in verifier contract file to 0
#[test]
fn test_pse_verifier_contracts_no_public_io() {
    let test_program_dirs = configure_test_dirs();
    // Pass in PSE Halo2 Backend as argument
    install_nargo("pse_halo2_backend");
    for test_program in &test_program_dirs[0..1] {
        // Generate necessary files
        gen_nargo_files(test_program.clone());
        // Paths to relevant nargo generated files
        let contract_path = format!("{}/contract/plonk_vk.sol", test_program.display());
        let proof_path = format!("{}/proofs/my_test_proof.proof", test_program.display());

        let yul_code = read_to_string(contract_path);
        let deployment_code = compile_yul(&yul_code.unwrap());

        let proof = hex::decode(read(proof_path).unwrap()).unwrap();
        evm_verify(deployment_code, vec![vec![]], proof);
    }
}

// Set num instances in verifier contract file to 1
#[test]
fn test_pse_verifier_contracts_public_io() {
    let test_program_dirs = configure_test_dirs();
    // Pass in PSE Halo2 Backend as argument
    install_nargo("pse_halo2_backend");
    for test_program in &test_program_dirs[8..9] {
        // Generate necessary files
        gen_nargo_files(test_program.clone());
        // Paths to relevant nargo generated files
        let contract_path = format!("{}/contract/plonk_vk.sol", test_program.display());
        let proof_path = format!("{}/proofs/my_test_proof.proof", test_program.display());

        let yul_code = read_to_string(contract_path);
        let deployment_code = compile_yul(&yul_code.unwrap());

        let proof = hex::decode(read(proof_path).unwrap()).unwrap();
        evm_verify(deployment_code, vec![vec![Fr::from(7)]], proof);
    }
}

// Set num instances in verifier contract file to 3
#[test]
fn test_pse_verifier_contracts_public_io_array() {
    let test_program_dirs = configure_test_dirs();
    // Pass in PSE Halo2 Backend as argument
    install_nargo("pse_halo2_backend");
    for test_program in &test_program_dirs[9..] {
        // Generate necessary files
        gen_nargo_files(test_program.clone());
        // Paths to relevant nargo generated files
        let contract_path = format!("{}/contract/plonk_vk.sol", test_program.display());
        let proof_path = format!("{}/proofs/my_test_proof.proof", test_program.display());

        let yul_code = read_to_string(contract_path);
        let deployment_code = compile_yul(&yul_code.unwrap());

        let proof = hex::decode(read(proof_path).unwrap()).unwrap();
        evm_verify(
            deployment_code,
            vec![vec![Fr::from(341), Fr::from(219), Fr::from(499)]],
            proof,
        );
    }
}
