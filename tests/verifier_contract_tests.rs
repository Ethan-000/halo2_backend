mod nargo_tests;
use nargo_tests::{
    install_nargo, nargo_codegen_verifier, nargo_compile, nargo_prove, test_program_dir_path,
};

use hex::FromHex;
use itertools::Itertools;
use std::{fs::File, io::Read, iter, path::PathBuf};

#[cfg(feature = "axiom_halo2")]
use {
    halo2_base::halo2_proofs::{
        halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
        plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    },
    snark_verifier::{
        loader::evm::{self, Address, EvmLoader, ExecutorBuilder},
        pcs::kzg::Gwc19,
        system::halo2::{compile, transcript::evm::EvmTranscript, Config},
        util::arithmetic::PrimeField,
        verifier::{self, plonk::PlonkVerifier, SnarkVerifier},
    },
};

#[cfg(feature = "pse_halo2")]
use pse_halo2wrong::curves::{bn256::Fr, ff::PrimeField};

const BACKENDS: [&str; 2] = ["axiom_halo2_backend", "pse_halo2_backend"];
const HALO2_BACKEND: &str = BACKENDS[0];

fn encode_calldata<F>(instances: &[Vec<F>], proof: &[u8]) -> Vec<u8>
where
    F: PrimeField<Repr = [u8; 32]>,
{
    iter::empty()
        .chain(
            instances
                .iter()
                .flatten()
                .flat_map(|value| value.to_repr().as_ref().iter().rev().cloned().collect_vec()),
        )
        .chain(proof.iter().cloned())
        .collect()
}

fn get_instance_values(test_program_dir: &PathBuf) -> Vec<Fr> {
    // Open Verifier.toml file
    let mut verifier_file = File::open(format!(
        "{}/{}",
        test_program_dir.display(),
        "Verifier.toml"
    ))
    .expect("Failed to open proof file");
    let mut verifier_file_contents = String::from("");
    // Read in file contents
    verifier_file
        .read_to_string(&mut verifier_file_contents)
        .expect("Failed to read proof file");

    let instance_values: Vec<Fr> = verifier_file_contents
        .split('=')
        .collect::<Vec<&str>>()
        .into_iter()
        .enumerate()
        .filter_map(|(index, val)| {
            if index % 2 == 0 {
                return None;
            } else {
                let trimmed_val = val.trim().trim_matches('\"');
                // Handle value in hex
                if trimmed_val.starts_with("0x") {
                    let byte_vec = Vec::from_hex(&trimmed_val[2..]).unwrap();
                    let byte_arr: [u8; 32] = byte_vec.try_into().unwrap();
                    return Some(Fr::from_bytes(&byte_arr).unwrap());
                } else {
                    return Some(Fr::from_str_vartime(trimmed_val).unwrap());
                };
            }
        })
        .collect();
    instance_values
}

fn get_proof_string(test_program_dir: &PathBuf) -> String {
    // Generate proof
    nargo_compile(test_program_dir).unwrap();
    nargo_prove(test_program_dir).unwrap();
    // Open proof file
    let mut proof_file = File::open(format!(
        "{}/{}",
        test_program_dir.display(),
        "proofs/my_test_proof.proof"
    ))
    .expect("Failed to open proof file");
    let mut proof = String::from("");
    // Read proof in as string
    proof_file
        .read_to_string(&mut proof)
        .expect("Failed to read proof file");
    proof
}

#[test]
fn test_verifier_contract() {
    install_nargo(HALO2_BACKEND);
    let test_program_dir = test_program_dir_path("1_mul");
    let proof = get_proof_string(&test_program_dir);
    // println!("{}", proof);
    let instances = get_instance_values(&test_program_dir);
    // Generate verifier contract
    nargo_codegen_verifier(&test_program_dir).unwrap();

    let instance: Vec<Fr> = vec![];

    let calldata = encode_calldata(&vec![instance], &proof.as_bytes());
    // let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![1]);
}
