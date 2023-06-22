use std::marker::PhantomData;
use std::rc::Rc;

use acvm::acir::native_types::WitnessMap;
use acvm::SmartContract;
use pse_halo2wrong::curves::bn256::{Bn256, Fq, Fr, G1Affine};
use pse_halo2wrong::halo2::dev::MockProver;
use pse_halo2wrong::halo2::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey,
};
use pse_halo2wrong::halo2::poly::commitment::{Params, ParamsProver};
use pse_halo2wrong::halo2::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use pse_halo2wrong::halo2::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use pse_halo2wrong::halo2::poly::kzg::strategy::AccumulatorStrategy;
use pse_halo2wrong::halo2::poly::VerificationStrategy;
use pse_halo2wrong::halo2::transcript::{TranscriptReadBuffer, TranscriptWriterBuffer};
use pse_halo2wrong::halo2::SerdeFormat;
use pse_snark_verifier::loader::evm::{compile_yul, encode_calldata, EvmLoader};
use pse_snark_verifier::pcs::kzg::{Gwc19, KzgAs};
use pse_snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use pse_snark_verifier::system::halo2::{compile, Config};
use pse_snark_verifier::verifier::{self, SnarkVerifier};
use rand::rngs::OsRng;
use revm::primitives::{CreateScheme, ExecutionResult, Output, TransactTo, TxEnv};
use revm::{InMemoryDB, EVM};

use crate::errors::BackendError;

use crate::pse_halo2::circuit_translator::NoirHalo2Translator;
use crate::pse_halo2::halo2_plonk_api::OpcodeFlags;
use crate::pse_halo2::PseHalo2;
use itertools::Itertools;
use serde_json::Value;
use std::env;
use std::fs;
use std::io::Read;
type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

pub fn deploy_and_call(deployment_code: Vec<u8>, calldata: Vec<u8>) -> Result<u64, String> {
    let mut evm = EVM {
        env: Default::default(),
        db: Some(InMemoryDB::default()),
    };

    evm.env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TransactTo::Create(CreateScheme::Create),
        data: deployment_code.into(),
        ..Default::default()
    };

    let result = evm.transact_commit().unwrap();
    let contract = match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(contract)),
            ..
        } => contract,
        ExecutionResult::Revert { gas_used, output } => {
            return Err(format!(
                "Contract deployment transaction reverts with gas_used {gas_used} and output {:#x}",
                output
            ))
        }
        ExecutionResult::Halt { reason, gas_used } => return Err(format!(
                "Contract deployment transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
                reason
            )),
        _ => unreachable!(),
    };

    evm.env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TransactTo::Call(contract),
        data: calldata.into(),
        ..Default::default()
    };

    let result = evm.transact_commit().unwrap();
    match result {
        ExecutionResult::Success { gas_used, .. } => Ok(gas_used),
        ExecutionResult::Revert { gas_used, output } => Err(format!(
            "Contract call transaction reverts with gas_used {gas_used} and output {:#x}",
            output
        )),
        ExecutionResult::Halt { reason, gas_used } => Err(format!(
            "Contract call transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
            reason
        )),
    }
}

fn gen_proof<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
    dbg!(gas_cost);
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
}

fn gen_halo2_circuit_and_witness() -> (acvm::acir::circuit::Circuit, WitnessMap) {
    let mut contents = String::new();
    fs::File::open(format!(
        "{}/target/my_test_circuit.json",
        env::current_dir().unwrap().display()
    ))
    .unwrap()
    .read_to_string(&mut contents)
    .unwrap();
    let json: Value = serde_json::from_str(&contents).unwrap();
    let bytecode: Vec<u8> = json
        .get("bytecode")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(|v| v.as_u64().map(|n| n as u8))
        .collect();
    let circuit = acvm::acir::circuit::Circuit::read(&*bytecode).unwrap();
    _ = std::process::Command::new("nargo")
        .current_dir(&env::current_dir().unwrap())
        .arg("execute")
        .arg("witness")
        .spawn()
        .unwrap()
        .wait_with_output();

    let mut witness_buffer = Vec::new();
    fs::File::open(format!(
        "{}/target/witness.tr",
        env::current_dir().unwrap().display()
    ))
    .unwrap()
    .read_to_end(&mut witness_buffer)
    .unwrap();

    let witness = WitnessMap::try_from(&witness_buffer[..]).unwrap();
    (circuit, witness)
}

/// Generate the evm verifier of the circuit as Yul code
fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> String {
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    // TODO: Testing verifier in rust. Remove after completion
    let (circuit, witness_values) = gen_halo2_circuit_and_witness();
    let translator = NoirHalo2Translator::<Fr> {
        circuit,
        witness_values,
        _marker: PhantomData::<Fr>,
    };
    let pk = gen_pk(&params, &translator);
    println!("{:?}", pk);
    let gen_proof = gen_proof(&params, &pk, translator.clone(), vec![vec![]]);
    evm_verify(compile_yul(&loader.yul_code()), vec![vec![]], gen_proof);

    loader.yul_code()
}

impl SmartContract for PseHalo2 {
    type Error = BackendError;

    /// Get ethereum verification contract from Verification Key
    fn eth_contract_from_vk(
        &self,
        mut common_reference_string: &[u8],
        verification_key: &[u8],
    ) -> Result<String, Self::Error> {
        let params =
            ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes)
                .unwrap();

        let opcode_flags = OpcodeFlags::default();
        let vk = VerifyingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            verification_key,
            SerdeFormat::RawBytes,
            opcode_flags,
        )
        .unwrap();

        Ok(gen_evm_verifier(&params, &vk, vec![1]))
    }
}
