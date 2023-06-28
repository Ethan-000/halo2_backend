use acvm::acir::native_types::WitnessMap;
use itertools::Itertools;
use pse_halo2wrong::{
    curves::bn256::{Bn256, Fr, G1Affine},
    halo2::{
        dev::MockProver,
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey},
        poly::{
            commitment::{Params, ParamsProver},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverGWC, VerifierGWC},
                strategy::AccumulatorStrategy,
            },
            VerificationStrategy,
        },
        transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
    },
};
use pse_snark_verifier::{
    loader::evm::encode_calldata, system::halo2::transcript::evm::EvmTranscript,
};
use rand::rngs::OsRng;
// TODO: Remove after verifier contract is working
use revm::{
    primitives::{CreateScheme, ExecutionResult, Output, TransactTo, TxEnv},
    InMemoryDB, EVM,
};
use serde_json::Value;
use std::{env, fs::File, io::Read};

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

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    println!("Calldata: {:?}", hex::encode(&calldata));
    let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
    dbg!(gas_cost);
}

fn gen_halo2_circuit_and_witness() -> (acvm::acir::circuit::Circuit, WitnessMap) {
    let mut contents = String::new();
    File::open(format!(
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
    File::open(format!(
        "{}/target/witness.tr",
        env::current_dir().unwrap().display()
    ))
    .unwrap()
    .read_to_end(&mut witness_buffer)
    .unwrap();

    let witness = WitnessMap::try_from(&witness_buffer[..]).unwrap();
    (circuit, witness)
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
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

#[cfg(feature = "pse_halo2")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::errors::BackendError;
    use crate::pse_halo2::halo2_params::constuct_halo2_params_from_aztec_crs;
    type Error = BackendError;
    use std::marker::PhantomData;

    use pse_halo2wrong::{curves::bn256::Fq, halo2::SerdeFormat};
    use pse_snark_verifier::loader::evm::{compile_yul, EvmLoader};

    use crate::pse_halo2::circuit_translator::NoirHalo2Translator;

    async fn generate_crs(translator: NoirHalo2Translator<Fr>) -> Result<Vec<u8>, Error> {
        let mut common_reference_string = Vec::new();
        constuct_halo2_params_from_aztec_crs(translator)
            .await?
            .write_custom(
                &mut common_reference_string,
                pse_halo2wrong::halo2::SerdeFormat::RawBytes,
            )
            .unwrap();
        Ok(common_reference_string)
    }

    #[cfg(test)]
    async fn test_pse_verifier() {
        let (circuit, witness_values) = gen_halo2_circuit_and_witness();
        let translator = NoirHalo2Translator::<Fr> {
            circuit,
            witness_values,
            _marker: PhantomData::<Fr>,
        };
        let mut common_reference_string = generate_crs(translator.clone()).await.unwrap();
        let params = ParamsKZG::<Bn256>::read_custom(
            &mut common_reference_string.as_slice(),
            SerdeFormat::RawBytes,
        )
        .unwrap();
        let loader = EvmLoader::new::<Fq, Fr>();
        let pk = gen_pk(&params, &translator);
        let gen_proof = gen_proof(&params, &pk, translator.clone(), vec![vec![]]);
        evm_verify(compile_yul(&loader.yul_code()), vec![vec![]], gen_proof);
    }
}
