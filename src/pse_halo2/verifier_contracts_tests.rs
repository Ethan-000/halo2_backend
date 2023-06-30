use acvm::acir::native_types::WitnessMap;
use itertools::Itertools;
use pse_halo2wrong::{
    curves::bn256::{Bn256, Fq, Fr, G1Affine},
    halo2::{
        dev::MockProver,
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey,
        },
        poly::{
            commitment::{Params, ParamsProver},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverGWC, VerifierGWC},
                strategy::{AccumulatorStrategy, SingleStrategy},
            },
            VerificationStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
};
use pse_snark_verifier::{
    loader::evm::{encode_calldata, EvmLoader},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use rand::rngs::OsRng;
// TODO: Remove after verifier contract is working
use revm::{
    primitives::{CreateScheme, ExecutionResult, Output, TransactTo, TxEnv},
    InMemoryDB, EVM,
};
use serde_json::Value;
use std::{env, fs::File, io::Read, rc::Rc};

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

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    println!("{:?}", hex::encode(&calldata));
    let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
    dbg!(gas_cost);
}

fn gen_halo2_circuit_and_witness(test: &str) -> (acvm::acir::circuit::Circuit, WitnessMap) {
    let mut contents = String::new();
    let path = format!(
        "{}/tests/test_programs/{}",
        env::current_dir().unwrap().display(),
        test
    );
    // Compile
    _ = std::process::Command::new("nargo")
        .current_dir(&path)
        .arg("compile")
        .arg("my_test_circuit")
        .spawn()
        .unwrap()
        .wait_with_output();

    // Read JSON circuit representation
    File::open(format!("{}/target/my_test_circuit.json", path))
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
    // Generate witness.tr file
    _ = std::process::Command::new("nargo")
        .current_dir(&path)
        .arg("execute")
        .arg("witness")
        .spawn()
        .unwrap()
        .wait_with_output();

    _ = std::process::Command::new("nargo")
        .current_dir(&path)
        .arg("prove")
        .arg("my_test_proof")
        .spawn()
        .unwrap()
        .wait_with_output();

    // Generate verifier contract
    _ = std::process::Command::new("nargo")
        .current_dir(&path)
        .arg("codegen-verifier")
        .spawn()
        .unwrap()
        .wait_with_output();

    let mut witness_buffer = Vec::new();
    File::open(format!("{}/target/witness.tr", &path))
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
        let mut transcript: Blake2bWrite<Vec<u8>, _, Challenge255<_>> =
            Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
            _,
        >(
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
        let strategy = SingleStrategy::new(params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof.as_slice());

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            params,
            pk.get_vk(),
            strategy,
            &[instances.as_slice()],
            &mut transcript,
        )
    };
    proof
}

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

    loader.yul_code()
}

#[cfg(feature = "pse_halo2")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::errors::BackendError;
    use crate::pse_halo2::halo2_params::constuct_halo2_params_from_aztec_crs;
    type Error = BackendError;
    use crate::pse_halo2::circuit_translator::NoirHalo2Translator;
    use ethers::{
        abi::{self, AbiEncode, AbiType},
        prelude::{ContractDeployer, ContractFactory, SignerMiddleware},
        providers::Provider,
        signers::LocalWallet,
    };
    use pse_halo2wrong::{curves::bn256::Fq, halo2::SerdeFormat};
    use pse_snark_verifier::loader::evm::{compile_yul, EvmLoader};
    use std::{fs::read_to_string, marker::PhantomData, sync::Arc};

    use ethers_solc::Solc;

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

    #[tokio::test]
    async fn test_pse_verifier() {
        let (circuit, witness_values) = gen_halo2_circuit_and_witness("9_public_io");
        let translator = NoirHalo2Translator::<Fr> {
            circuit,
            witness_values,
            _marker: PhantomData::<Fr>,
        };
        let common_reference_string = generate_crs(translator.clone()).await.unwrap();
        let params = ParamsKZG::<Bn256>::read_custom(
            &mut common_reference_string.as_slice(),
            SerdeFormat::RawBytes,
        )
        .unwrap();
        let pk = gen_pk(&params, &translator);

        // let verifier_contract = gen_evm_verifier(&params, pk.get_vk(), vec![1]);
        let proof_path = format!(
            "{}/tests/test_programs/{}",
            env::current_dir().unwrap().display(),
            "9_public_io/proofs/my_test_proof.proof"
        );
        // let proof = read_to_string(proof_path).unwrap();
        let proof = hex::decode(std::fs::read(proof_path).unwrap()).unwrap();
        let contract_path = format!(
            "{}/tests/test_programs/{}",
            env::current_dir().unwrap().display(),
            "9_public_io/contract/plonk_vk.sol"
        );

        let yul_code = read_to_string(contract_path).unwrap();
        let deployment_code = compile_yul(&yul_code);

        // let gen_proof = gen_proof(&params, &pk, translator.clone(), vec![vec![]]);
        evm_verify(
            deployment_code,
            vec![vec![Fr::from_raw([7u64, 0, 0, 0])]],
            proof,
        );

        // evm_verify(deployment_code, vec![], proof.as_bytes().to_vec());
    }
}
