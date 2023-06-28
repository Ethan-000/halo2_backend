use acvm::{
    acir::native_types::{Witness, WitnessMap},
    FieldElement, SmartContract,
};

use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
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
    SerdeFormat,
};
use snark_verifier::{
    loader::evm::{compile_yul, encode_calldata, Address, EvmLoader, ExecutorBuilder},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};

use crate::axiom_halo2::circuit_translator::NoirHalo2Translator;
use crate::axiom_halo2::AxiomHalo2;
use crate::errors::BackendError;

use rand::{rngs::OsRng, RngCore};
use serde_json::Value;
use std::env;
use std::fs;
use std::io::Read;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::rc::Rc;
type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;
use itertools::Itertools;

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
    println!("Instances {:?}", instances);
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
            &[],
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
                &[],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
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

    let compiled_code = compile_yul(&loader.yul_code());

    // TODO: Testing verifier in rust. Remove after completion
    let (circuit, witness_values) = gen_halo2_circuit_and_witness();
    let translator = NoirHalo2Translator::<Fr> {
        circuit,
        witness_values,
        _marker: PhantomData::<Fr>,
    };
    let pk = gen_pk(&params, &translator);
    let gen_proof = gen_proof(&params, &pk, translator.clone(), vec![]);
    evm_verify(compiled_code, vec![], gen_proof);

    loader.yul_code()
}

impl SmartContract for AxiomHalo2 {
    type Error = BackendError;
    fn eth_contract_from_vk(
        &self,
        common_reference_string: &[u8],
        verification_key: &[u8],
    ) -> Result<String, Self::Error> {
        let params = ParamsKZG::<Bn256>::read_custom(
            &mut &(*common_reference_string),
            SerdeFormat::RawBytes,
        );

        // Deserialize verification key
        let vk = VerifyingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            verification_key,
            SerdeFormat::RawBytes,
        )
        .unwrap();

        Ok(gen_evm_verifier(&params, &vk, vec![0]))
    }
}
