use crate::{circuit_translator::NoirHalo2Translator, AxiomHalo2};
use acvm::{acir::circuit::Circuit, SmartContract};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use noir_halo2_backend_common::errors::BackendError;
use snark_verifier::{
    loader::evm::EvmLoader,
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use std::rc::Rc;

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> String {
    let protocol = compile(params, vk, Config::kzg().with_num_instance(num_instance.clone()));
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();
    loader.yul_code()
}

impl SmartContract for AxiomHalo2 {
    type Error = BackendError;
    fn eth_contract_from_vk(
        &self,
        common_reference_string: &[u8],
        circuit: &Circuit,
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
