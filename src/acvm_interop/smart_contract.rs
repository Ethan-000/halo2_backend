use acvm::SmartContract;

use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use snark_verifier::{
    loader::evm::{self, encode_calldata, EvmLoader, ExecutorBuilder},
    pcs::kzg::{Gwc19, Kzg},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, PlonkVerifier},
};

use crate::errors::BackendError;

use crate::Halo2;

use std::rc::Rc;
type Plonk = verifier::Plonk<Kzg<Bn256, Gwc19>>;

fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::read_proof(&svk, &protocol, &instances, &mut transcript);
    Plonk::verify(&svk, &dk, &protocol, &instances, &proof);

    evm::compile_yul(&loader.yul_code())
}

impl SmartContract for Halo2 {
    type Error = BackendError;
    fn eth_contract_from_vk(
        &self,
        _common_reference_string: &[u8],
        _verification_key: &[u8],
    ) -> Result<String, Self::Error> {
        todo!()
    }
}
