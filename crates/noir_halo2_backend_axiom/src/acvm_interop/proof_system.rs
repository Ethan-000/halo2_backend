use crate::{
    circuit_translator::NoirHalo2Translator,
    halo2_plonk_api::{halo2_keygen, halo2_prove, halo2_verify},
    AxiomHalo2,
};
use acvm::{
    acir::{
        circuit::{Circuit as NoirCircuit, Opcode},
        native_types::WitnessMap,
        BlackBoxFunc,
    },
    FieldElement, Language, ProofSystemCompiler,
};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use noir_halo2_backend_common::errors::BackendError;
use std::marker::PhantomData;

impl ProofSystemCompiler for AxiomHalo2 {
    type Error = BackendError;

    fn get_exact_circuit_size(&self, circuit: &NoirCircuit) -> Result<u32, BackendError> {
        Ok(circuit.opcodes.len() as u32)
    }

    fn preprocess(
        &self,
        mut common_reference_string: &[u8],
        circuit: &NoirCircuit,
    ) -> Result<(Vec<u8>, Vec<u8>), BackendError> {
        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values: WitnessMap::new(),
            _marker: PhantomData::<Fr>,
        };

        let params =
            ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes);
        let (pk, vk) = halo2_keygen(&translator, &params);

        Ok((pk.to_bytes(SerdeFormat::RawBytes), vk.to_bytes(SerdeFormat::RawBytes)))
    }

    fn prove_with_pk(
        &self,
        mut common_reference_string: &[u8],
        circuit: &NoirCircuit,
        witness_values: WitnessMap,
        proving_key: &[u8],
        _is_recursive: bool,
    ) -> Result<Vec<u8>, BackendError> {
        let params =
            ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes);

        let pk = ProvingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            proving_key,
            SerdeFormat::RawBytes,
        )
        .unwrap();

        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values,
            _marker: PhantomData::<Fr>,
        };

        let proof = halo2_prove(translator, &params, &pk);

        Ok(proof)
    }

    fn verify_with_vk(
        &self,
        mut common_reference_string: &[u8],
        proof: &[u8],
        _public_inputs: WitnessMap,
        _circuit: &NoirCircuit,
        verification_key: &[u8],
        _is_recursive: bool,
    ) -> Result<bool, BackendError> {
        let params =
            ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes);

        let vk = VerifyingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            verification_key,
            SerdeFormat::RawBytes,
        )
        .unwrap();

        Ok(halo2_verify(&params, &vk, proof).is_ok())
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn supports_opcode(&self, opcode: &acvm::acir::circuit::Opcode) -> bool {
        match opcode {
            Opcode::Arithmetic(_) => true,
            Opcode::Directive(_) | Opcode::Brillig(_) => true,
            Opcode::BlackBoxFuncCall(func) => match func.get_black_box_func() {
                BlackBoxFunc::AND | BlackBoxFunc::RANGE => true,

                BlackBoxFunc::XOR
                | BlackBoxFunc::SHA256
                | BlackBoxFunc::Blake2s
                | BlackBoxFunc::Pedersen
                | BlackBoxFunc::HashToField128Security
                | BlackBoxFunc::EcdsaSecp256k1
                | BlackBoxFunc::EcdsaSecp256r1
                | BlackBoxFunc::Keccak256
                | BlackBoxFunc::FixedBaseScalarMul
                | BlackBoxFunc::RecursiveAggregation
                | BlackBoxFunc::SchnorrVerify => false,
            },
            Opcode::Block(_) | Opcode::ROM(_) | Opcode::RAM(_) => false,
        }
    }

    fn proof_as_fields(
        &self,
        _proof: &[u8],
        _public_inputs: WitnessMap,
    ) -> Result<Vec<FieldElement>, Self::Error> {
        panic!("vk_as_fields not supported in this backend");
    }

    fn vk_as_fields(
        &self,
        _common_reference_string: &[u8],
        _verification_key: &[u8],
    ) -> Result<(Vec<FieldElement>, FieldElement), Self::Error> {
        panic!("vk_as_fields not supported in this backend");
    }
}
