use crate::{
    circuit_translator::NoirHalo2Translator,
    halo2_plonk_api::{halo2_keygen, halo2_prove, halo2_verify},
};
use acvm::{
    acir::{
        circuit::{Circuit as NoirCircuit, Opcode},
        native_types::WitnessMap,
        BlackBoxFunc,
    },
    FieldElement, Language, ProofSystemCompiler,
};
use noir_halo2_backend_common::errors::BackendError;
use std::marker::PhantomData;
use zcash_halo2_proofs::{
    pasta::{EqAffine, Fp},
    poly::commitment::Params,
};

use crate::ZcashHalo2;

impl ProofSystemCompiler for ZcashHalo2 {
    type Error = BackendError;

    fn get_exact_circuit_size(&self, circuit: &NoirCircuit) -> Result<u32, BackendError> {
        Ok(circuit.opcodes.len() as u32)
    }

    fn preprocess(
        &self,
        mut common_reference_string: &[u8],
        circuit: &NoirCircuit,
    ) -> Result<(Vec<u8>, Vec<u8>), BackendError> {
        let translator = NoirHalo2Translator::<Fp> {
            circuit: circuit.clone(),
            witness_values: WitnessMap::new(),
            _marker: PhantomData::<Fp>,
        };

        let params = Params::<EqAffine>::read(&mut common_reference_string).unwrap();
        let (_pk, _vk) = halo2_keygen(&translator, &params);

        // can't serialize pk vk to bytes
        Ok((Vec::new(), Vec::new()))
    }

    fn prove_with_pk(
        &self,
        mut common_reference_string: &[u8],
        circuit: &NoirCircuit,
        witness_values: WitnessMap,
        _proving_key: &[u8],
        _is_recursive: bool,
    ) -> Result<Vec<u8>, BackendError> {
        let translator = NoirHalo2Translator::<Fp> {
            circuit: circuit.clone(),
            witness_values,
            _marker: PhantomData::<Fp>,
        };

        let params = Params::<EqAffine>::read(&mut common_reference_string).unwrap();

        let (pk, _vk) = halo2_keygen(&translator, &params);

        let proof = halo2_prove(translator, &params, &pk);

        Ok(proof)
    }

    fn verify_with_vk(
        &self,
        mut common_reference_string: &[u8],
        proof: &[u8],
        public_inputs: WitnessMap,
        circuit: &NoirCircuit,
        _verification_key: &[u8],
        _is_recursive: bool,
    ) -> Result<bool, BackendError> {
        let translator = NoirHalo2Translator::<Fp> {
            circuit: circuit.clone(),
            witness_values: public_inputs,
            _marker: PhantomData::<Fp>,
        };

        let params = Params::<EqAffine>::read(&mut common_reference_string).unwrap();

        let (_, vk) = halo2_keygen(&translator, &params);

        Ok(halo2_verify(&params, &vk, proof).is_ok())
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn supports_opcode(&self, opcode: &acvm::acir::circuit::Opcode) -> bool {
        match opcode {
            Opcode::Arithmetic(_) => true,
            Opcode::Directive(_) => false,
            Opcode::Block(_) => false,
            Opcode::ROM(_) => false,
            Opcode::RAM(_) => false,
            Opcode::Oracle(_) => false,
            Opcode::BlackBoxFuncCall(func) => match func.get_black_box_func() {
                BlackBoxFunc::AND | BlackBoxFunc::RANGE => true,

                BlackBoxFunc::XOR
                | BlackBoxFunc::SHA256
                | BlackBoxFunc::Blake2s
                | BlackBoxFunc::Pedersen
                | BlackBoxFunc::HashToField128Security
                | BlackBoxFunc::EcdsaSecp256k1
                | BlackBoxFunc::Keccak256
                | BlackBoxFunc::FixedBaseScalarMul
                | BlackBoxFunc::RecursiveAggregation
                | BlackBoxFunc::SchnorrVerify => false,
            },
            Opcode::Brillig(_) => todo!(),
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
