use std::marker::PhantomData;

use acvm::acir::circuit::Circuit as NoirCircuit;
use acvm::acir::circuit::Opcode;
use acvm::acir::native_types::WitnessMap;
use acvm::acir::BlackBoxFunc;
use acvm::FieldElement;
use acvm::{Language, ProofSystemCompiler};
use pse_halo2wrong::halo2::halo2curves::bn256::Fr;
use pse_halo2wrong::halo2::halo2curves::bn256::{Bn256, G1Affine};
use pse_halo2wrong::halo2::plonk::{ProvingKey, VerifyingKey};

use pse_halo2wrong::halo2::poly::kzg::commitment::ParamsKZG;
use pse_halo2wrong::halo2::SerdeFormat;

use crate::errors::BackendError;
use crate::pse_halo2::circuit_translator::NoirHalo2Translator;
use crate::pse_halo2::halo2_plonk_api::OpcodeFlags;
use crate::pse_halo2::halo2_plonk_api::{halo2_keygen, halo2_prove, halo2_verify};

use crate::pse_halo2::PseHalo2;

use crate::noir_field_to_halo2_field;

impl ProofSystemCompiler for PseHalo2 {
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
            ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes)
                .unwrap();
        let (pk, vk) = halo2_keygen(&translator, &params);

        Ok((
            pk.to_bytes(SerdeFormat::RawBytes),
            vk.to_bytes(SerdeFormat::RawBytes),
        ))
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
            ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes)
                .unwrap();

        let opcode_flags = OpcodeFlags::new(circuit.opcodes.clone());

        let pk = ProvingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            proving_key,
            SerdeFormat::RawBytes,
            opcode_flags,
        )
        .unwrap();

        let instance: Vec<Fr> = circuit
            .public_inputs()
            .indices()
            .iter()
            .map(|index| match witness_values.get_index(*index) {
                Some(val) => noir_field_to_halo2_field(*val),
                None => noir_field_to_halo2_field(FieldElement::zero()),
            })
            .collect();

        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values,
            _marker: PhantomData::<Fr>,
        };

        let proof = halo2_prove(translator, &params, &pk, &instance[..]);

        Ok(proof)
    }

    fn verify_with_vk(
        &self,
        mut common_reference_string: &[u8],
        proof: &[u8],
        _public_inputs: WitnessMap,
        circuit: &NoirCircuit,
        verification_key: &[u8],
        _is_recursive: bool,
    ) -> Result<bool, BackendError> {
        let params =
            ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes)
                .unwrap();

        let opcode_flags = OpcodeFlags::new(circuit.opcodes.clone());

        let vk = VerifyingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            verification_key,
            SerdeFormat::RawBytes,
            opcode_flags,
        )
        .unwrap();

        let instance: Vec<Fr> = _public_inputs
            .into_iter()
            .map(|(_, el)| noir_field_to_halo2_field(el))
            .collect();

        Ok(halo2_verify(&params, &vk, proof, &instance[..]).is_ok())
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
                BlackBoxFunc::RANGE => true,

                BlackBoxFunc::XOR
                | BlackBoxFunc::AND
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
            Opcode::Brillig(_) => false,
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

noir_field_to_halo2_field!(Fr);
