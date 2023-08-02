use crate::{
    circuit_translator::NoirHalo2Translator,
    dimension_measure::DimensionMeasurement,
    halo2_plonk_api::{halo2_keygen, halo2_prove, halo2_verify, OpcodeFlags},
    PseHalo2,
};
use acvm::{
    acir::{
        circuit::{Circuit as NoirCircuit, Opcode},
        native_types::WitnessMap,
        BlackBoxFunc,
    },
    FieldElement, Language, ProofSystemCompiler,
};
use noir_halo2_backend_common::{errors::BackendError, noir_field_to_halo2_field};
use pse_halo2wrong::halo2::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use std::marker::PhantomData;

impl ProofSystemCompiler for PseHalo2 {
    type Error = BackendError;

    /// Get the size of the circuit
    fn get_exact_circuit_size(&self, circuit: &NoirCircuit) -> Result<u32, BackendError> {
        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values: WitnessMap::new(),
            _marker: PhantomData::<Fr>,
        };

        let dimension = DimensionMeasurement::measure(&translator).unwrap();
        let k = dimension.k();

        Ok(1 << k)
    }

    /// Preprocess the circuit to get
    /// Proving Key and Verifying Key
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

        Ok((pk.to_bytes(SerdeFormat::RawBytes), vk.to_bytes(SerdeFormat::RawBytes)))
    }

    /// Generate proof with Proving Key
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

        let opcode_flags = OpcodeFlags::new(&circuit.opcodes);

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

    /// Verify proof with Verification Key
    fn verify_with_vk(
        &self,
        mut common_reference_string: &[u8],
        proof: &[u8],
        public_inputs: WitnessMap,
        circuit: &NoirCircuit,
        verification_key: &[u8],
        _is_recursive: bool,
    ) -> Result<bool, BackendError> {
        let params =
            ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes)
                .unwrap();

        let opcode_flags = OpcodeFlags::new(&circuit.opcodes);

        let vk = VerifyingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            verification_key,
            SerdeFormat::RawBytes,
            opcode_flags,
        )
        .unwrap();

        let instance: Vec<Fr> =
            public_inputs.into_iter().map(|(_, el)| noir_field_to_halo2_field(el)).collect();

        Ok(halo2_verify(&params, &vk, proof, &instance[..]).is_ok())
    }

    /// Type of constraint system
    // The pse-halo2 backend supports Plonkish constraint
    // of width 5 but we only used 3
    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    /// Opcodes supported by pse-halo2 backend
    fn supports_opcode(&self, opcode: &acvm::acir::circuit::Opcode) -> bool {
        match opcode {
            Opcode::Arithmetic(_) => true,
            Opcode::Directive(_) | Opcode::Brillig(_) => true,
            Opcode::BlackBoxFuncCall(func) => match func.get_black_box_func() {
                BlackBoxFunc::RANGE | BlackBoxFunc::AND => true,
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
            Opcode::Block(_) | Opcode::ROM(_) | Opcode::RAM(_) => false
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
