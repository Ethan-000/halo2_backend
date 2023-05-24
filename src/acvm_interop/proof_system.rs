
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::marker::PhantomData;

use acvm::acir::native_types::WitnessMap;
use acvm::acir::{circuit::Circuit as NoirCircuit};
use acvm::{Language, ProofSystemCompiler};
use halo2_proofs_axiom::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs_axiom::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs_axiom::poly::commitment::Params;
use halo2_proofs_axiom::poly::kzg::commitment::ParamsKZG;
use halo2_proofs_axiom::SerdeFormat;

use crate::circuit_translator::NoirHalo2Translator;
use crate::halo2_plonk_api::{keygen, prover, verifier};
use crate::errors::BackendError;

use crate::Halo2;

impl ProofSystemCompiler for Halo2 {
    type Error = BackendError;

    fn get_exact_circuit_size(&self, circuit: &NoirCircuit) -> Result<u32, BackendError> {
        Ok(circuit.opcodes.len() as u32)
    }

    fn preprocess(&self, mut common_reference_string: &[u8], circuit: &NoirCircuit) -> Result<(Vec<u8>, Vec<u8>), BackendError> {
        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values: WitnessMap::new(),
            _marker: PhantomData::<Fr>,
        };

        let params = ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes);
        let (pk, vk) = keygen(&translator, &params);

        let f = File::create("target/halo2_kzg_bn256.params").unwrap();
        let mut writer = BufWriter::new(f);
        params.write(&mut writer).unwrap();
        writer.flush().unwrap();

        Ok((
            pk.to_bytes(SerdeFormat::RawBytes),
            vk.to_bytes(SerdeFormat::RawBytes),
        ))
    }

    fn prove_with_pk(
        &self,
        _common_reference_string: &[u8],
        circuit: &NoirCircuit,
        witness_values: WitnessMap,
        proving_key: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        let f = File::open("target/halo2_kzg_bn256.params").unwrap();
        let mut reader = BufReader::new(f);
        let params = ParamsKZG::<Bn256>::read::<_>(&mut reader).unwrap();

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

        let proof = prover(translator, &params, &pk);

        Ok(proof)
    }

    fn verify_with_vk(
        &self,
        _common_reference_string: &[u8],
        proof: &[u8],
        _public_inputs: WitnessMap,
        _circuit: &NoirCircuit,
        verification_key: &[u8],
    ) -> Result<bool, BackendError> {
        let f = File::open("target/halo2_kzg_bn256.params").unwrap();
        let mut reader = BufReader::new(f);
        let params = ParamsKZG::<Bn256>::read::<_>(&mut reader).unwrap();

        let vk = VerifyingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            verification_key,
            SerdeFormat::RawBytes,
        )
        .unwrap();

        Ok(verifier(&params, &vk, &proof).is_ok())
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn supports_opcode(&self, _opcode: &acvm::acir::circuit::Opcode) -> bool {
        todo!()
    }
}