use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::marker::PhantomData;

use acvm::acir::{circuit::Circuit as NoirCircuit, native_types::Witness, BlackBoxFunc};
use acvm::{FieldElement, Language, ProofSystemCompiler};
use halo2_proofs_axiom::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs_axiom::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs_axiom::poly::commitment::Params;
use halo2_proofs_axiom::poly::kzg::commitment::ParamsKZG;
use halo2_proofs_axiom::SerdeFormat;

use crate::circuit_translator::NoirHalo2Translator;
use crate::halo2_params::constuct_halo2_params_from_aztec_crs;
use crate::halo2_plonk_api::{keygen, prover, verifier};

use super::Halo2;

impl ProofSystemCompiler for Halo2 {
    fn get_exact_circuit_size(&self, circuit: &NoirCircuit) -> u32 {
        circuit.opcodes.len() as u32
    }

    fn preprocess(&self, circuit: &NoirCircuit) -> (Vec<u8>, Vec<u8>) {
        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values: BTreeMap::new(),
            _marker: PhantomData::<Fr>,
        };

        let params = constuct_halo2_params_from_aztec_crs(self.get_exact_circuit_size(circuit));
        let (pk, vk) = keygen(&translator, &params);

        let f = File::create("target/halo2_kzg_bn256.params").unwrap();
        let mut writer = BufWriter::new(f);
        params.write(&mut writer).unwrap();
        writer.flush().unwrap();

        (
            pk.to_bytes(SerdeFormat::RawBytes),
            vk.to_bytes(SerdeFormat::RawBytes),
        )
    }

    fn prove_with_pk(
        &self,
        circuit: &NoirCircuit,
        witness_values: BTreeMap<Witness, FieldElement>,
        proving_key: &[u8],
    ) -> Vec<u8> {
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

        proof
    }

    fn verify_with_vk(
        &self,
        proof: &[u8],
        _public_inputs: BTreeMap<Witness, FieldElement>,
        _circuit: &NoirCircuit,
        verification_key: &[u8],
    ) -> bool {
        let f = File::open("target/halo2_kzg_bn256.params").unwrap();
        let mut reader = BufReader::new(f);
        let params = ParamsKZG::<Bn256>::read::<_>(&mut reader).unwrap();

        let vk = VerifyingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            verification_key,
            SerdeFormat::RawBytes,
        )
        .unwrap();

        verifier(&params, &vk, &proof).is_ok()
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn black_box_function_supported(&self, _opcode: &BlackBoxFunc) -> bool {
        false
    }
}
