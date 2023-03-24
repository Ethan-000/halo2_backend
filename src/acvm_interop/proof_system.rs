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
use rand::rngs::OsRng;

use crate::circuit_translator::NoirHalo2Translator;
use crate::halo2_plonk_api::{keygen, prover, verifier};

use super::Halo2;

impl ProofSystemCompiler for Halo2 {
    fn get_exact_circuit_size(&self, _: &NoirCircuit) -> u32 {
        todo!()
    }

    fn preprocess(&self, circuit: &NoirCircuit) -> (Vec<u8>, Vec<u8>) {
        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values: BTreeMap::new(),
            _marker: PhantomData::<Fr>,
        };
        let params = ParamsKZG::<Bn256>::setup(10, ark_std::test_rng());
        let (pk, vk) = keygen(&translator, &params);

        let f = File::create("serialization-test.params").unwrap();
        let mut writer = BufWriter::new(f);
        params.write(&mut writer).unwrap();
        writer.flush().unwrap();

        let f = File::create("serialization-test.pk").unwrap();
        let mut writer = BufWriter::new(f);
        pk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
        writer.flush().unwrap();

        let f = File::create("serialization-test.vk").unwrap();
        let mut writer = BufWriter::new(f);
        vk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
        writer.flush().unwrap();

        (
            pk.to_bytes(SerdeFormat::Processed),
            vk.to_bytes(SerdeFormat::Processed),
        )
    }

    fn prove_with_meta(
        &self,
        circuit: NoirCircuit,
        witness_values: BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        let translator = NoirHalo2Translator::<Fr> {
            circuit,
            witness_values,
            _marker: PhantomData::<Fr>,
        };

        let params = ParamsKZG::<Bn256>::setup(1000, OsRng);

        let (pk, vk) = keygen(&translator, &params);
        let proof = prover(translator, &params, &pk);
        assert!(verifier(&params, &vk, &proof).is_ok());
        proof
    }

    fn verify_from_cs(
        &self,
        _proof: &[u8],
        _public_inputs: Vec<FieldElement>,
        _circuit: NoirCircuit,
    ) -> bool {
        todo!()
    }

    fn prove_with_pk(
        &self,
        circuit: &NoirCircuit,
        witness_values: BTreeMap<Witness, FieldElement>,
        _proving_key: &[u8],
    ) -> Vec<u8> {
        let f = File::open("serialization-test.params").unwrap();
        let mut reader = BufReader::new(f);
        let params = ParamsKZG::<Bn256>::read::<_>(&mut reader).unwrap();

        let f = File::open("serialization-test.pk").unwrap();
        let mut reader = BufReader::new(f);
        let pk = ProvingKey::<G1Affine>::read::<_, NoirHalo2Translator<Fr>>(
            &mut reader,
            SerdeFormat::RawBytes,
        )
        .unwrap();

        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values,
            _marker: PhantomData::<Fr>,
        };

        let proof = prover(translator, &params, &pk);

        let f = File::open("serialization-test.vk").unwrap();
        let mut reader = BufReader::new(f);
        let vk = VerifyingKey::<G1Affine>::read::<_, NoirHalo2Translator<Fr>>(
            &mut reader,
            SerdeFormat::RawBytes,
        )
        .unwrap();

        assert!(verifier(&params, &vk, &proof).is_ok());

        proof
    }

    fn verify_with_vk(
        &self,
        proof: &[u8],
        _public_inputs: BTreeMap<Witness, FieldElement>,
        _circuit: &NoirCircuit,
        _verification_key: &[u8],
    ) -> bool {
        let f = File::open("serialization-test.params").unwrap();
        let mut reader = BufReader::new(f);
        let params = ParamsKZG::<Bn256>::read::<_>(&mut reader).unwrap();

        let f = File::open("serialization-test.vk").unwrap();
        let mut reader = BufReader::new(f);
        let vk = VerifyingKey::<G1Affine>::read::<_, NoirHalo2Translator<Fr>>(
            &mut reader,
            SerdeFormat::RawBytes,
        )
        .unwrap();

        verifier(&params, &vk, &proof).is_ok()
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn black_box_function_supported(&self, _opcode: &BlackBoxFunc) -> bool {
        todo!()
    }
}
