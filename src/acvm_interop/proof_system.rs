use std::collections::BTreeMap;

use acvm::acir::{circuit::Circuit as NoirCircuit, native_types::Witness, BlackBoxFunc};
use acvm::{FieldElement, Language, ProofSystemCompiler};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::G1Affine,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Assigned,
        Circuit as Halo2Circuit, Column, ConstraintSystem, Error, Fixed, Instance, ProvingKey,
        VerifyingKey,
    },
};

use super::Halo2;

impl ProofSystemCompiler for Halo2 {
    fn get_exact_circuit_size(&self, _: &NoirCircuit) -> u32 {
        todo!()
    }

    fn preprocess(&self, circuit: &NoirCircuit) -> (Vec<u8>, Vec<u8>) {
        todo!()
    }

    fn prove_with_meta(
        &self,
        circuit: NoirCircuit,
        witness_values: BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        todo!()
    }

    fn verify_from_cs(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: NoirCircuit,
    ) -> bool {
        todo!()
    }

    fn prove_with_pk(
        &self,
        circuit: &NoirCircuit,
        witness_values: BTreeMap<Witness, FieldElement>,
        proving_key: &[u8],
    ) -> Vec<u8> {
        todo!()
    }

    fn verify_with_vk(
        &self,
        proof: &[u8],
        public_inputs: BTreeMap<Witness, FieldElement>,
        circuit: &NoirCircuit,
        verification_key: &[u8],
    ) -> bool {
        todo!()
    }

    fn np_language(&self) -> Language {
        todo!()
    }

    fn black_box_function_supported(&self, opcode: &BlackBoxFunc) -> bool {
        todo!()
    }
}
