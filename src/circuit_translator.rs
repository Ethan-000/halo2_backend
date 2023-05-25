use std::marker::PhantomData;

use crate::halo2_plonk_api::{PlonkConfig, StandardPlonk};
use acvm::acir::{
    circuit::{opcodes::BlackBoxFuncCall, Circuit as NoirCircuit, Opcode},
    native_types::WitnessMap,
};
use halo2_proofs_axiom::{
    circuit::SimpleFloorPlanner, halo2curves::bn256::Fr, plonk::Circuit as Halo2PlonkCircuit,
    plonk::ConstraintSystem,
};

#[derive(Clone, Default)]
pub struct NoirHalo2Translator<Fr> {
    pub circuit: NoirCircuit,
    pub witness_values: WitnessMap,
    pub _marker: PhantomData<Fr>,
}

impl Halo2PlonkCircuit<Fr> for NoirHalo2Translator<Fr> {
    type Config = PlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> PlonkConfig {
        meta.set_minimum_degree(5);

        PlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs_axiom::circuit::Layouter<Fr>,
    ) -> Result<(), halo2_proofs_axiom::plonk::Error> {
        let cs: StandardPlonk<Fr> = StandardPlonk::new(config.clone());
        for gate in self.circuit.opcodes.iter() {
            match gate {
                Opcode::Arithmetic(expression) => {
                    self.add_arithmetic_constrains(expression, &cs, &mut layouter)
                }
                Opcode::BlackBoxFuncCall(gadget_call) => {
                    match gadget_call {
                        BlackBoxFuncCall::RANGE { input } => {
                            self.add_range_constrain(input.witness, input.num_bits, &config)
                        }
                        BlackBoxFuncCall::AND { lhs, rhs, output: _ }
                        | BlackBoxFuncCall::XOR { lhs, rhs, output: _ } => {
                            let _witness_lhs = lhs.witness;
                            let _witness_rhs = rhs.witness;

                            assert_eq!(lhs.num_bits, rhs.num_bits);
                        }
                        BlackBoxFuncCall::SHA256 { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::Blake2s { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::SchnorrVerify { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::Pedersen { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::HashToField128Security { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::EcdsaSecp256k1 { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::FixedBaseScalarMul { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::Keccak256 { .. } => {
                            panic!("Keccak256 has not yet been implemented")
                        }
                        BlackBoxFuncCall::AES { .. } => panic!("AES has not yet been implemented"),
                        BlackBoxFuncCall::ComputeMerkleRoot {
                            leaf: _,
                            index: _,
                            hash_path: _,
                            output: _,
                        } => todo!(),
                    };
                }
                Opcode::Directive(_) | Opcode::Oracle(_) => {
                    // Directives are only needed by the pwg
                }
                Opcode::Block(_) | Opcode::RAM(_) | Opcode::ROM(_) => {
                    todo!()
                }
            }
        }
        Ok(())
    }
}
