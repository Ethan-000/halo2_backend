use core::panic;
use std::marker::PhantomData;

use crate::zcash_halo2::halo2_plonk_api::{PlonkConfig, StandardPlonk};
use acvm::acir::{
    circuit::{opcodes::BlackBoxFuncCall, Circuit as NoirCircuit, Opcode},
    native_types::WitnessMap,
};
use zcash_halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    pasta::Fp,
    plonk::Circuit as Halo2PlonkCircuit,
    plonk::ConstraintSystem,
};

#[derive(Clone, Default)]
pub struct NoirHalo2Translator<Fr> {
    pub circuit: NoirCircuit,
    pub witness_values: WitnessMap,
    pub _marker: PhantomData<Fr>,
}

impl Halo2PlonkCircuit<Fp> for NoirHalo2Translator<Fp> {
    type Config = PlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> PlonkConfig {
        meta.set_minimum_degree(5);

        PlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), zcash_halo2_proofs::plonk::Error> {
        let cs: StandardPlonk<Fp> = StandardPlonk::new(config);
        for gate in self.circuit.opcodes.iter() {
            match gate {
                Opcode::Arithmetic(expression) => {
                    self.add_arithmetic_constrains(expression, &cs, &mut layouter)
                }
                Opcode::BlackBoxFuncCall(gadget_call) => {
                    match gadget_call {
                        BlackBoxFuncCall::RANGE { input: _ } => {
                            panic!("range constraint has not yet been implemented")
                        }
                        BlackBoxFuncCall::AND {
                            lhs,
                            rhs,
                            output: _,
                        }
                        | BlackBoxFuncCall::XOR {
                            lhs,
                            rhs,
                            output: _,
                        } => {
                            let _witness_lhs = lhs.witness;
                            let _witness_rhs = rhs.witness;

                            assert_eq!(lhs.num_bits, rhs.num_bits);

                            match gadget_call {
                                BlackBoxFuncCall::AND { .. } => {
                                    panic!("and has not yet been implemented")
                                }
                                BlackBoxFuncCall::XOR { .. } => {
                                    panic!("xor has not yet been implemented")
                                }
                                _ => unreachable!("expected either an AND or XOR opcode"),
                            }
                        }
                        BlackBoxFuncCall::SHA256 { .. } => {
                            panic!("sha256 has not yet been implemented")
                        }
                        BlackBoxFuncCall::Blake2s { .. } => {
                            panic!("blake2s has not yet been implemented")
                        }
                        BlackBoxFuncCall::SchnorrVerify { .. } => {
                            panic!("schnorrverify has not yet been implemented")
                        }
                        BlackBoxFuncCall::Pedersen { .. } => {
                            panic!("pedersen has not yet been implemented")
                        }
                        BlackBoxFuncCall::HashToField128Security { .. } => {
                            panic!("hash to field has not yet been implemented")
                        }
                        BlackBoxFuncCall::EcdsaSecp256k1 {
                            public_key_x: _public_key_x_inputs,
                            public_key_y: _public_key_y_inputs,
                            signature: _signature_inputs,
                            hashed_message: _hashed_message_inputs,
                            output: _,
                        } => {
                            panic!("ecdsa has not yet been implemented")
                        }
                        BlackBoxFuncCall::FixedBaseScalarMul { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::Keccak256 {
                            inputs: _,
                            outputs: _,
                        } => {
                            panic!("keccak256 has not yet been implemented")
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
