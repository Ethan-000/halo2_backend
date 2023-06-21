use core::panic;
use std::marker::PhantomData;

use crate::{
    pse_halo2::{assigned_map::AssignedMap, halo2_plonk_api::PlonkConfig}
};
use acvm::acir::{
    circuit::{opcodes::BlackBoxFuncCall, Circuit as NoirCircuit, Opcode},
    native_types::WitnessMap,
};

use pse_halo2wrong::halo2::{
    circuit::SimpleFloorPlanner, halo2curves::bn256::Fr, plonk::Circuit as Halo2PlonkCircuit,
    plonk::ConstraintSystem,
};
use pse_maingate::{RangeChip, RangeInstructions};

use super::halo2_plonk_api::OpcodeFlags;

/// Concrete Halo2 Circuit
#[derive(Clone, Default, Debug)]
pub struct NoirHalo2Translator<Fr> {
    pub circuit: NoirCircuit,
    pub witness_values: WitnessMap,
    pub _marker: PhantomData<Fr>,
}

impl Halo2PlonkCircuit<Fr> for NoirHalo2Translator<Fr> {
    type Config = PlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = OpcodeFlags;

    /// Get default/empty circuit
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    /// Get opcode flags of which
    /// opcode is used in a circuit instance
    fn params(&self) -> Self::Params {
        OpcodeFlags::new(&self.circuit.opcodes)
    }

    /// Configue the circuit in runtime with
    /// parameters (opcode flags) so that unnecessary
    /// circuits are not configured.
    fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        opcode_flags: Self::Params,
    ) -> Self::Config {
        PlonkConfig::configure_with_params(meta, opcode_flags)
    }

    /// Default configuration of the circuit
    fn configure(meta: &mut ConstraintSystem<Fr>) -> PlonkConfig {
        PlonkConfig::configure(meta)
    }

    /// Synthesize the circuit for Halo2 proving system
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl pse_halo2wrong::halo2::circuit::Layouter<Fr>,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        let mut witness_assignments = AssignedMap::<Fr>::new();
        let range_chip = RangeChip::<Fr>::new(config.range_config.clone());
        for gate in self.circuit.opcodes.iter() {
            match gate {
                Opcode::Arithmetic(expression) => {
                    self.add_arithmetic_constrains(
                        expression,
                        &config,
                        &mut layouter,
                        &mut witness_assignments,
                    )?;
                }
                Opcode::BlackBoxFuncCall(gadget_call) => {
                    match gadget_call {
                        BlackBoxFuncCall::RANGE { input } => self.add_range_constrain(
                            input.witness,
                            input.num_bits,
                            &range_chip,
                            &mut layouter,
                            &mut witness_assignments,
                        )?,
                        BlackBoxFuncCall::AND { lhs, rhs, output }
                        | BlackBoxFuncCall::XOR { lhs, rhs, output } => {
                            assert_eq!(lhs.num_bits, rhs.num_bits);

                            match gadget_call {
                                BlackBoxFuncCall::AND { .. } => self.add_and_constrain(
                                    lhs.witness,
                                    rhs.witness,
                                    *output,
                                    &config,
                                    &mut layouter,
                                    &mut witness_assignments,
                                )?,
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
                        BlackBoxFuncCall::Keccak256VariableLength {
                            inputs: _,
                            var_message_size: _,
                            outputs: _,
                        } => todo!(),
                        BlackBoxFuncCall::RecursiveAggregation {
                            verification_key: _,
                            proof: _,
                            public_inputs: _,
                            key_hash: _,
                            input_aggregation_object: _,
                            output_aggregation_object: _,
                        } => todo!(),
                    };
                }
                Opcode::Directive(_) | Opcode::Oracle(_) => {
                    // Directives are only needed by the pwg
                }
                Opcode::Block(_) => {
                    // Block is managed by ACVM
                }
                Opcode::RAM(_) | Opcode::ROM(_) => {
                    todo!()
                }
                Opcode::Brillig(_) => todo!(),
            }
        }

        range_chip.load_table(&mut layouter)?;

        // synthesize public io
        self.expose_public(&config, &mut layouter, &witness_assignments)?;

        Ok(())
    }
}
