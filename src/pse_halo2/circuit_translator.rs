use core::{panic};
use std::marker::PhantomData;

use crate::{pse_halo2::halo2_plonk_api::PlonkConfig};
use acvm::acir::{
    circuit::{opcodes::BlackBoxFuncCall, Circuit as NoirCircuit, Opcode},
    native_types::WitnessMap,
};

use pse_ecc::GeneralEccChip;
use pse_halo2wrong::{
    curves::secp256k1::Secp256k1Affine,
    halo2::{
        circuit::SimpleFloorPlanner, halo2curves::bn256::Fr, plonk::Circuit as Halo2PlonkCircuit,
        plonk::ConstraintSystem,
    },
};
use pse_maingate::{RangeChip, RangeInstructions};

use super::halo2_plonk_api::OpcodeFlags;

#[derive(Clone, Default)]
pub struct NoirHalo2Translator<Fr> {
    pub circuit: NoirCircuit,
    pub witness_values: WitnessMap,
    pub _marker: PhantomData<Fr>,
}

impl Halo2PlonkCircuit<Fr> for NoirHalo2Translator<Fr> {
    type Config = PlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = OpcodeFlags;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn params(&self) -> Self::Params {
        Self::Params::default()
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        opcode_flags: Self::Params,
    ) -> Self::Config {
        PlonkConfig::configure_with_params(meta, opcode_flags)
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> PlonkConfig {
        PlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl pse_halo2wrong::halo2::circuit::Layouter<Fr>,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        let range_chip = RangeChip::<Fr>::new(config.range_config.clone());
        for gate in self.circuit.opcodes.iter() {
            match gate {
                Opcode::Arithmetic(expression) => {
                    self.add_arithmetic_constrains(expression, &config, &mut layouter)?;
                }
                Opcode::BlackBoxFuncCall(gadget_call) => {
                    match gadget_call {
                        BlackBoxFuncCall::RANGE { input } => self.add_range_constrain(
                            input.witness,
                            input.num_bits,
                            &range_chip,
                            &mut layouter,
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
                                )?,
                                BlackBoxFuncCall::XOR { .. } => {
                                    panic!("xor has not yet been implemented")
                                }
                                _ => unreachable!("expected either an AND or XOR opcode"),
                            }
                        }
                        BlackBoxFuncCall::SHA256 { inputs, outputs } => {
                            let mut sha256_inputs = Vec::new();
                            for input in inputs.iter() {
                                let witness = input.witness;
                                let num_bits = input.num_bits;
                                sha256_inputs.push((witness, num_bits));
                            }

                            assert_eq!(outputs.len(), 32);

                            self.add_sha256_constrain(
                                sha256_inputs,
                                outputs.to_vec(),
                                &config,
                                &mut layouter,
                            )?
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
                            public_key_x: public_key_x_inputs,
                            public_key_y: public_key_y_inputs,
                            signature: signature_inputs,
                            hashed_message: hashed_message_inputs,
                            output: _,
                        } => {
                            match config.ecc_config {
                                Some(ref ecc_config) => {
                                    let ecc_chip =
                                        GeneralEccChip::<Secp256k1Affine, Fr, 4, 68>::new(
                                            ecc_config.clone(),
                                        );
                                    // public key x
                                    let public_key_x =
                                        public_key_x_inputs.iter().map(|x| x.witness).collect();

                                    // public key y
                                    let public_key_y =
                                        public_key_y_inputs.iter().map(|y| y.witness).collect();

                                    // signature
                                    let signature =
                                        signature_inputs.iter().map(|sig| sig.witness).collect();

                                    // The rest of the input is the message
                                    let hashed_message =
                                        hashed_message_inputs.iter().map(|h| h.witness).collect();

                                    self.add_ecdsa_secp256k1_constrain(
                                        hashed_message,
                                        signature,
                                        public_key_x,
                                        public_key_y,
                                        &mut layouter,
                                        ecc_chip,
                                    )?;
                                }
                                None => unreachable!(),
                            }
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
        Ok(())
    }
}
