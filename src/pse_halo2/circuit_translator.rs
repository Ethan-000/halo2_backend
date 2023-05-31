use core::panic;
use std::marker::PhantomData;

use crate::{pse_halo2::halo2_plonk_api::PlonkConfig};
use acvm::acir::{
    circuit::{opcodes::BlackBoxFuncCall, Circuit as NoirCircuit, Opcode},
    native_types::WitnessMap,
};

use pse_halo2wrong::{
    halo2::{
        circuit::SimpleFloorPlanner, halo2curves::bn256::Fr, plonk::Circuit as Halo2PlonkCircuit,
        plonk::ConstraintSystem,
    },
};
use pse_maingate::{RangeChip, RangeInstructions};

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
                            // let ecc_chip = GeneralEccChip::<Secp256k1Affine, Fr, 4, 68>::new(
                            //     config.ecc_config.clone(),
                            // );

                            // // public key x
                            // let mut public_key_x_inputs = public_key_x_inputs.iter();
                            // let mut public_key_x = Vec::new();
                            // for (i, pkx) in public_key_x.iter_mut().enumerate() {
                            //     let x_byte = public_key_x_inputs
                            //         .next()
                            //         .ok_or_else(|| Error::MalformedBlackBoxFunc(
                            //             BlackBoxFunc::EcdsaSecp256k1,
                            //             format!("Missing rest of `x` component for public key. Tried to get byte {i} but failed"),
                            //         )).unwrap();
                            //     let x_byte_index = x_byte.witness;
                            //     *pkx = x_byte_index;
                            // }

                            // // public key y
                            // let mut public_key_y_inputs = public_key_y_inputs.iter();
                            // let mut public_key_y = Vec::new();
                            // for (i, pky) in public_key_y.iter_mut().enumerate() {
                            //     let y_byte = public_key_y_inputs
                            //         .next()
                            //         .ok_or_else(|| Error::MalformedBlackBoxFunc(
                            //             BlackBoxFunc::EcdsaSecp256k1,
                            //             format!("Missing rest of `y` component for public key. Tried to get byte {i} but failed"),
                            //         )).unwrap();
                            //     let y_byte_index = y_byte.witness;
                            //     *pky = y_byte_index;
                            // }

                            // // signature
                            // let mut signature_inputs = signature_inputs.iter();
                            // let mut signature = Vec::new();
                            // for (i, sig) in signature.iter_mut().enumerate() {
                            //     let sig_byte =
                            //         signature_inputs.next().ok_or_else(|| Error::MalformedBlackBoxFunc(
                            //             BlackBoxFunc::EcdsaSecp256k1,
                            //             format!("Missing rest of signature. Tried to get byte {i} but failed"),
                            //         )).unwrap();
                            //     let sig_byte_index = sig_byte.witness;
                            //     *sig = sig_byte_index;
                            // }

                            // // The rest of the input is the message
                            // let mut hashed_message = Vec::new();
                            // for msg in hashed_message_inputs.iter() {
                            //     let msg_byte_index = msg.witness;
                            //     hashed_message.push(msg_byte_index);
                            // }

                            // self.add_ecdsa_secp256k1_constrain(
                            //     hashed_message,
                            //     signature,
                            //     public_key_x,
                            //     public_key_y,
                            //     &mut layouter,
                            //     ecc_chip,
                            // )?;
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
                Opcode::Block(_) => {
                    // Block is managed by ACVM
                }
                Opcode::RAM(_) | Opcode::ROM(_) => {
                    todo!()
                }
            }
        }

        range_chip.load_table(&mut layouter)?;
        Ok(())
    }
}
