use crate::{assigned_map::AssignedMap, halo2_plonk_api::PlonkConfig};
use acvm::acir::{
    circuit::{opcodes::BlackBoxFuncCall, Circuit as NoirCircuit, Opcode},
    native_types::WitnessMap,
    BlackBoxFunc,
};
use core::panic;
use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    halo2curves::bn256::Fr,
    plonk::{Circuit as Halo2PlonkCircuit, ConstraintSystem},
};
use noir_halo2_backend_common::errors::Error;
use std::marker::PhantomData;

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
        _layouter: impl halo2_base::halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), halo2_base::halo2_proofs::plonk::Error> {
        let mut witness_assignments = AssignedMap::<Fr>::new();

        // let cs: StandardPlonk<Fr> = StandardPlonk::new(config.clone());
        for gate in self.circuit.opcodes.iter() {
            match gate {
                Opcode::Arithmetic(expression) => {
                    self.add_arithmetic_constrains(expression, &config, &mut witness_assignments);
                }
                Opcode::BlackBoxFuncCall(gadget_call) => {
                    match gadget_call {
                        BlackBoxFuncCall::RANGE { input } => self.add_range_constrain(
                            input.witness,
                            input.num_bits,
                            &config,
                            &mut witness_assignments,
                        ),
                        BlackBoxFuncCall::AND { lhs, rhs, output }
                        | BlackBoxFuncCall::XOR { lhs, rhs, output } => {
                            assert_eq!(lhs.num_bits, rhs.num_bits);

                            match gadget_call {
                                BlackBoxFuncCall::AND { .. } => self.add_and_constrain(
                                    lhs.witness,
                                    rhs.witness,
                                    *output,
                                    &config,
                                    &mut witness_assignments,
                                ),
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
                            public_key_x: public_key_x_inputs,
                            public_key_y: public_key_y_inputs,
                            signature: signature_inputs,
                            hashed_message: hashed_message_inputs,
                            output,
                        } => {
                            // public key x
                            let mut public_key_x_inputs = public_key_x_inputs.iter();
                            let mut public_key_x = Vec::new();
                            for (i, pkx) in public_key_x.iter_mut().enumerate() {
                                let x_byte = public_key_x_inputs
                                    .next()
                                    .ok_or_else(|| Error::MalformedBlackBoxFunc(
                                        BlackBoxFunc::EcdsaSecp256k1,
                                        format!("Missing rest of `x` component for public key. Tried to get byte {i} but failed"),
                                    )).unwrap();
                                let x_byte_index = x_byte.witness;
                                *pkx = x_byte_index;
                            }

                            // public key y
                            let mut public_key_y_inputs = public_key_y_inputs.iter();
                            let mut public_key_y = Vec::new();
                            for (i, pky) in public_key_y.iter_mut().enumerate() {
                                let y_byte = public_key_y_inputs
                                    .next()
                                    .ok_or_else(|| Error::MalformedBlackBoxFunc(
                                        BlackBoxFunc::EcdsaSecp256k1,
                                        format!("Missing rest of `y` component for public key. Tried to get byte {i} but failed"),
                                    )).unwrap();
                                let y_byte_index = y_byte.witness;
                                *pky = y_byte_index;
                            }

                            // signature
                            let mut signature_inputs = signature_inputs.iter();
                            let mut signature = Vec::new();
                            for (i, sig) in signature.iter_mut().enumerate() {
                                let sig_byte =
                                    signature_inputs.next().ok_or_else(|| Error::MalformedBlackBoxFunc(
                                        BlackBoxFunc::EcdsaSecp256k1,
                                        format!("Missing rest of signature. Tried to get byte {i} but failed"),
                                    )).unwrap();
                                let sig_byte_index = sig_byte.witness;
                                *sig = sig_byte_index;
                            }

                            // The rest of the input is the message
                            let mut hashed_message = Vec::new();
                            for msg in hashed_message_inputs.iter() {
                                let msg_byte_index = msg.witness;
                                hashed_message.push(msg_byte_index);
                            }

                            self.add_ecdsa_secp256k1_constrain(
                                hashed_message,
                                signature,
                                public_key_x,
                                public_key_y,
                                *output,
                                &config,
                            );
                        }
                        BlackBoxFuncCall::EcdsaSecp256r1 { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::FixedBaseScalarMul { .. } => {
                            todo!()
                        }
                        BlackBoxFuncCall::Keccak256 { inputs: _, outputs: _ } => {
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
                Opcode::Directive(_) => {
                    // Directives are only needed by the pwg
                }
                Opcode::MemoryInit { .. } | Opcode::MemoryOp { .. } => todo!(),
                Opcode::Brillig(_) => todo!(),
            }
        }
        Ok(())
    }
}
