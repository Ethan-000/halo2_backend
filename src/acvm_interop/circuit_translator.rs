use std::{collections::BTreeMap, marker::PhantomData};

use crate::acvm_interop::halo2_plonk_api::{PlonkConfig, StandardPlonk};
use acvm::{
    acir::{
        circuit::{Circuit as NoirCircuit, Opcode},
        native_types::Witness,
        BlackBoxFunc,
    },
    FieldElement,
};
use halo2_proofs_axiom::{
    circuit::SimpleFloorPlanner, halo2curves::bn256::Fr, plonk::Circuit as Halo2PlonkCircuit,
    plonk::ConstraintSystem,
};

#[derive(Clone, Default)]
pub struct NoirHalo2Translator<Fr> {
    pub circuit: NoirCircuit,
    pub witness_values: BTreeMap<Witness, FieldElement>,
    _marker: PhantomData<Fr>,
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
        layouter: impl halo2_proofs_axiom::circuit::Layouter<Fr>,
    ) -> Result<(), halo2_proofs_axiom::plonk::Error> {
        let cs: StandardPlonk<Fr> = StandardPlonk::new(config);
        for gate in self.circuit.opcodes.iter() {
            match gate {
                Opcode::Arithmetic(expression) => {
                    todo!()
                }
                Opcode::BlackBoxFuncCall(gadget_call) => {
                    match gadget_call.name {
                        BlackBoxFunc::RANGE => {
                            todo!()
                        }
                        BlackBoxFunc::AND | BlackBoxFunc::XOR => {
                            todo!()
                        }
                        BlackBoxFunc::SHA256 => {
                            todo!()
                        }
                        BlackBoxFunc::Blake2s => {
                            todo!()
                        }
                        BlackBoxFunc::MerkleMembership => {
                            todo!()
                        }
                        BlackBoxFunc::SchnorrVerify => {
                            todo!()
                        }
                        BlackBoxFunc::Pedersen => {
                            todo!()
                        }
                        BlackBoxFunc::HashToField128Security => {
                            todo!()
                        }
                        BlackBoxFunc::EcdsaSecp256k1 => {
                            todo!()
                        }
                        BlackBoxFunc::FixedBaseScalarMul => {
                            todo!()
                        }
                        BlackBoxFunc::Keccak256 => panic!("Keccak256 has not yet been implemented"),
                        BlackBoxFunc::AES => panic!("AES has not yet been implemented"),
                    };
                }
                Opcode::Directive(_) => {
                    // Directives are only needed by the pwg
                }
                Opcode::Block(_, _) => {
                    todo!()
                }
            }
        }
        Ok(())
    }
}
