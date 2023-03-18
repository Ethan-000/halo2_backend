use std::{collections::BTreeMap, marker::PhantomData};

use crate::acvm_interop::halo2_plonk_api::PlonkConfig;
use acvm::{
    acir::{circuit::Circuit as NoirCircuit, native_types::Witness},
    FieldElement,
};
use halo2_proofs_axiom::{
    circuit::SimpleFloorPlanner, halo2curves::bn256::Fr, plonk::Circuit as Halo2PlonkCircuit,
};

pub struct NoirHalo2Translator<Fr> {
    pub circuit: NoirCircuit,
    pub witness_values: BTreeMap<Witness, FieldElement>,
    _marker: PhantomData<Fr>,
}

impl Halo2PlonkCircuit<Fr> for NoirHalo2Translator<Fr> {
    type Config = PlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut halo2_proofs_axiom::plonk::ConstraintSystem<Fr>) -> Self::Config {
        todo!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl halo2_proofs_axiom::circuit::Layouter<Fr>,
    ) -> Result<(), halo2_proofs_axiom::plonk::Error> {
        todo!()
    }
}
