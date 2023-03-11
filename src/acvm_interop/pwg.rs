use acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use acvm::PartialWitnessGenerator;
use acvm::{FieldElement, OpcodeResolutionError};
use std::collections::BTreeMap;

mod gadget_call;

use self::gadget_call::GadgetCaller;
use super::Halo2;

impl PartialWitnessGenerator for Halo2 {
    fn solve_black_box_function_call(
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        func_call: &BlackBoxFuncCall,
    ) -> Result<(), OpcodeResolutionError> {
        GadgetCaller::solve_blackbox_function_call(initial_witness, func_call)
    }
}
