use acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use acvm::{FieldElement, OpcodeResolutionError};
use acvm::{OpcodeResolution, PartialWitnessGenerator};
use std::collections::BTreeMap;

mod gadget_call;

use self::gadget_call::BlackBoxFuncCaller;

use super::Halo2;

impl PartialWitnessGenerator for Halo2 {
    fn solve_black_box_function_call(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        func_call: &BlackBoxFuncCall,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        BlackBoxFuncCaller::solve_blackbox_function_call(initial_witness, func_call)
    }
}
