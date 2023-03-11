use acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use acvm::{FieldElement, OpcodeResolutionError};
use std::collections::BTreeMap;

pub struct GadgetCaller;

impl GadgetCaller {
    pub fn solve_blackbox_function_call(
        _initial_witness: &mut BTreeMap<Witness, FieldElement>,
        gadget_call: &BlackBoxFuncCall,
    ) -> Result<(), OpcodeResolutionError> {
        // XXX: halo2 currently does not implement any of the ACIR opcodes
        // except for arithmetic
        Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
            gadget_call.name,
        ))
    }
}
