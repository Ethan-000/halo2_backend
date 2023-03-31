use acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use acvm::{FieldElement, OpcodeResolution, OpcodeResolutionError};
use std::collections::BTreeMap;

pub struct BlackBoxFuncCaller;

impl BlackBoxFuncCaller {
    pub fn solve_blackbox_function_call(
        _initial_witness: &mut BTreeMap<Witness, FieldElement>,
        gadget_call: &BlackBoxFuncCall,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
            gadget_call.name,
        ))
    }
}
