use crate::ZcashHalo2;
use acvm::{acir::native_types::Witness, pwg::OpcodeResolutionError, PartialWitnessGenerator};

impl PartialWitnessGenerator for ZcashHalo2 {
    fn schnorr_verify(
        &self,
        _initial_witness: &mut acvm::acir::native_types::WitnessMap,
        _public_key_x: &acvm::acir::circuit::opcodes::FunctionInput,
        _public_key_y: &acvm::acir::circuit::opcodes::FunctionInput,
        _signature: &[acvm::acir::circuit::opcodes::FunctionInput],
        _message: &[acvm::acir::circuit::opcodes::FunctionInput],
        _output: &Witness,
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn pedersen(
        &self,
        _initial_witness: &mut acvm::acir::native_types::WitnessMap,
        _inputs: &[acvm::acir::circuit::opcodes::FunctionInput],
        _domain_separator: u32,
        _outputs: &[Witness],
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn fixed_base_scalar_mul(
        &self,
        _initial_witness: &mut acvm::acir::native_types::WitnessMap,
        _input: &acvm::acir::circuit::opcodes::FunctionInput,
        _outputs: &[Witness],
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }
}
