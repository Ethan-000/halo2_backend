use acvm::acir::native_types::Witness;
use acvm::OpcodeResolutionError;
use acvm::{PartialWitnessGenerator};

mod gadget_call;

use super::Halo2;

impl PartialWitnessGenerator for Halo2 {

    fn aes(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        inputs: &[acvm::acir::circuit::opcodes::FunctionInput],
        outputs: &[Witness],
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn and(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        lhs: &acvm::acir::circuit::opcodes::FunctionInput,
        rhs: &acvm::acir::circuit::opcodes::FunctionInput,
        output: &Witness,
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn xor(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        lhs: &acvm::acir::circuit::opcodes::FunctionInput,
        rhs: &acvm::acir::circuit::opcodes::FunctionInput,
        output: &Witness,
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn range(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        input: &acvm::acir::circuit::opcodes::FunctionInput,
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn sha256(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        inputs: &[acvm::acir::circuit::opcodes::FunctionInput],
        outputs: &[Witness],
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn blake2s(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        inputs: &[acvm::acir::circuit::opcodes::FunctionInput],
        outputs: &[Witness],
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn compute_merkle_root(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        leaf: &acvm::acir::circuit::opcodes::FunctionInput,
        index: &acvm::acir::circuit::opcodes::FunctionInput,
        hash_path: &[acvm::acir::circuit::opcodes::FunctionInput],
        output: &Witness,
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn schnorr_verify(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        public_key_x: &acvm::acir::circuit::opcodes::FunctionInput,
        public_key_y: &acvm::acir::circuit::opcodes::FunctionInput,
        signature: &[acvm::acir::circuit::opcodes::FunctionInput],
        message: &[acvm::acir::circuit::opcodes::FunctionInput],
        output: &Witness,
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn pedersen(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        inputs: &[acvm::acir::circuit::opcodes::FunctionInput],
        outputs: &[Witness],
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn hash_to_field_128_security(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        inputs: &[acvm::acir::circuit::opcodes::FunctionInput],
        outputs: &Witness,
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn ecdsa_secp256k1(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        public_key_x: &[acvm::acir::circuit::opcodes::FunctionInput],
        public_key_y: &[acvm::acir::circuit::opcodes::FunctionInput],
        signature: &[acvm::acir::circuit::opcodes::FunctionInput],
        message: &[acvm::acir::circuit::opcodes::FunctionInput],
        outputs: &Witness,
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn fixed_base_scalar_mul(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        input: &acvm::acir::circuit::opcodes::FunctionInput,
        outputs: &[Witness],
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }

    fn keccak256(
        &self,
        initial_witness: &mut acvm::acir::native_types::WitnessMap,
        inputs: &[acvm::acir::circuit::opcodes::FunctionInput],
        outputs: &[Witness],
    ) -> Result<acvm::pwg::OpcodeResolution, OpcodeResolutionError> {
        todo!()
    }
}
