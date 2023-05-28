use acvm::{acir::circuit::Circuit, async_trait, CommonReferenceString, ProofSystemCompiler};
use zcash_halo2_proofs::pasta::EqAffine;
use zcash_halo2_proofs::poly::commitment::Params;

use crate::errors::BackendError;
use crate::zcash_halo2::halo2_params::constuct_halo2_ipa_params;
use crate::zcash_halo2::ZcashHalo2;

// TODO(#185): Ensure CRS download works in JS
#[async_trait]
impl CommonReferenceString for ZcashHalo2 {
    type Error = BackendError;

    async fn generate_common_reference_string(
        &self,
        circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut common_reference_string = Vec::new();
        let params: Params<EqAffine> =
            constuct_halo2_ipa_params(self.get_exact_circuit_size(circuit)?)?;
        params.write(&mut common_reference_string).unwrap();
        // Separated to have nicer coercion on error types
        Ok(common_reference_string)
    }

    // Separated to have nicer coercion on error types
    async fn update_common_reference_string(
        &self,
        _common_reference_string: Vec<u8>,
        circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut common_reference_string = Vec::new();
        let params: Params<EqAffine> =
            constuct_halo2_ipa_params(self.get_exact_circuit_size(circuit)?)?;
        params.write(&mut common_reference_string).unwrap();

        Ok(common_reference_string)
    }
}
