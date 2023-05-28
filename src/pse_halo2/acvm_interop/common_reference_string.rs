use acvm::{acir::circuit::Circuit, async_trait, CommonReferenceString, ProofSystemCompiler};

use crate::errors::BackendError;
use crate::pse_halo2::halo2_params::constuct_halo2_params_from_aztec_crs;
use crate::pse_halo2::PseHalo2;

// TODO(#185): Ensure CRS download works in JS
#[async_trait]
impl CommonReferenceString for PseHalo2 {
    type Error = BackendError;

    async fn generate_common_reference_string(
        &self,
        circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut common_reference_string = Vec::new();
        constuct_halo2_params_from_aztec_crs(self.get_exact_circuit_size(circuit)?)
            .await?
            .write_custom(
                &mut common_reference_string,
                pse_halo2_proofs::SerdeFormat::RawBytes,
            )
            .unwrap();
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
        constuct_halo2_params_from_aztec_crs(self.get_exact_circuit_size(circuit)?)
            .await?
            .write_custom(
                &mut common_reference_string,
                pse_halo2_proofs::SerdeFormat::RawBytes,
            )
            .unwrap();

        Ok(common_reference_string)
    }
}
