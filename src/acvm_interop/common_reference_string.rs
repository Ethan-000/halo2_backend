use acvm::ProofSystemCompiler;
use acvm::{acir::circuit::Circuit, async_trait, CommonReferenceString};

use crate::errors::BackendError;
use crate::halo2_params::constuct_halo2_params_from_aztec_crs;
use crate::Halo2;

// TODO(#185): Ensure CRS download works in JS
#[async_trait]
impl CommonReferenceString for Halo2 {
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
                halo2_proofs_axiom::SerdeFormat::RawBytes,
            );
        // Separated to have nicer coercion on error types
        Ok(common_reference_string)
    }

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
                halo2_proofs_axiom::SerdeFormat::RawBytes,
            );

        // TODO: Implement this
        // Separated to have nicer coercion on error types
        Ok(common_reference_string)
    }
}
