use acvm::{acir::circuit::Circuit, async_trait, CommonReferenceString, ProofSystemCompiler};

use crate::axiom_halo2::halo2_params::constuct_halo2_params_from_aztec_crs;
use crate::axiom_halo2::AxiomHalo2;
use crate::errors::BackendError;

// TODO(#185): Ensure CRS download works in JS
#[async_trait]
impl CommonReferenceString for AxiomHalo2 {
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
                halo2_base::halo2_proofs::SerdeFormat::RawBytes,
            );
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
                halo2_base::halo2_proofs::SerdeFormat::RawBytes,
            );

        Ok(common_reference_string)
    }
}
