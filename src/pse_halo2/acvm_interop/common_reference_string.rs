use std::marker::PhantomData;

use acvm::acir::native_types::WitnessMap;
use acvm::{acir::circuit::Circuit, async_trait, CommonReferenceString};
use pse_halo2wrong::curves::bn256::Fr;

use crate::errors::BackendError;
use crate::pse_halo2::circuit_translator::NoirHalo2Translator;
use crate::pse_halo2::halo2_params::constuct_halo2_params_from_aztec_crs;
use crate::pse_halo2::PseHalo2;

// TODO(#185): Ensure CRS download works in JS
#[async_trait(?Send)]
impl CommonReferenceString for PseHalo2 {
    type Error = BackendError;

    async fn generate_common_reference_string(
        &self,
        circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut common_reference_string = Vec::new();

        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values: WitnessMap::new(),
            _marker: PhantomData::<Fr>,
        };
        constuct_halo2_params_from_aztec_crs(translator)
            .await?
            .write_custom(
                &mut common_reference_string,
                pse_halo2wrong::halo2::SerdeFormat::RawBytes,
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

        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values: WitnessMap::new(),
            _marker: PhantomData::<Fr>,
        };
        constuct_halo2_params_from_aztec_crs(translator)
            .await?
            .write_custom(
                &mut common_reference_string,
                pse_halo2wrong::halo2::SerdeFormat::RawBytes,
            )
            .unwrap();

        Ok(common_reference_string)
    }
}
