use acvm::SmartContract;
use noir_halo2_backend_common::errors::BackendError;

use crate::ZcashHalo2;

impl SmartContract for ZcashHalo2 {
    type Error = BackendError;
    fn eth_contract_from_vk(
        &self,
        _common_reference_string: &[u8],
        _verification_key: &[u8],
    ) -> Result<String, Self::Error> {
        panic!("ethereum solidity verifier not supported for halo2-ipa")
    }
}
