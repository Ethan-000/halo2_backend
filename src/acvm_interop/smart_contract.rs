use acvm::SmartContract;

use crate::errors::BackendError;

use crate::Halo2;

impl SmartContract for Halo2 {
    type Error = BackendError;
    fn eth_contract_from_vk(&self, _common_reference_string: &[u8], _verification_key: &[u8]) -> Result<String,Self::Error> {
        todo!()
    }
}
