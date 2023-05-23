use acvm::SmartContract;

use crate::errors::BackendError;

use super::Halo2;

impl SmartContract for Halo2 {
    fn eth_contract_from_vk(&self, _verification_key: &[u8]) -> Result<String, BackendError> {
        todo!()
    }

    type Error = BackendError;
}
