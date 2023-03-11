use acvm::acir::circuit::Circuit;

use acvm::SmartContract;

use super::Halo2;

impl SmartContract for Halo2 {
    fn eth_contract_from_cs(&self, _circuit: Circuit) -> String {
        todo!()
    }

    fn eth_contract_from_vk(&self, verification_key: &[u8]) -> String {
        todo!()
    }
}
