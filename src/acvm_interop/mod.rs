use acvm::Backend;

mod proof_system;
pub mod pwg;
mod smart_contract;

#[derive(Debug)]
pub struct Halo2;

impl Backend for Halo2 {}

impl Halo2 {
    pub(crate) fn new() -> Halo2 {
        Halo2 {}
    }
}

impl Default for Halo2 {
    fn default() -> Self {
        Halo2::new()
    }
}