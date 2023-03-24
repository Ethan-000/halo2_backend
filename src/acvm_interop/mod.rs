use acvm::Backend;

mod proof_system;
pub mod pwg;
mod smart_contract;

pub struct Halo2;

impl Backend for Halo2 {}
