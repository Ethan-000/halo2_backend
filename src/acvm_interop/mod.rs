use crate::Halo2;
use acvm::Backend;

mod common_reference_string;
mod proof_system;
pub mod pwg;
mod smart_contract;

impl Backend for Halo2 {}
