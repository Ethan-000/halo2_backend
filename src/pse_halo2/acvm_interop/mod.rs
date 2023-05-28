use crate::pse_halo2::PseHalo2;
use acvm::Backend;

mod common_reference_string;
mod proof_system;
mod pwg;
mod smart_contract;

impl Backend for PseHalo2 {}
