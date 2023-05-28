use crate::zcash_halo2::ZcashHalo2;
use acvm::Backend;

mod common_reference_string;
mod proof_system;
mod pwg;
mod smart_contract;

impl Backend for ZcashHalo2 {}
