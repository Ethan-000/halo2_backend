mod common_reference_string;
mod proof_system;
mod pwg;
mod smart_contract;

use crate::ZcashHalo2;
use acvm::Backend;

impl Backend for ZcashHalo2 {}
