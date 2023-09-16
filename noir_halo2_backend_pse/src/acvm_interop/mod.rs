mod common_reference_string;
mod proof_system;
mod pwg;
mod smart_contract;

use crate::PseHalo2;
use acvm::Backend;

impl Backend for PseHalo2 {}
