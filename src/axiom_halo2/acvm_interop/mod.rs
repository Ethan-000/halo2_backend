use crate::axiom_halo2::AxiomHalo2;
use acvm::Backend;

mod common_reference_string;
mod proof_system;
mod pwg;
mod smart_contract;

impl Backend for AxiomHalo2 {}
