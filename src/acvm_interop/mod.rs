use acvm::Backend;

mod circuit_translator;
mod halo2_plonk_api;
mod proof_system;
pub mod pwg;
mod smart_contract;

pub struct Halo2;
mod utils;

impl Backend for Halo2 {}
