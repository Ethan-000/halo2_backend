mod acvm_interop;

mod circuit_translator;
mod constrains;
mod halo2_params;
mod halo2_plonk_api;

#[derive(Debug)]
pub struct ZcashHalo2;

impl ZcashHalo2 {
    pub(crate) fn new() -> ZcashHalo2 {
        ZcashHalo2 {}
    }
}

impl Default for ZcashHalo2 {
    fn default() -> ZcashHalo2 {
        ZcashHalo2::new()
    }
}
