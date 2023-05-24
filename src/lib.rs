mod acvm_interop;

mod aztec_crs;
mod circuit_translator;
mod halo2_params;
mod halo2_plonk_api;
mod errors;

#[derive(Debug)]
pub struct Halo2;

impl Halo2 {
    pub(crate) fn new() -> Halo2 {
        Halo2 {}
    }
}

impl Default for Halo2 {
    fn default() -> Halo2 {
        Halo2::new()
    }
}
