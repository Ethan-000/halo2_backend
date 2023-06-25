mod acvm_interop;

mod assigned_map;
mod circuit_translator;
mod constrains;
mod halo2_params;
mod halo2_plonk_api;
mod tests;

#[derive(Debug)]
pub struct AxiomHalo2;

impl AxiomHalo2 {
    pub(crate) fn new() -> AxiomHalo2 {
        AxiomHalo2 {}
    }
}

impl Default for AxiomHalo2 {
    fn default() -> AxiomHalo2 {
        AxiomHalo2::new()
    }
}
