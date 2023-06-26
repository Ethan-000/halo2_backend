mod acvm_interop;
mod dimension_measure;

mod assigned_map;
mod circuit_translator;
mod constrains;
mod halo2_params;
mod halo2_plonk_api;
mod tests;
mod wasm;

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
