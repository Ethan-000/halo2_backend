mod acvm_interop;
mod dimension_measure;
mod assigned_map;
mod circuit_translator;
mod constrains;
mod halo2_params;
mod halo2_plonk_api;
mod tests;
// #[cfg(target_family = "wasm")]
// mod wasm;

#[derive(Debug, Clone)]
pub struct PseHalo2;

impl PseHalo2 {
    pub(crate) fn new() -> PseHalo2 {
        PseHalo2 {}
    }
}

impl Default for PseHalo2 {
    fn default() -> PseHalo2 {
        PseHalo2::new()
    }
}
