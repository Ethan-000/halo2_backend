#[cfg(feature = "axiom_halo2")]
pub mod axiom_halo2;
#[cfg(any(feature = "axiom_halo2", feature = "pse_halo2"))]
pub mod aztec_crs;
#[cfg(any(feature = "axiom_halo2", feature = "pse_halo2"))]
pub mod dimension_measure;
pub mod errors;
#[cfg(feature = "pse_halo2")]
pub mod pse_halo2;
pub mod utils;

#[cfg(feature = "zcash_halo2")]
mod zcash_halo2;

#[cfg(feature = "axiom_halo2")]
pub use axiom_halo2::AxiomHalo2 as Halo2;
#[cfg(feature = "pse_halo2")]
pub use pse_halo2::PseHalo2 as Halo2;
// TODO:
// zcash not working at the moment, need acir to support pasta curve
#[cfg(feature = "zcash_halo2")]
pub use zcash_halo2::ZcashHalo2 as Halo2;