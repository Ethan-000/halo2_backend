#![feature(allocator_api)]

#[cfg(feature = "axiom_halo2")]
mod axiom_halo2;
#[cfg(any(feature = "axiom_halo2", feature = "pse_halo2"))]
mod aztec_crs;
mod dimension_measure;
mod errors;
#[cfg(feature = "pse_halo2")]
mod pse_halo2;
mod utils;
mod cell_map;
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
