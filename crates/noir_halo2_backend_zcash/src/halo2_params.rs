use noir_halo2_backend_common::errors::Error;
use zcash_halo2_proofs::{pasta::EqAffine, poly::commitment::Params};

pub(crate) fn constuct_halo2_ipa_params(num_points: u32) -> Result<Params<EqAffine>, Error> {
    Ok(Params::new(num_points))
}
