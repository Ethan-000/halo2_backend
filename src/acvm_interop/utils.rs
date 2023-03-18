use halo2_proofs_axiom::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};

use rand::rngs::OsRng;

fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(k, OsRng)
}
