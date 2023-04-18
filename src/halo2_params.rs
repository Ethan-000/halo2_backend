use crate::aztec_crs::get_aztec_crs;
use ark_std::log2;
use halo2_proofs_axiom::{
    arithmetic::g_to_lagrange,
    halo2curves::{
        bn256::{Bn256, Fq, Fq2, G1Affine, G2Affine},
        group::prime::PrimeCurveAffine,
        pairing::Engine,
        CurveAffine,
    },
    poly::kzg::commitment::ParamsKZG,
};

pub(crate) fn constuct_halo2_params_from_aztec_crs(num_points: u32) -> ParamsKZG<Bn256> {
    let points_needed = pow2ceil(num_points);
    let (g1_data, g2_data) = get_aztec_crs(points_needed);

    let k = log2(points_needed as usize);
    let n = points_needed as u64;

    let mut g = vec![<<Bn256 as Engine>::G1Affine as PrimeCurveAffine>::generator()];

    g.extend(g1_data.chunks(64).map(|g1| to_g1_point(g1)));

    let g_lagrange = g_to_lagrange(g.iter().map(|g| PrimeCurveAffine::to_curve(g)).collect(), k);

    let g2 = <<Bn256 as Engine>::G2Affine as PrimeCurveAffine>::generator();
    let s_g2 = to_g2_point(&g2_data);

    // WARNING: currently the fields of ParamsKZG are private
    // and there's no consturctor from these fields,
    // so I changed my local version of these fields to public.
    ParamsKZG::<Bn256> {
        k,
        n,
        g,
        g_lagrange,
        g2,
        s_g2,
    }
}

fn to_g1_point(point: &[u8]) -> G1Affine {
    let le_bytes: Vec<u8> = point
        .chunks(8)
        .map(|limb| {
            let mut new_limb = limb.to_vec();
            new_limb.reverse();
            new_limb
        })
        .flatten()
        .collect();

    let mut first_byte_array = [0u8; 32];
    let mut second_byte_array = [0u8; 32];

    for i in 0..le_bytes.len() {
        if i < 32 {
            first_byte_array[i] = le_bytes[i]
        } else {
            second_byte_array[i - 32] = le_bytes[i]
        }
    }

    G1Affine::from_xy(
        Fq::from_bytes(&first_byte_array).unwrap(),
        Fq::from_bytes(&second_byte_array).unwrap(),
    )
    .unwrap()
}

fn to_g2_point(point: &[u8]) -> G2Affine {
    let le_bytes: Vec<u8> = point
        .chunks(8)
        .map(|limb| {
            let mut new_limb = limb.to_vec();
            new_limb.reverse();
            new_limb
        })
        .flatten()
        .collect();

    let mut first_byte_array = [0u8; 64];
    let mut second_byte_array = [0u8; 64];

    for i in 0..le_bytes.len() {
        if i < 64 {
            first_byte_array[i] = le_bytes[i]
        } else {
            second_byte_array[i - 64] = le_bytes[i]
        }
    }

    G2Affine::from_xy(
        Fq2::from_bytes(&first_byte_array).unwrap(),
        Fq2::from_bytes(&second_byte_array).unwrap(),
    )
    .unwrap()
}

fn pow2ceil(v: u32) -> u32 {
    v.next_power_of_two()
}
