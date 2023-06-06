use crate::{aztec_crs::get_aztec_crs, dimension_measure::DimensionMeasurement, errors::Error};
use halo2_base::halo2_proofs::{
    arithmetic::g_to_lagrange,
    halo2curves::{
        bn256::{Bn256, Fq, Fq2, Fr, G1Affine, G2Affine},
        group::prime::PrimeCurveAffine,
        pairing::Engine,
        serde::SerdeObject,
        CurveAffine,
    },
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use std::io::Write;

pub(crate) async fn constuct_halo2_params_from_aztec_crs(
    translator: impl halo2_base::halo2_proofs::plonk::Circuit<Fr>,
) -> Result<ParamsKZG<Bn256>, Error> {
    let dimension = DimensionMeasurement::measure(&translator).unwrap();
    let k = dimension.k();
    let n = 1 << k;
    assert!(n == 1 << k);

    let (g1_data, g2_data) = get_aztec_crs(n).await?;

    let mut g = vec![<<Bn256 as Engine>::G1Affine as PrimeCurveAffine>::generator()];

    g.extend(g1_data.chunks(64).map(to_g1_point));

    let g_lagrange = g_to_lagrange(g.iter().map(PrimeCurveAffine::to_curve).collect(), k);

    let g2 = <<Bn256 as Engine>::G2Affine as PrimeCurveAffine>::generator();
    let s_g2 = to_g2_point(&g2_data);

    Ok(params_kzg(k, g, g_lagrange, g2, s_g2))
}

/// Constructs a `ParamsKZG<Bn256>` from its parameters
fn params_kzg(
    k: u32,
    g: Vec<G1Affine>,
    g_lagrange: Vec<G1Affine>,
    g2: G2Affine,
    s_g2: G2Affine,
) -> ParamsKZG<Bn256> {
    // Halo2 doesn't allow us to directly construct a `ParamsKZG` from parameters directly,
    // however it does allow constructing one from a serialized set of parameters.

    // First we serialize all of the parameters into the format expected by Halo2.
    // For format see:
    // https://github.com/axiom-crypto/halo2/blob/475e45f52a0774ceb81304dd6a3a97dddd07662e/halo2_proofs/src/poly/kzg/commitment.rs#L142-L156
    // We're using the equivalent of the `SerdeFormat::RawBytesUnchecked` encoding here.

    let mut buf: Vec<u8> = Vec::new();
    buf.write_all(&k.to_le_bytes()).unwrap();
    for el in g.iter() {
        el.write_raw(&mut buf).unwrap();
    }
    for el in g_lagrange.iter() {
        el.write_raw(&mut buf).unwrap();
    }
    g2.write_raw(&mut buf).unwrap();
    s_g2.write_raw(&mut buf).unwrap();

    // Then we feed it in to be deserialized again!

    ParamsKZG::<Bn256>::read_custom(&mut &buf[..], SerdeFormat::RawBytesUnchecked)
}

fn to_g1_point(point: &[u8]) -> G1Affine {
    let le_bytes: Vec<u8> = point
        .chunks(8)
        .flat_map(|limb| {
            let mut new_limb = limb.to_vec();
            new_limb.reverse();
            new_limb
        })
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
        .flat_map(|limb| {
            let mut new_limb = limb.to_vec();
            new_limb.reverse();
            new_limb
        })
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
