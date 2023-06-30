use crate::circuit_translator::NoirHalo2Translator;
use halo2_base::{
    gates::{GateChip, RangeChip, builder::{GateCircuitBuilder, RangeWithInstanceCircuitBuilder}},
    halo2_proofs::{
        halo2curves::bn256::Fr,
        halo2curves::{
            bn256::{Bn256, G1Affine, G1},
            group::cofactor::CofactorCurve,
        },
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, ConstraintSystem, Error, ProvingKey,
            VerifyingKey,
        },
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
};
use rand::rngs::OsRng;

pub fn halo2_keygen(
    circuit: &NoirHalo2Translator<Fr>,
    params: &ParamsKZG<Bn256>,
) -> (
    ProvingKey<<G1 as CofactorCurve>::Affine>,
    VerifyingKey<<G1 as CofactorCurve>::Affine>,
) {
    let vk = keygen_vk(params, circuit).expect("keygen_vk should not fail");
    let vk_return = vk.clone();
    let pk = keygen_pk(params, vk, circuit).expect("keygen_pk should not fail");
    (pk, vk_return)
}

pub fn halo2_prove(
    circuit: NoirHalo2Translator<Fr>,
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<<G1 as CofactorCurve>::Affine>,
) -> Vec<u8> {
    let rng = OsRng;
    let mut transcript: Blake2bWrite<Vec<u8>, _, Challenge255<_>> =
        Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
        _,
    >(params, pk, &[circuit], &[&[]], rng, &mut transcript)
    .expect("proof generation should not fail");
    transcript.finalize()
}

pub fn halo2_verify(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<<G1 as CofactorCurve>::Affine>,
    proof: &[u8],
) -> Result<(), Error> {
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(params, vk, strategy, &[&[]], &mut transcript)
}

#[derive(Clone)]
pub struct PlonkConfig {
    pub(crate) range_chip: RangeChip<Fr>,
    pub(crate) gate_chip: GateChip<Fr>,
}

impl PlonkConfig {
    pub fn configure(_meta: &mut ConstraintSystem<Fr>) -> Self {
        let range_chip = RangeChip::default(17);
        let gate_chip = GateChip::default();

        PlonkConfig {
            range_chip,
            gate_chip,
        }
    }
}
