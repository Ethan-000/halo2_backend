use acvm::FieldElement;

use pse_halo2wrong::{
    halo2::{
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

use pse_maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::pse_halo2::circuit_translator::NoirHalo2Translator;

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
    >(params, pk, &[circuit], &[&[&[]]], rng, &mut transcript)
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
    >(params, vk, strategy, &[&[&[]]], &mut transcript)
}

#[derive(Clone)]
pub struct PlonkConfig {
    pub(crate) main_gate_config: MainGateConfig,
    pub(crate) range_config: RangeConfig,
    // pub(crate) ecc_config: EccConfig,
}

impl PlonkConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        // let (rns_base, rns_scalar) = GeneralEccChip::<Secp256k1Affine, Fr, 4, 68>::rns();
        let main_gate_config = MainGate::<Fr>::configure(meta);

        // let mut overflow_bit_lens: Vec<usize> =
        //     vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        // overflow_bit_lens.extend(rns_base.overflow_lengths());
        // overflow_bit_lens.extend(rns_scalar.overflow_lengths());
        // let composition_bit_lens = vec![8, 68 / 4];

        let overflow_bit_lens: Vec<usize> = vec![1, 2, 3, 4, 5, 6, 7];
        let composition_bit_lens = vec![8];

        let range_config = RangeChip::<Fr>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );
        // let ecc_config = EccConfig::new(range_config.clone(), main_gate_config.clone());

        PlonkConfig {
            main_gate_config,
            range_config,
            // ecc_config,
        }
    }
}

#[derive(Clone, Hash, Debug, Serialize, Deserialize)]
pub(crate) struct NoirConstraint {
    pub(crate) a: i32,
    pub(crate) b: i32,
    pub(crate) c: i32,
    pub(crate) qm: FieldElement,
    pub(crate) ql: FieldElement,
    pub(crate) qr: FieldElement,
    pub(crate) qo: FieldElement,
    pub(crate) qc: FieldElement,
}

impl Default for NoirConstraint {
    fn default() -> Self {
        NoirConstraint {
            a: 0,
            b: 0,
            c: 0,
            qm: FieldElement::zero(),
            ql: FieldElement::zero(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: FieldElement::zero(),
        }
    }
}

impl NoirConstraint {
    pub(crate) fn set_linear_term(&mut self, x: FieldElement, witness: i32) {
        if self.a == 0 || self.a == witness {
            self.a = witness;
            self.ql = x;
        } else if self.b == 0 || self.b == witness {
            self.b = witness;
            self.qr = x;
        } else if self.c == 0 || self.c == witness {
            self.c = witness;
            self.qo = x;
        } else {
            unreachable!("Cannot assign linear term to a constrain of width 3");
        }
    }
}
