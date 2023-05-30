use std::marker::PhantomData;

use acvm::FieldElement;
use pse_halo2wrong::halo2::{
    arithmetic::Field,
    circuit::Layouter,
    circuit::{Cell, Value},
    halo2curves::bn256::Fr,
    halo2curves::{
        bn256::{Bn256, G1Affine, G1},
        group::cofactor::CofactorCurve,
    },
    plonk::Assigned,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Column, ConstraintSystem, Error,
        Fixed, ProvingKey, VerifyingKey,
    },
    poly::{
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};


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
    arith_a: Column<Advice>,
    arith_b: Column<Advice>,
    arith_c: Column<Advice>,

    arith_sl: Column<Fixed>,
    arith_sr: Column<Fixed>,
    arith_so: Column<Fixed>,
    arith_sm: Column<Fixed>,
    arith_sc: Column<Fixed>,
    // pub(crate) range_config: RangeConfig,
    // pub(crate) main_gate_config: MainGateConfig,
    // pub(crate) range_chip: RangeChip<Fr>,
}

impl PlonkConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let arith_a = meta.advice_column();
        let arith_b = meta.advice_column();
        let arith_c = meta.advice_column();

        meta.enable_equality(arith_a);
        meta.enable_equality(arith_b);
        meta.enable_equality(arith_c);

        let arith_sm = meta.fixed_column();
        let arith_sl = meta.fixed_column();
        let arith_sr = meta.fixed_column();
        let arith_so = meta.fixed_column();
        let arith_sc = meta.fixed_column();

        // let main_gate_config = MainGate::<Fr>::configure(meta);
        // let range_config = RangeChip::<Fr>::configure(meta, &main_gate_config, vec![8], vec![3]);

        meta.create_gate("Combined add-mult", |meta| {
            let arith_a = meta.query_advice(arith_a, Rotation::cur());
            let arith_b = meta.query_advice(arith_b, Rotation::cur());
            let arith_c = meta.query_advice(arith_c, Rotation::cur());

            let arith_sl = meta.query_fixed(arith_sl, Rotation::cur());
            let arith_sr = meta.query_fixed(arith_sr, Rotation::cur());
            let arith_so = meta.query_fixed(arith_so, Rotation::cur());
            let arith_sm = meta.query_fixed(arith_sm, Rotation::cur());
            let arith_sc = meta.query_fixed(arith_sc, Rotation::cur());

            vec![
                arith_a.clone() * arith_sl
                    + arith_b.clone() * arith_sr
                    + arith_a * arith_b * arith_sm
                    + (arith_c * arith_so)
                    + arith_sc,
            ]
        });

        PlonkConfig {
            arith_a,
            arith_b,
            arith_c,
            arith_sl,
            arith_sr,
            arith_so,
            arith_sm,
            arith_sc,
            // range_config,
            // main_gate_config,
            // range_chip,
        }
    }
}
#[allow(clippy::type_complexity)]
pub trait StandardCs<FF: Field> {
    fn raw_multiply<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        f: F,
    ) -> Result<(Cell, Cell, Cell), Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>;
    fn raw_add<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        f: F,
    ) -> Result<(Cell, Cell, Cell), Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>;
    fn raw_poly<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        f: F,
    ) -> Result<(Cell, Cell, Cell), Error>
    where
        F: FnMut() -> PolyTriple<Assigned<FF>>;
    fn copy(&self, layouter: &mut impl Layouter<FF>, a: Cell, b: Cell) -> Result<(), Error>;
}

#[derive(Copy, Clone, Debug)]
pub struct PolyTriple<F> {
    a: Value<F>,
    b: Value<F>,
    c: Value<F>,
    qm: F,
    ql: F,
    qr: F,
    qo: F,
    qc: F,
}

impl<F> PolyTriple<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        a: Value<F>,
        b: Value<F>,
        c: Value<F>,
        qm: F,
        ql: F,
        qr: F,
        qo: F,
        qc: F,
    ) -> PolyTriple<F> {
        PolyTriple {
            a,
            b,
            c,
            qm,
            ql,
            qr,
            qo,
            qc,
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

pub struct StandardPlonk<F: Field> {
    config: PlonkConfig,
    _marker: PhantomData<F>,
}

impl<FF: Field> StandardPlonk<FF> {
    pub fn new(config: PlonkConfig) -> Self {
        StandardPlonk {
            config,
            _marker: PhantomData,
        }
    }
}

impl<FF: Field> StandardCs<FF> for StandardPlonk<FF> {
    fn raw_multiply<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), pse_halo2wrong::halo2::plonk::Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>,
    {
        layouter.assign_region(
            || "raw_multiply",
            |mut region| {
                #[allow(unused_assignments)]
                let mut value = None;
                let lhs = region.assign_advice(
                    || "lhs",
                    self.config.arith_a,
                    0,
                    || {
                        value = Some(f());
                        value.unwrap().map(|v| v.0)
                    },
                )?;
                let rhs = region.assign_advice(
                    || "rhs",
                    self.config.arith_b,
                    0,
                    || value.unwrap().map(|v| v.1),
                )?;
                let out = region.assign_advice(
                    || "out",
                    self.config.arith_c,
                    0,
                    || value.unwrap().map(|v| v.2),
                )?;

                region.assign_fixed(
                    || "a",
                    self.config.arith_sl,
                    0,
                    || Value::known(FF::zero()),
                )?;
                region.assign_fixed(
                    || "b",
                    self.config.arith_sr,
                    0,
                    || Value::known(FF::zero()),
                )?;
                region.assign_fixed(|| "c", self.config.arith_so, 0, || Value::known(FF::one()))?;
                region.assign_fixed(
                    || "a*b",
                    self.config.arith_sm,
                    0,
                    || Value::known(FF::one()),
                )?;
                Ok((lhs.cell(), rhs.cell(), out.cell()))
            },
        )
    }
    fn raw_add<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), pse_halo2wrong::halo2::plonk::Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>,
    {
        layouter.assign_region(
            || "raw_add",
            |mut region| {
                #[allow(unused_assignments)]
                let mut value = None;
                let lhs = region.assign_advice(
                    || "lhs",
                    self.config.arith_a,
                    0,
                    || {
                        value = Some(f());
                        value.unwrap().map(|v| v.0)
                    },
                )?;
                let rhs = region.assign_advice(
                    || "rhs",
                    self.config.arith_b,
                    0,
                    || value.unwrap().map(|v| v.1),
                )?;
                let out = region.assign_advice(
                    || "out",
                    self.config.arith_c,
                    0,
                    || value.unwrap().map(|v| v.2),
                )?;

                region.assign_fixed(|| "a", self.config.arith_sl, 0, || Value::known(FF::one()))?;
                region.assign_fixed(|| "b", self.config.arith_sr, 0, || Value::known(FF::one()))?;
                region.assign_fixed(|| "c", self.config.arith_so, 0, || Value::known(FF::one()))?;
                region.assign_fixed(
                    || "a + b",
                    self.config.arith_sm,
                    0,
                    || Value::known(FF::zero()),
                )?;
                Ok((lhs.cell(), rhs.cell(), out.cell()))
            },
        )
    }
    fn raw_poly<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), pse_halo2wrong::halo2::plonk::Error>
    where
        F: FnMut() -> PolyTriple<Assigned<FF>>,
    {
        layouter.assign_region(
            || "raw_poly",
            |mut region| {
                let value = f();
                let lhs = region.assign_advice(|| "lhs", self.config.arith_a, 0, || value.a)?;
                let rhs = region.assign_advice(|| "rhs", self.config.arith_b, 0, || value.b)?;
                let out = region.assign_advice(|| "out", self.config.arith_c, 0, || value.c)?;

                region.assign_fixed(|| "a", self.config.arith_sl, 0, || Value::known(value.ql))?;
                region.assign_fixed(|| "b", self.config.arith_sr, 0, || Value::known(value.qr))?;
                region.assign_fixed(|| "c", self.config.arith_so, 0, || Value::known(value.qo))?;
                region.assign_fixed(
                    || "a * b",
                    self.config.arith_sm,
                    0,
                    || Value::known(value.qm),
                )?;
                region.assign_fixed(|| "qc", self.config.arith_sc, 0, || Value::known(value.qc))?;
                Ok((lhs.cell(), rhs.cell(), out.cell()))
            },
        )
    }
    fn copy(
        &self,
        layouter: &mut impl Layouter<FF>,
        left: Cell,
        right: Cell,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        layouter.assign_region(
            || "copy",
            |mut region| {
                region.constrain_equal(left, right)?;
                region.constrain_equal(left, right)
            },
        )
    }
}
