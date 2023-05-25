use std::marker::PhantomData;

use halo2_base::gates::{GateChip, RangeChip};
use halo2_proofs_axiom::{
    self,
    arithmetic::Field,
    circuit::Layouter,
    circuit::{Cell, Value},
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine, G1},
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

use crate::circuit_translator::NoirHalo2Translator;

pub fn keygen(
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

pub fn prover(
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

pub fn verifier(
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
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,

    sl: Column<Fixed>,
    sr: Column<Fixed>,
    so: Column<Fixed>,
    sm: Column<Fixed>,
    sc: Column<Fixed>,

    pub(crate) range_chip: RangeChip<Fr>,
    pub(crate) gate_chip: GateChip<Fr>,
}

impl PlonkConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);

        let sm = meta.fixed_column();
        let sl = meta.fixed_column();
        let sr = meta.fixed_column();
        let so = meta.fixed_column();
        let sc = meta.fixed_column();

        let range_chip = RangeChip::default(17);
        let gate_chip = GateChip::default();

        meta.create_gate("Combined add-mult", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());

            let sl = meta.query_fixed(sl, Rotation::cur());
            let sr = meta.query_fixed(sr, Rotation::cur());
            let so = meta.query_fixed(so, Rotation::cur());
            let sm = meta.query_fixed(sm, Rotation::cur());
            let sc = meta.query_fixed(sc, Rotation::cur());

            vec![a.clone() * sl + b.clone() * sr + a * b * sm + (c * so) + sc]
        });

        PlonkConfig {
            a,
            b,
            c,
            sl,
            sr,
            so,
            sm,
            sc,
            range_chip,
            gate_chip,
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
    ) -> Result<(Cell, Cell, Cell), Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>,
    {
        layouter.assign_region(
            || "raw_multiply",
            |mut region| {
                #[allow(unused_assignments)]
                let mut value = None;
                let lhs = region.assign_advice(self.config.a, 0, {
                    value = Some(f());
                    value.unwrap().map(|v| v.0)
                })?;
                region.assign_advice(self.config.b, 0, value.unwrap().map(|v| v.1))?;
                let rhs = region.assign_advice(self.config.b, 0, value.unwrap().map(|v| v.1))?;
                region.assign_advice(self.config.c, 0, value.unwrap().map(|v| v.2))?;
                let out = region.assign_advice(self.config.c, 0, value.unwrap().map(|v| v.2))?;

                region.assign_fixed(self.config.sl, 0, FF::zero());
                region.assign_fixed(self.config.sr, 0, FF::zero());
                region.assign_fixed(self.config.so, 0, FF::one());
                region.assign_fixed(self.config.sm, 0, FF::one());
                Ok((*lhs.cell(), *rhs.cell(), *out.cell()))
            },
        )
    }
    fn raw_add<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>,
    {
        layouter.assign_region(
            || "raw_add",
            |mut region| {
                #[allow(unused_assignments)]
                let mut value = None;
                let lhs = region.assign_advice(self.config.a, 0, {
                    value = Some(f());
                    value.unwrap().map(|v| v.0)
                })?;
                region.assign_advice(self.config.b, 0, value.unwrap().map(|v| v.1))?;
                let rhs = region.assign_advice(self.config.b, 0, value.unwrap().map(|v| v.1))?;
                region.assign_advice(self.config.c, 0, value.unwrap().map(|v| v.2))?;
                let out = region.assign_advice(self.config.c, 0, value.unwrap().map(|v| v.2))?;

                region.assign_fixed(self.config.sl, 0, FF::one());
                region.assign_fixed(self.config.sr, 0, FF::one());
                region.assign_fixed(self.config.so, 0, FF::one());
                region.assign_fixed(self.config.sm, 0, FF::zero());
                Ok((*lhs.cell(), *rhs.cell(), *out.cell()))
            },
        )
    }
    fn raw_poly<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), Error>
    where
        F: FnMut() -> PolyTriple<Assigned<FF>>,
    {
        layouter.assign_region(
            || "raw_poly",
            |mut region| {
                let value = f();
                let lhs = region.assign_advice(self.config.a, 0, value.a)?;
                let rhs = region.assign_advice(self.config.b, 0, value.b)?;
                let out = region.assign_advice(self.config.c, 0, value.c)?;

                region.assign_fixed(self.config.sl, 0, value.ql);
                region.assign_fixed(self.config.sr, 0, value.qr);
                region.assign_fixed(self.config.so, 0, value.qo);
                region.assign_fixed(self.config.sm, 0, value.qm);
                region.assign_fixed(self.config.sc, 0, value.qc);
                Ok((*lhs.cell(), *rhs.cell(), *out.cell()))
            },
        )
    }
    fn copy(&self, layouter: &mut impl Layouter<FF>, left: Cell, right: Cell) -> Result<(), Error> {
        layouter.assign_region(
            || "copy",
            |mut region| {
                region.constrain_equal(&left, &right);
                Ok(())
            },
        )
    }
}
