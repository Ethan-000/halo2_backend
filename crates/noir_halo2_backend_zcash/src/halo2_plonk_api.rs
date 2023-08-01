use crate::circuit_translator::NoirHalo2Translator;
use acvm::FieldElement;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use zcash_halo2_proofs::{
    arithmetic::Field,
    circuit::{Cell, Layouter, Value},
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Assigned, Column,
        ConstraintSystem, Fixed, ProvingKey, SingleVerifier, VerifyingKey,
    },
    poly::{commitment::Params, Rotation},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};

pub fn halo2_keygen(
    circuit: &NoirHalo2Translator<Fp>,
    params: &Params<EqAffine>,
) -> (ProvingKey<EqAffine>, VerifyingKey<EqAffine>) {
    let vk = keygen_vk(params, circuit).expect("keygen_vk should not fail");
    let vk_return = vk.clone();
    let pk = keygen_pk(params, vk, circuit).expect("keygen_pk should not fail");
    (pk, vk_return)
}

pub fn halo2_prove(
    circuit: NoirHalo2Translator<Fp>,
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
) -> Vec<u8> {
    let rng = OsRng;
    let mut transcript: Blake2bWrite<Vec<u8>, _, Challenge255<_>> =
        Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(params, pk, &[circuit], &[&[]], rng, &mut transcript)
        .expect("proof generation should not fail");
    transcript.finalize()
}

pub fn halo2_verify(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    proof: &[u8],
) -> Result<(), zcash_halo2_proofs::plonk::Error> {
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    verify_proof(params, vk, strategy, &[&[]], &mut transcript)
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
}

impl PlonkConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
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

        meta.create_gate("Combined add-mult", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());

            let sl = meta.query_fixed(sl);
            let sr = meta.query_fixed(sr);
            let so = meta.query_fixed(so);
            let sm = meta.query_fixed(sm);
            let sc = meta.query_fixed(sc);

            vec![a.clone() * sl + b.clone() * sr + a * b * sm + (c * so) + sc]
        });

        PlonkConfig { a, b, c, sl, sr, so, sm, sc }
    }
}
#[allow(clippy::type_complexity)]
pub trait StandardCs<FF: Field> {
    fn raw_multiply<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        f: F,
    ) -> Result<(Cell, Cell, Cell), zcash_halo2_proofs::plonk::Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>;
    fn raw_add<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        f: F,
    ) -> Result<(Cell, Cell, Cell), zcash_halo2_proofs::plonk::Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>;
    fn raw_poly<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        f: F,
    ) -> Result<(Cell, Cell, Cell), zcash_halo2_proofs::plonk::Error>
    where
        F: FnMut() -> PolyTriple<Assigned<FF>>;
    fn copy(
        &self,
        layouter: &mut impl Layouter<FF>,
        a: Cell,
        b: Cell,
    ) -> Result<(), zcash_halo2_proofs::plonk::Error>;
}

#[derive(Copy, Clone, Debug)]
pub struct PolyTriple<F> {
    pub(crate) a: Value<F>,
    pub(crate) b: Value<F>,
    pub(crate) c: Value<F>,
    pub(crate) qm: F,
    pub(crate) ql: F,
    pub(crate) qr: F,
    pub(crate) qo: F,
    pub(crate) qc: F,
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
        PolyTriple { a, b, c, qm, ql, qr, qo, qc }
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
        StandardPlonk { config, _marker: PhantomData }
    }
}

impl<FF: Field> StandardCs<FF> for StandardPlonk<FF> {
    fn raw_multiply<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), zcash_halo2_proofs::plonk::Error>
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
                    self.config.a,
                    0,
                    || {
                        value = Some(f());
                        value.unwrap().map(|v| v.0)
                    },
                )?;
                let rhs = region.assign_advice(
                    || "rhs",
                    self.config.b,
                    0,
                    || value.unwrap().map(|v| v.1),
                )?;
                let out = region.assign_advice(
                    || "out",
                    self.config.c,
                    0,
                    || value.unwrap().map(|v| v.2),
                )?;

                region.assign_fixed(|| "a", self.config.sl, 0, || Value::known(FF::ZERO))?;
                region.assign_fixed(|| "b", self.config.sr, 0, || Value::known(FF::ZERO))?;
                region.assign_fixed(|| "c", self.config.so, 0, || Value::known(FF::ONE))?;
                region.assign_fixed(|| "a*b", self.config.sm, 0, || Value::known(FF::ONE))?;
                Ok((lhs.cell(), rhs.cell(), out.cell()))
            },
        )
    }
    fn raw_add<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), zcash_halo2_proofs::plonk::Error>
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
                    self.config.a,
                    0,
                    || {
                        value = Some(f());
                        value.unwrap().map(|v| v.0)
                    },
                )?;
                let rhs = region.assign_advice(
                    || "rhs",
                    self.config.b,
                    0,
                    || value.unwrap().map(|v| v.1),
                )?;
                let out = region.assign_advice(
                    || "out",
                    self.config.c,
                    0,
                    || value.unwrap().map(|v| v.2),
                )?;

                region.assign_fixed(|| "a", self.config.sl, 0, || Value::known(FF::ONE))?;
                region.assign_fixed(|| "b", self.config.sr, 0, || Value::known(FF::ONE))?;
                region.assign_fixed(|| "c", self.config.so, 0, || Value::known(FF::ONE))?;
                region.assign_fixed(|| "a + b", self.config.sm, 0, || Value::known(FF::ZERO))?;
                Ok((lhs.cell(), rhs.cell(), out.cell()))
            },
        )
    }
    fn raw_poly<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), zcash_halo2_proofs::plonk::Error>
    where
        F: FnMut() -> PolyTriple<Assigned<FF>>,
    {
        layouter.assign_region(
            || "raw_poly",
            |mut region| {
                let value = f();
                let lhs = region.assign_advice(|| "lhs", self.config.a, 0, || value.a)?;
                let rhs = region.assign_advice(|| "rhs", self.config.b, 0, || value.b)?;
                let out = region.assign_advice(|| "out", self.config.c, 0, || value.c)?;

                region.assign_fixed(|| "a", self.config.sl, 0, || Value::known(value.ql))?;
                region.assign_fixed(|| "b", self.config.sr, 0, || Value::known(value.qr))?;
                region.assign_fixed(|| "c", self.config.so, 0, || Value::known(value.qo))?;
                region.assign_fixed(|| "a * b", self.config.sm, 0, || Value::known(value.qm))?;
                region.assign_fixed(|| "qc", self.config.sc, 0, || Value::known(value.qc))?;
                Ok((lhs.cell(), rhs.cell(), out.cell()))
            },
        )
    }
    fn copy(
        &self,
        layouter: &mut impl Layouter<FF>,
        left: Cell,
        right: Cell,
    ) -> Result<(), zcash_halo2_proofs::plonk::Error> {
        layouter.assign_region(
            || "copy",
            |mut region| {
                region.constrain_equal(left, right)?;
                region.constrain_equal(left, right)
            },
        )
    }
}
