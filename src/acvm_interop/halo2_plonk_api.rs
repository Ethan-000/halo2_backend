use std::marker::PhantomData;

use halo2_proofs_axiom::{
    self,
    arithmetic::Field,
    circuit::Layouter,
    circuit::{Cell, Value},
    halo2curves::bn256::Fr,
    plonk::Assigned,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};

#[derive(Clone, Copy)]
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
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let p = meta.instance_column();

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

            let sl = meta.query_fixed(sl, Rotation::cur());
            let sr = meta.query_fixed(sr, Rotation::cur());
            let so = meta.query_fixed(so, Rotation::cur());
            let sm = meta.query_fixed(sm, Rotation::cur());
            let sc = meta.query_fixed(sc, Rotation::cur());

            vec![a.clone() * sl + b.clone() * sr + a * b * sm + (c * so) + sc]
        });

        meta.create_gate("Public input", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let p = meta.query_instance(p, Rotation::cur());
            let sc = meta.query_fixed(sc, Rotation::cur());

            vec![sc * (a - p)]
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
        }
    }
}
#[allow(clippy::type_complexity)]
trait StandardCs<FF: Field> {
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
    fn copy(&self, layouter: &mut impl Layouter<FF>, a: Cell, b: Cell) -> Result<(), Error>;
    fn public_input<F>(&self, layouter: &mut impl Layouter<FF>, f: F) -> Result<Cell, Error>
    where
        F: FnMut() -> Value<FF>;
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
        Ok(layouter.assign_region(
            || "raw_multiply",
            |mut region| {
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
        )?)
    }
    fn raw_add<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>,
    {
        Ok(layouter.assign_region(
            || "raw_add",
            |mut region| {
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
        )?)
    }
    fn copy(&self, layouter: &mut impl Layouter<FF>, left: Cell, right: Cell) -> Result<(), Error> {
        layouter.assign_region(
            || "copy",
            |mut region| Ok(region.constrain_equal(&left, &right)),
        )
    }
    fn public_input<F>(&self, layouter: &mut impl Layouter<FF>, mut f: F) -> Result<Cell, Error>
    where
        F: FnMut() -> Value<FF>,
    {
        layouter.assign_region(
            || "public_input",
            |mut region| {
                let value = region.assign_advice(self.config.a, 0, (&mut f)())?;
                region.assign_fixed(self.config.sc, 0, FF::one());

                Ok(*value.cell())
            },
        )
    }
}
