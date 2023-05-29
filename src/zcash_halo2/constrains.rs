use crate::zcash_halo2::halo2_plonk_api::{PolyTriple, StandardCs};
use acvm::{acir::native_types::Expression, FieldElement};
use zcash_halo2_proofs::{
    circuit::{Layouter, Value},
    pasta::{group::ff::PrimeField, Fp},
    plonk::Assigned,
};

use crate::zcash_halo2::circuit_translator::NoirHalo2Translator;

use super::halo2_plonk_api::NoirConstraint;

impl NoirHalo2Translator<Fp> {
    #[allow(non_snake_case)]
    pub(crate) fn add_arithmetic_constrains(
        &self,
        gate: &Expression,
        cs: &impl StandardCs<Fp>,
        layouter: &mut impl Layouter<Fp>,
    ) {
        let mut noir_cs = NoirConstraint::default();
        // check mul gate
        if !gate.mul_terms.is_empty() {
            let mul_term = &gate.mul_terms[0];
            noir_cs.qm = mul_term.0;

            // Get wL term
            let wL = &mul_term.1;
            noir_cs.a = wL.witness_index() as i32;

            // Get wR term
            let wR = &mul_term.2;
            noir_cs.b = wR.witness_index() as i32;
        }

        for term in &gate.linear_combinations {
            noir_cs.set_linear_term(term.0, term.1.witness_index() as i32);
        }

        // Add the qc term
        noir_cs.qc = gate.q_c;

        let a: Value<Assigned<_>> = Value::known(noir_field_to_halo2_field(
            *self
                .witness_values
                .get_index(noir_cs.a as u32)
                .unwrap_or(&FieldElement::zero()),
        ))
        .into();

        let b: Value<Assigned<_>> = Value::known(noir_field_to_halo2_field(
            *self
                .witness_values
                .get_index(noir_cs.b as u32)
                .unwrap_or(&FieldElement::zero()),
        ))
        .into();

        let c: Value<Assigned<_>> = Value::known(noir_field_to_halo2_field(
            *self
                .witness_values
                .get_index(noir_cs.c as u32)
                .unwrap_or(&FieldElement::zero()),
        ))
        .into();

        let qm = noir_field_to_halo2_field(noir_cs.qm);

        let ql = noir_field_to_halo2_field(noir_cs.ql);

        let qr = noir_field_to_halo2_field(noir_cs.qr);

        let qo = noir_field_to_halo2_field(noir_cs.qo);

        let qc = noir_field_to_halo2_field(noir_cs.qc);

        let poly_gate = PolyTriple::new(
            a,
            b,
            c,
            qm.into(),
            ql.into(),
            qr.into(),
            qo.into(),
            qc.into(),
        );

        cs.raw_poly(layouter, || poly_gate).unwrap();
    }
}

fn noir_field_to_halo2_field(noir_ele: FieldElement) -> Fp {
    let mut bytes = noir_ele.to_be_bytes();
    bytes.reverse();
    let mut halo_ele: [u8; 32] = [0; 32];
    halo_ele[..bytes.len()].copy_from_slice(&bytes[..]);
    Fp::from_repr(halo_ele).unwrap()
}
