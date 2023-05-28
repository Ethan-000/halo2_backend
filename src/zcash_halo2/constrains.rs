use crate::zcash_halo2::halo2_plonk_api::{PolyTriple, StandardCs};
use acvm::{acir::native_types::Expression, FieldElement};
use zcash_halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, Value},
    pasta::{group::ff::PrimeField, Fp},
    plonk::Assigned,
};

use crate::zcash_halo2::circuit_translator::NoirHalo2Translator;

impl NoirHalo2Translator<Fp> {
    #[allow(non_snake_case)]
    pub(crate) fn add_arithmetic_constrains(
        &self,
        gate: &Expression,
        cs: &impl StandardCs<Fp>,
        layouter: &mut impl Layouter<Fp>,
    ) {
        let mut a: Value<Assigned<_>> = Value::known(Fp::ZERO).into();
        let mut b: Value<Assigned<_>> = Value::known(Fp::ZERO).into();
        let mut c: Value<Assigned<_>> = Value::known(Fp::ZERO).into();
        let mut qm = Fp::ZERO;
        let mut ql = Fp::ZERO;
        let mut qr = Fp::ZERO;
        let mut qo = Fp::ZERO;

        // check mul gate
        if !gate.mul_terms.is_empty() {
            let mul_term = &gate.mul_terms[0];
            qm = noir_field_to_halo2_field(mul_term.0);

            // Get wL term
            let wL = &mul_term.1;
            a = Value::known(noir_field_to_halo2_field(
                *self.witness_values.get(wL).unwrap_or(&FieldElement::zero()),
            ))
            .into();

            // Get wR term
            let wR = &mul_term.2;
            b = Value::known(noir_field_to_halo2_field(
                *self.witness_values.get(wR).unwrap_or(&FieldElement::zero()),
            ))
            .into();
        }

        // If there is only one simplified fan term,
        // then put it in qO * wO
        // This is in case, the qM term is non-zero
        if gate.linear_combinations.len() == 1 {
            let qO_wO_term = &gate.linear_combinations[0];
            qo = noir_field_to_halo2_field(qO_wO_term.0);

            let wO = &qO_wO_term.1;
            c = Value::known(noir_field_to_halo2_field(
                *self.witness_values.get(wO).unwrap_or(&FieldElement::zero()),
            ))
            .into();
        }

        // XXX: This is a code smell. Refactor to be better. Maybe change Barretenberg to take vectors
        // If there is more than one term,
        // Then add normally
        if gate.linear_combinations.len() == 2 {
            let qL_wL_term = &gate.linear_combinations[0];
            ql = noir_field_to_halo2_field(qL_wL_term.0);

            let wL = &qL_wL_term.1;
            a = Value::known(noir_field_to_halo2_field(
                *self.witness_values.get(wL).unwrap_or(&FieldElement::zero()),
            ))
            .into();

            let qR_wR_term = &gate.linear_combinations[1];
            qr = noir_field_to_halo2_field(qR_wR_term.0);

            let wR = &qR_wR_term.1;
            b = Value::known(noir_field_to_halo2_field(
                *self.witness_values.get(wR).unwrap_or(&FieldElement::zero()),
            ))
            .into();
        }

        if gate.linear_combinations.len() == 3 {
            let qL_wL_term = &gate.linear_combinations[0];
            ql = noir_field_to_halo2_field(qL_wL_term.0);

            let wL = &qL_wL_term.1;
            a = Value::known(noir_field_to_halo2_field(
                *self.witness_values.get(wL).unwrap_or(&FieldElement::zero()),
            ))
            .into();

            let qR_wR_term = &gate.linear_combinations[1];
            qr = noir_field_to_halo2_field(qR_wR_term.0);

            let wR = &qR_wR_term.1;
            b = Value::known(noir_field_to_halo2_field(
                *self.witness_values.get(wR).unwrap_or(&FieldElement::zero()),
            ))
            .into();

            let qO_wO_term = &gate.linear_combinations[2];
            qo = noir_field_to_halo2_field(qO_wO_term.0);

            let wO = &qO_wO_term.1;
            c = Value::known(noir_field_to_halo2_field(
                *self.witness_values.get(wO).unwrap_or(&FieldElement::zero()),
            ))
            .into();
        }

        // Add the qc term
        let qc = noir_field_to_halo2_field(gate.q_c);
        let poly_triple = PolyTriple::new(
            a,
            b,
            c,
            qm.into(),
            ql.into(),
            qr.into(),
            qo.into(),
            qc.into(),
        );

        cs.raw_poly(layouter, || poly_triple).unwrap();
    }
}

fn noir_field_to_halo2_field(noir_ele: FieldElement) -> Fp {
    let mut bytes = noir_ele.to_be_bytes();
    bytes.reverse();
    let mut halo_ele: [u8; 32] = [0; 32];
    halo_ele[..bytes.len()].copy_from_slice(&bytes[..]);
    Fp::from_repr(halo_ele).unwrap()
}
