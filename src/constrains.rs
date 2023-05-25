use crate::halo2_plonk_api::{PlonkConfig, PolyTriple, StandardCs};
use acvm::{
    acir::native_types::{Expression, Witness},
    FieldElement,
};
use halo2_base::{gates::RangeInstructions, Context};
use halo2_proofs_axiom::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::Assigned,
};

use crate::circuit_translator::NoirHalo2Translator;

impl NoirHalo2Translator<Fr> {
    #[allow(non_snake_case)]
    pub(crate) fn add_arithmetic_constrains(
        &self,
        gate: &Expression,
        cs: &impl StandardCs<Fr>,
        layouter: &mut impl Layouter<Fr>,
    ) {
        let mut a: Value<Assigned<_>> = Value::known(Fr::zero()).into();
        let mut b: Value<Assigned<_>> = Value::known(Fr::zero()).into();
        let mut c: Value<Assigned<_>> = Value::known(Fr::zero()).into();
        let d: Value<Assigned<_>> = Value::known(Fr::zero()).into();
        let mut qm = Fr::zero();
        let mut ql = Fr::zero();
        let mut qr = Fr::zero();
        let mut qo = Fr::zero();

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
                *self
                    .witness_values
                    .get(wR)
                    .unwrap_or(&FieldElement::zero()),
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
                *self
                    .witness_values
                    .get(wO)
                    .unwrap_or(&FieldElement::zero()),
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
                *self
                    .witness_values
                    .get(wL)
                    .unwrap_or(&FieldElement::zero()),
            ))
            .into();

            let qR_wR_term = &gate.linear_combinations[1];
            qr = noir_field_to_halo2_field(qR_wR_term.0);

            let wR = &qR_wR_term.1;
            b = Value::known(noir_field_to_halo2_field(
                *self
                    .witness_values
                    .get(wR)
                    .unwrap_or(&FieldElement::zero()),
            ))
            .into();
        }

        if gate.linear_combinations.len() == 3 {
            let qL_wL_term = &gate.linear_combinations[0];
            ql = noir_field_to_halo2_field(qL_wL_term.0);

            let wL = &qL_wL_term.1;
            a = Value::known(noir_field_to_halo2_field(
                *self
                    .witness_values
                    .get(wL)
                    .unwrap_or(&FieldElement::zero()),
            ))
            .into();

            let qR_wR_term = &gate.linear_combinations[1];
            qr = noir_field_to_halo2_field(qR_wR_term.0);

            let wR = &qR_wR_term.1;
            b = Value::known(noir_field_to_halo2_field(
                *self
                    .witness_values
                    .get(wR)
                    .unwrap_or(&FieldElement::zero()),
            ))
            .into();

            let qO_wO_term = &gate.linear_combinations[2];
            qo = noir_field_to_halo2_field(qO_wO_term.0);

            let wO = &qO_wO_term.1;
            c = Value::known(noir_field_to_halo2_field(
                *self
                    .witness_values
                    .get(wO)
                    .unwrap_or(&FieldElement::zero()),
            ))
            .into();
        }

        // Add the qc term
        let qc = noir_field_to_halo2_field(gate.q_c);
        let poly_triple = PolyTriple::new(
            a,
            b,
            c,
            d,
            qm.into(),
            ql.into(),
            qr.into(),
            qo.into(),
            qc.into(),
        );

        cs.raw_poly(layouter, || poly_triple).unwrap();
    }

    pub(crate) fn add_range_constrain(
        &self,
        witness: Witness,
        num_bits: u32,
        config: &PlonkConfig,
    ) {
        let mut ctx = Context::<Fr>::new(true, 0);

        let d = noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&witness)
                .unwrap_or(&FieldElement::zero()),
        );

        let x = ctx.load_witness(d);

        config
            .range_chip
            .range_check(&mut ctx, x, num_bits as usize);
    }
}

fn noir_field_to_halo2_field(noir_ele: FieldElement) -> Fr {
    let mut bytes = noir_ele.to_be_bytes();
    bytes.reverse();
    let mut halo_ele: [u8; 32] = [0; 32];
    for i in 0..bytes.len() {
        halo_ele[i] = bytes[i]
    }
    Fr::from_bytes(&halo_ele).unwrap()
}
