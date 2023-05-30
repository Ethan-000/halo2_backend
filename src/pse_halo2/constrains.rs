use crate::pse_halo2::halo2_plonk_api::{PolyTriple, StandardCs};
use acvm::{
    acir::native_types::{Expression},
    FieldElement,
};
use pse_halo2wrong::{
    halo2::{
        circuit::{Layouter, Value},
        halo2curves::bn256::Fr,
        plonk::Assigned,
    },
};


use crate::pse_halo2::circuit_translator::NoirHalo2Translator;

use super::halo2_plonk_api::{NoirConstraint};

impl NoirHalo2Translator<Fr> {
    #[allow(non_snake_case)]
    pub(crate) fn add_arithmetic_constrains(
        &self,
        gate: &Expression,
        cs: &impl StandardCs<Fr>,
        layouter: &mut impl Layouter<Fr>,
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

    // pub(crate) fn add_range_constrain(
    //     &self,
    //     witness: Witness,
    //     num_bits: u32,
    //     config: &PlonkConfig,
    //     layouter: &mut impl Layouter<Fr>,
    // ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
    //     let range_chip = RangeChip::<Fr>::new(config.range_config.clone());
    //     let main_gate = MainGate::<Fr>::new(config.main_gate_config.clone());

    //     let input = noir_field_to_halo2_field(
    //         *self
    //             .witness_values
    //             .get(&witness)
    //             .unwrap_or(&FieldElement::zero()),
    //     );

    //     layouter.assign_region(
    //         || "region 0",
    //         |region| {
    //             let offset = 0;
    //             let ctx = &mut RegionCtx::new(region, offset);

    //             let value = Value::known(input);
    //             let limb_bit_len = 8;
    //             let bit_len = num_bits as usize;

    //             let a_0 = main_gate.assign_value(ctx, value)?;
    //             let (a_1, decomposed) = range_chip.decompose(ctx, value, limb_bit_len, bit_len)?;

    //             main_gate.assert_equal(ctx, &a_0, &a_1)?;

    //             let bases: Vec<Fr> = (0..Fr::NUM_BITS as usize / bit_len)
    //                 .map(|i| Fr::from(2).pow(&[(bit_len * i) as u64, 0, 0, 0]))
    //                 .collect();

    //             let terms: Vec<Term<Fr>> = decomposed
    //                 .iter()
    //                 .zip(bases)
    //                 .map(|(limb, base)| Term::Assigned(limb, base))
    //                 .collect();
    //             let a_1 = main_gate.compose(ctx, &terms[..], Fr::zero())?;
    //             main_gate.assert_equal(ctx, &a_0, &a_1)?;

    //             Ok(())
    //         },
    //     )?;

    //     range_chip.load_table(layouter)?;

    //     Ok(())
    // }
}

fn noir_field_to_halo2_field(noir_ele: FieldElement) -> Fr {
    let mut bytes = noir_ele.to_be_bytes();
    bytes.reverse();
    let mut halo_ele: [u8; 32] = [0; 32];
    halo_ele[..bytes.len()].copy_from_slice(&bytes[..]);
    Fr::from_bytes(&halo_ele).unwrap()
}
