use acvm::{
    acir::native_types::{Expression, Witness},
    FieldElement,
};
use pse_halo2wrong::{
    halo2::{
        circuit::{Layouter, Value},
        halo2curves::bn256::Fr,
    },
    RegionCtx,
};
use pse_maingate::{
    CombinationOption, MainGate, MainGateColumn, MainGateInstructions, RangeChip,
    RangeInstructions, Term,
};

use crate::pse_halo2::circuit_translator::NoirHalo2Translator;

use super::halo2_plonk_api::{NoirConstraint, PlonkConfig};

impl NoirHalo2Translator<Fr> {
    pub(crate) fn add_arithmetic_constrains(
        &self,
        gate: &Expression,
        config: &PlonkConfig,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        let mut noir_cs = NoirConstraint::default();
        // check mul gate
        if !gate.mul_terms.is_empty() {
            let mul_term = &gate.mul_terms[0];
            noir_cs.qm = mul_term.0;

            // Get wL term
            let wl = &mul_term.1;
            noir_cs.a = wl.witness_index() as i32;

            // Get wR term
            let wr = &mul_term.2;
            noir_cs.b = wr.witness_index() as i32;
        }

        for term in &gate.linear_combinations {
            noir_cs.set_linear_term(term.0, term.1.witness_index() as i32);
        }

        // Add the qc term
        noir_cs.qc = gate.q_c;

        let a = Value::known(noir_field_to_halo2_field(
            *self
                .witness_values
                .get_index(noir_cs.a as u32)
                .unwrap_or(&FieldElement::zero()),
        ));

        let b = Value::known(noir_field_to_halo2_field(
            *self
                .witness_values
                .get_index(noir_cs.b as u32)
                .unwrap_or(&FieldElement::zero()),
        ));

        let c = Value::known(noir_field_to_halo2_field(
            *self
                .witness_values
                .get_index(noir_cs.c as u32)
                .unwrap_or(&FieldElement::zero()),
        ));

        let qm = noir_field_to_halo2_field(noir_cs.qm);

        let ql = noir_field_to_halo2_field(noir_cs.ql);

        let qr = noir_field_to_halo2_field(noir_cs.qr);

        let qo = noir_field_to_halo2_field(noir_cs.qo);

        let qc = noir_field_to_halo2_field(noir_cs.qc);

        layouter.assign_region(
            || "region 0",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let main_gate = MainGate::<Fr>::new(config.main_gate_config.clone());

                let mut terms = Vec::new();

                let a = main_gate.assign_to_column(ctx, a, MainGateColumn::A)?;
                terms.push(Term::Assigned(&a, ql));
                let b = main_gate.assign_to_column(ctx, b, MainGateColumn::B)?;
                terms.push(Term::Assigned(&b, qr));
                let c = main_gate.assign_to_column(ctx, c, MainGateColumn::C)?;
                terms.push(Term::Assigned(&c, qo));
                let d =
                    main_gate.assign_to_column(ctx, Value::known(Fr::zero()), MainGateColumn::D)?;
                terms.push(Term::Assigned(&d, Fr::zero()));
                let e =
                    main_gate.assign_to_column(ctx, Value::known(Fr::zero()), MainGateColumn::E)?;
                terms.push(Term::Assigned(&e, Fr::zero()));

                main_gate.apply(
                    ctx,
                    terms,
                    qc,
                    CombinationOption::Common(
                        pse_maingate::CombinationOptionCommon::CombineToNextScaleMul(
                            Fr::zero(),
                            qm,
                        ),
                    ),
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }

    pub(crate) fn add_range_constrain(
        &self,
        witness: Witness,
        num_bits: u32,
        range_chip: &RangeChip<Fr>,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        let input = noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&witness)
                .unwrap_or(&FieldElement::zero()),
        );

        layouter.assign_region(
            || "region 1",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let value = Value::known(input);
                let limb_bit_len = 8;
                let bit_len = num_bits as usize;

                range_chip.assign(ctx, value, limb_bit_len, bit_len)?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

fn noir_field_to_halo2_field(noir_ele: FieldElement) -> Fr {
    let mut bytes = noir_ele.to_be_bytes();
    bytes.reverse();
    let mut halo_ele: [u8; 32] = [0; 32];
    halo_ele[..bytes.len()].copy_from_slice(&bytes[..]);
    Fr::from_bytes(&halo_ele).unwrap()
}
