use acvm::{
    acir::native_types::{Expression, Witness},
    FieldElement,
};

use pse_halo2wrong::{
    halo2::{
        circuit::{AssignedCell, Layouter, Value},
        halo2curves::bn256::Fr,
    },
    RegionCtx,
};
use pse_maingate::{
    CombinationOption, MainGate, MainGateColumn, MainGateInstructions, RangeChip,
    RangeInstructions, Term,
};

use crate::{
    noir_field_to_halo2_field,
    pse_halo2::{assigned_map::AssignedMap, circuit_translator::NoirHalo2Translator},
};

use super::halo2_plonk_api::{NoirConstraint, PlonkConfig};

impl NoirHalo2Translator<Fr> {
    pub(crate) fn add_arithmetic_constrains(
        &self,
        gate: &Expression,
        config: &PlonkConfig,
        layouter: &mut impl Layouter<Fr>,
        witness_assignments: &mut AssignedMap<Fr>,
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
                check_and_copy(ctx, witness_assignments, noir_cs.a as u32, &a)?;
                terms.push(Term::Assigned(&a, ql));

                let b = main_gate.assign_to_column(ctx, b, MainGateColumn::B)?;
                check_and_copy(ctx, witness_assignments, noir_cs.b as u32, &b)?;
                terms.push(Term::Assigned(&b, qr));

                let c = main_gate.assign_to_column(ctx, c, MainGateColumn::C)?;
                check_and_copy(ctx, witness_assignments, noir_cs.c as u32, &c)?;
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

                // store assignments to a, b, c
                witness_assignments.insert(Witness(noir_cs.a as u32), a);
                witness_assignments.insert(Witness(noir_cs.b as u32), b);
                witness_assignments.insert(Witness(noir_cs.c as u32), c);

                Ok(())
            },
        )?;

        //

        Ok(())
    }

    pub(crate) fn add_range_constrain(
        &self,
        witness: Witness,
        num_bits: u32,
        range_chip: &RangeChip<Fr>,
        layouter: &mut impl Layouter<Fr>,
        witness_assignments: &mut AssignedMap<Fr>,
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

                let cell = range_chip.assign(ctx, value, limb_bit_len, bit_len)?;
                check_and_copy(ctx, witness_assignments, witness.0, &cell)?;

                // add to assignment map
                witness_assignments.insert(witness, cell);

                Ok(())
            },
        )?;

        Ok(())
    }

    pub(crate) fn add_and_constrain(
        &self,
        lhs: Witness,
        rhs: Witness,
        output: Witness,
        config: &PlonkConfig,
        layouter: &mut impl Layouter<Fr>,
        witness_assignments: &mut AssignedMap<Fr>,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        let lhs_v = Value::known(noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&lhs)
                .unwrap_or(&FieldElement::zero()),
        ));

        let rhs_v = Value::known(noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&rhs)
                .unwrap_or(&FieldElement::zero()),
        ));

        let output_v = Value::known(noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&output)
                .unwrap_or(&FieldElement::zero()),
        ));

        layouter.assign_region(
            || "region 0",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let main_gate = MainGate::<Fr>::new(config.main_gate_config.clone());

                let lhs_cell = main_gate.assign_to_column(ctx, lhs_v, MainGateColumn::A)?;
                check_and_copy(ctx, witness_assignments, lhs.0, &lhs_cell)?;

                let rhs_cell = main_gate.assign_to_column(ctx, rhs_v, MainGateColumn::B)?;
                check_and_copy(ctx, witness_assignments, rhs.0, &rhs_cell)?;

                let output_cell = main_gate.assign_to_column(ctx, output_v, MainGateColumn::C)?;
                check_and_copy(ctx, witness_assignments, output.0, &output_cell)?;

                let result = main_gate.and(ctx, &lhs_cell, &rhs_cell)?;
                main_gate.assert_equal(ctx, &output_cell, &result)?;

                // add to assignment map
                witness_assignments.insert(lhs, lhs_cell);
                witness_assignments.insert(rhs, rhs_cell);
                witness_assignments.insert(output, output_cell);

                Ok(())
            },
        )?;

        Ok(())
    }

    pub(crate) fn expose_public(
        &self,
        config: &PlonkConfig,
        layouter: &mut impl Layouter<Fr>,
        witness_assignments: &AssignedMap<Fr>,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        // get public witness indices from noir circuit
        let public_indices = self.circuit.public_inputs().indices();
        // instnantiate new main gate
        let main_gate = MainGate::<Fr>::new(config.main_gate_config.clone());
        // loop through public witness indices and expose publicly through main gate
        for (i, _) in public_indices.iter().enumerate() {
            let assigned = witness_assignments
                .get_index(public_indices[i])
                .unwrap()
                .last()
                .unwrap();
            main_gate.expose_public(
                layouter.namespace(|| format!("Public IO #{i:?}")),
                assigned.clone(),
                i,
            )?;
        }
        Ok(())
    }
}

// check for equality during assignment

/// Check if a given acir witness index needs a copy constraint when assigning a witness to a halo2 cell.
/// If so, perform an equality constraint on a given cell if a given witness appears in the assignment map
//
// @param ctx - the context for the region being assigned to
// @param assignments - the assignment map of acir witness index to exsiting halo2 cells storing witness assignments
// @param witness - the acir witness index to check for
// @param cell - the newly assigned cell to copy constrain with a cell stored in the assignment map
// @return - success if copy constraint operation succeeds
pub fn check_and_copy(
    ctx: &mut RegionCtx<Fr>,
    assignments: &AssignedMap<Fr>,
    witness: u32,
    cell: &AssignedCell<Fr, Fr>,
) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
    if assignments.contains_key(&Witness(witness)) {
        let witness_cell = assignments.get_index(witness).unwrap().last().unwrap();
        ctx.constrain_equal(witness_cell.cell(), cell.cell())
    } else {
        Ok(())
    }
}

noir_field_to_halo2_field!(Fr);
