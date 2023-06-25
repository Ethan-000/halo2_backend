use crate::{
    axiom_halo2::{
        assigned_map::AssignedMap, circuit_translator::NoirHalo2Translator,
        halo2_plonk_api::PlonkConfig,
    },
    impl_noir_field_to_secp255k1_field_conversion, noir_field_to_halo2_field,
    utils::Secp256k1FieldConversion,
};
use acvm::{
    acir::native_types::{Expression, Witness},
    FieldElement,
};
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::{
        bn256::Fr,
        secp256k1::{Fp, Fq, Secp256k1Affine},
        CurveAffine,
    },
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::FieldChip,
    secp256k1::{FpChip, FqChip},
};
use std::slice::Iter;

impl NoirHalo2Translator<Fr> {
    pub(crate) fn add_arithmetic_constrains(
        &self,
        gate: &Expression,
        config: &PlonkConfig,
        witness_assignments: &mut AssignedMap<Fr>,
    ) {
        let mut ctx: Context<Fr> = Context::<Fr>::new(false, 0);

        // store the constrained output of multiplied terms
        let mut solution: AssignedValue<Fr>;

        if !gate.mul_terms.is_empty() {
            // if there is a mul gate, take mul term selector, left, right, and constant then compute with gates:
            // mul gate: selector * left = intermediate
            // mul_add gate: intermediate * right + constant = output
            let mul_term = &gate.mul_terms[0];

            // assign terms or get existing assignnments
            let w_l = &witness_assignments.get_or_assign(
                &mut ctx,
                &mul_term.1,
                noir_field_to_halo2_field(
                    *self
                        .witness_values
                        .get(&mul_term.1)
                        .unwrap_or(&FieldElement::zero()),
                ),
            );
            let w_r = &witness_assignments.get_or_assign(
                &mut ctx,
                &mul_term.2,
                noir_field_to_halo2_field(
                    *self
                        .witness_values
                        .get(&mul_term.1)
                        .unwrap_or(&FieldElement::zero()),
                ),
            );

            // get coefficient/ selector term
            let coefficient = QuantumCell::Witness(noir_field_to_halo2_field(mul_term.0));
            // multiply coefficient / selector by left term
            let intermediate = config.gate_chip.mul(&mut ctx, coefficient, *w_l);
            // multiply product of coefficient and left term by right term, then add constant term
            let c = QuantumCell::Witness(noir_field_to_halo2_field(gate.q_c));

            solution = config.gate_chip.mul_add(&mut ctx, intermediate, *w_r, c);
        } else {
            // otherwise just assign the constant term
            solution = ctx.load_witness(noir_field_to_halo2_field(gate.q_c));
        }

        for term in &gate.linear_combinations {
            // get term selector and witness
            let coefficient = QuantumCell::Witness(noir_field_to_halo2_field(term.0));
            let variable = &witness_assignments.get_or_assign(
                &mut ctx,
                &term.1,
                noir_field_to_halo2_field(
                    *self
                        .witness_values
                        .get(&term.1)
                        .unwrap_or(&FieldElement::zero()),
                ),
            );
            // multiply to get term value & add to existing solution value
            solution = config
                .gate_chip
                .mul_add(&mut ctx, coefficient, *variable, solution);
        }

        // constrain the solution to the output to be equal to 0
        config.gate_chip.is_zero(&mut ctx, solution);
    }

    pub(crate) fn add_range_constrain(
        &self,
        witness: Witness,
        num_bits: u32,
        config: &PlonkConfig,
        witness_assignments: &mut AssignedMap<Fr>,
    ) {
        let mut ctx = Context::<Fr>::new(false, 0);

        // assign x or get existing assignnment
        let x = &witness_assignments.get_or_assign(
            &mut ctx,
            &witness,
            noir_field_to_halo2_field(
                *self
                    .witness_values
                    .get(&witness)
                    .unwrap_or(&FieldElement::zero()),
            ),
        );

        config
            .range_chip
            .range_check(&mut ctx, *x, num_bits as usize);
    }

    pub(crate) fn add_and_constrain(
        &self,
        lhs: Witness,
        rhs: Witness,
        output: Witness,
        config: &PlonkConfig,
        witness_assignments: &mut AssignedMap<Fr>,
    ) {
        let mut ctx = Context::<Fr>::new(false, 0);

        // assign lhs, rhs, output or get existing assignnments
        let lhs_v = &witness_assignments.get_or_assign(
            &mut ctx,
            &lhs,
            noir_field_to_halo2_field(
                *self
                    .witness_values
                    .get(&lhs)
                    .unwrap_or(&FieldElement::zero()),
            ),
        );
        let rhs_v = &witness_assignments.get_or_assign(
            &mut ctx,
            &rhs,
            noir_field_to_halo2_field(
                *self
                    .witness_values
                    .get(&rhs)
                    .unwrap_or(&FieldElement::zero()),
            ),
        );
        let output_v = &witness_assignments.get_or_assign(
            &mut ctx,
            &output,
            noir_field_to_halo2_field(
                *self
                    .witness_values
                    .get(&output)
                    .unwrap_or(&FieldElement::zero()),
            ),
        );

        let and_out = config.gate_chip.and(&mut ctx, *lhs_v, *rhs_v);

        config.gate_chip.is_equal(&mut ctx, *output_v, and_out);
    }

    pub(crate) fn add_ecdsa_secp256k1_constrain(
        &self,
        hashed_message: Vec<Witness>,
        signature: Vec<Witness>,
        public_key_x: Vec<Witness>,
        public_key_y: Vec<Witness>,
        result: Witness,
        config: &PlonkConfig,
    ) {
        let r = self.noir_field_to_secp255k1_fq_field(signature[..32].to_vec());
        let s = self.noir_field_to_secp255k1_fq_field(signature[32..].to_vec());
        let msghash = self.noir_field_to_secp255k1_fq_field(hashed_message);
        let public_key_x = self.noir_field_to_secp255k1_fp_field(public_key_x);
        let public_key_y = self.noir_field_to_secp255k1_fp_field(public_key_y);

        let pk = Secp256k1Affine::from_xy(public_key_x, public_key_y).unwrap();

        // loading the chip here instead of in config cus
        // puting them in a struct requires lifetime parameters
        // not sure if theres a way around this
        // this could be okay
        let mut ctx = Context::<Fr>::new(false, 0);
        let ecdsa_range_chip = RangeChip::<Fr>::default(17);
        let ecdsa_fp_chip = FpChip::new(&ecdsa_range_chip, 88, 3);
        let ecdsa_fq_chip = FqChip::new(&ecdsa_range_chip, 88, 3);

        let [m, r, s] = [msghash, r, s].map(|x| ecdsa_fq_chip.load_private(&mut ctx, x));

        let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&ecdsa_fp_chip);
        let pk = ecc_chip.load_private_unchecked(&mut ctx, (pk.x, pk.y));
        // test ECDSA
        let res = ecdsa_verify_no_pubkey_check::<Fr, Fp, Fq, Secp256k1Affine>(
            &ecc_chip, &mut ctx, pk, r, s, m, 4, 4,
        );
        assert_eq!(res.value(), &Fr::one());

        let result_value = noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&result)
                .unwrap_or(&FieldElement::zero()),
        );

        let output = ctx.load_witness(result_value);
        config.gate_chip.is_equal(&mut ctx, output, res);
    }
}

impl_noir_field_to_secp255k1_field_conversion!(NoirHalo2Translator, Fr, Fp, Fq);

noir_field_to_halo2_field!(Fr);
