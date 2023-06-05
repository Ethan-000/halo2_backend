use crate::{
    axiom_halo2::{
        circuit_translator::NoirHalo2Translator,
        halo2_plonk_api::{NoirConstraint, PlonkConfig, PolyTriple, StandardCs},
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
    halo2_proofs::{
        circuit::{Layouter, Value},
        halo2curves::{
            bn256::Fr,
            secp256k1::{Fp, Fq, Secp256k1Affine},
            CurveAffine,
        },
        plonk::Assigned,
    },
    Context,
};
use halo2_ecc::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::FieldChip,
    secp256k1::{FpChip, FqChip},
};
use std::slice::Iter;

impl NoirHalo2Translator<Fr> {
    #[allow(non_snake_case)]
    pub(crate) fn add_arithmetic_constrains(
        &self,
        gate: &Expression,
        cs: &impl StandardCs<Fr>,
        layouter: &mut impl Layouter<Fr>,
        // assignments: &mut AssignmentMap,
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

        // set assigned witness map
        // assignments.insert(Witness(noir_cs.a as u32), cells.0);
        // assignments.insert(Witness(noir_cs.b as u32), cells.1);
        // assignments.insert(Witness(noir_cs.c as u32), cells.2);
    }

    pub(crate) fn add_range_constrain(
        &self,
        witness: Witness,
        num_bits: u32,
        config: &PlonkConfig,
        // assignments: &mut AssignmentMap,
    ) {
        let mut ctx = Context::<Fr>::new(false, 0);

        let x = noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&witness)
                .unwrap_or(&FieldElement::zero()),
        );

        let x = ctx.load_witness(x);

        config
            .range_chip
            .range_check(&mut ctx, x, num_bits as usize);

        // set assigned witness map
        // assignments.insert(witness, x.)
    }

    pub(crate) fn add_and_constrain(
        &self,
        lhs: Witness,
        rhs: Witness,
        output: Witness,
        config: &PlonkConfig,
        // assignments: &mut AssignmentMap,
    ) {
        let mut ctx = Context::<Fr>::new(false, 0);
        let lhs_v = noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&lhs)
                .unwrap_or(&FieldElement::zero()),
        );

        let rhs_v = noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&rhs)
                .unwrap_or(&FieldElement::zero()),
        );

        let output_v = noir_field_to_halo2_field(
            *self
                .witness_values
                .get(&output)
                .unwrap_or(&FieldElement::zero()),
        );

        let a = ctx.load_witness(lhs_v);
        let b = ctx.load_witness(rhs_v);
        let c = ctx.load_witness(output_v);

        let and_out = config.gate_chip.and(&mut ctx, a, b);

        config.gate_chip.is_equal(&mut ctx, c, and_out);
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
