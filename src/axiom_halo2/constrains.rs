use std::slice::Iter;

use crate::axiom_halo2::halo2_plonk_api::{PlonkConfig, PolyTriple, StandardCs};
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

use crate::axiom_halo2::circuit_translator::NoirHalo2Translator;

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

    pub(crate) fn add_range_constrain(
        &self,
        witness: Witness,
        num_bits: u32,
        config: &PlonkConfig,
    ) {
        let mut ctx = Context::<Fr>::new(true, 0);

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
    }

    pub(crate) fn add_and_constrain(
        &self,
        lhs: Witness,
        rhs: Witness,
        output: Witness,
        config: &PlonkConfig,
    ) {
        let mut ctx = Context::<Fr>::new(true, 0);
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
        let mut ctx = Context::<Fr>::new(true, 0);
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

impl NoirHalo2Translator<Fr> {
    fn noir_field_to_secp255k1_fq_field(&self, limbs: Vec<Witness>) -> Fq {
        let binding: Vec<u8> = limbs
            .into_iter()
            .map(|w| *self.witness_values.get(&w).unwrap_or(&FieldElement::zero()))
            .flat_map(|ele| ele.to_be_bytes())
            .collect::<Vec<u8>>();

        let mut element_bytes = [0u8; 32];
        let mut element_vec: Iter<u8> = binding.iter();
        for byte in element_bytes.iter_mut() {
            *byte = *element_vec.next().unwrap();
        }

        Fq::from_bytes(&element_bytes).unwrap()
    }

    fn noir_field_to_secp255k1_fp_field(&self, limbs: Vec<Witness>) -> Fp {
        let binding: Vec<u8> = limbs
            .into_iter()
            .map(|w| *self.witness_values.get(&w).unwrap_or(&FieldElement::zero()))
            .flat_map(|ele| ele.to_be_bytes())
            .collect::<Vec<u8>>();

        let mut element_bytes = [0u8; 32];
        let mut element_vec: Iter<u8> = binding.iter();
        for byte in element_bytes.iter_mut() {
            *byte = *element_vec.next().unwrap();
        }

        Fp::from_bytes(&element_bytes).unwrap()
    }
}

fn noir_field_to_halo2_field(noir_ele: FieldElement) -> Fr {
    let mut bytes = noir_ele.to_be_bytes();
    bytes.reverse();
    let mut halo_ele: [u8; 32] = [0; 32];
    halo_ele[..bytes.len()].copy_from_slice(&bytes[..]);
    Fr::from_bytes(&halo_ele).unwrap()
}
