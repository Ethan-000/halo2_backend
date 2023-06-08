use acvm::{
    acir::native_types::{Expression, Witness},
    FieldElement,
};
use halo2wrong_sha256::sha256::{BlockWordNew, Sha256, Table16Chip};
use pse_ecc::{
    integer::{IntegerInstructions, Range},
    GeneralEccChip,
};
use pse_ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use pse_halo2wrong::{
    curves::{
        secp256k1::{Fp, Fq, Secp256k1Affine},
        CurveAffine,
    },
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
use sha2::Digest;

use std::slice::Iter;

use crate::{
    impl_noir_field_to_secp255k1_field_conversion, noir_field_to_halo2_field,
    pse_halo2::circuit_translator::NoirHalo2Translator, utils::Secp256k1FieldConversion,
};

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

    pub(crate) fn add_and_constrain(
        &self,
        lhs: Witness,
        rhs: Witness,
        output: Witness,
        config: &PlonkConfig,
        layouter: &mut impl Layouter<Fr>,
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

                let c1 = main_gate.assign_to_column(ctx, lhs_v, MainGateColumn::A)?;
                let c2 = main_gate.assign_to_column(ctx, rhs_v, MainGateColumn::B)?;
                let out = main_gate.assign_to_column(ctx, output_v, MainGateColumn::C)?;
                let result = main_gate.and(ctx, &c1, &c2)?;

                main_gate.assert_equal(ctx, &out, &result)?;

                Ok(())
            },
        )?;

        Ok(())
    }

    pub(crate) fn add_sha256_constrain(
        &self,
        sha256_input: Vec<(Witness, u32)>,
        _result: Vec<Witness>,
        config: &PlonkConfig,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        Table16Chip::load(config.sha256_config.clone().unwrap(), layouter)?;
        let table16_chip = Table16Chip::construct(config.sha256_config.clone().unwrap());

        let sha256_input: Vec<u8> = sha256_input
            .into_iter()
            .flat_map(|(witness, num_bits)| {
                (*self
                    .witness_values
                    .get(&witness)
                    .unwrap_or(&FieldElement::zero()))
                .fetch_nearest_bytes(num_bits as usize)
            })
            .collect();

        // let message_bits = sha256_input.len() * 8;
        // sha256_input.push(128);

        // let bytes_per_block = 64;
        // let num_bytes = sha256_input.len() + 8;
        // let num_blocks = num_bytes / bytes_per_block + (num_bytes % bytes_per_block != 0) as usize;

        // let num_total_bytes = num_blocks * bytes_per_block;
        // sha256_input.resize(num_total_bytes, 0);

        // sha256_input.extend_from_slice([message_bits as u8; 8].as_slice());

        // let sha256_input: Vec<u32> = sha256_input
        //     .chunks(4)
        //     .map(|x| {
        //         let mut bytes = [0; 4];
        //         bytes.copy_from_slice(x);
        //         u32::from_le_bytes(bytes)
        //     })
        //     .collect();

        let mut block_words = Vec::new();

        for i in sha256_input {
            let block_word = BlockWordNew(Value::known(i));
            block_words.push(block_word)
        }

        let test = vec![BlockWordNew(Value::known(1))];
        let digest = Sha256::digest(table16_chip, layouter.namespace(|| "sha256"), &test)?;
        // let output: Vec<Value<Fr>> = self
        //     .process_hash_output(result)
        //     .into_iter()
        //     .map(Value::known)
        //     .collect();

        let test = 1_u8;

        let mut hasher = sha2::Sha256::new();

        hasher.update([test]);

        let output = hasher.finalize();

        println!(
            "digest: {:?}",
            digest
                .into_iter()
                .map(|x| x.map(|u| u.to_bytes()))
                .collect::<Vec<Value<[u8; 32]>>>()
        );

        println!("{output:?}");

        // let mut noir_field_elements = Vec::new();
        // for i in result {
        //     let element = *self.witness_values.get(&i).unwrap_or(&FieldElement::zero());
        //     noir_field_elements.push(element);
        // }

        // println!(
        //     "output: {:?}",
        //     noir_field_elements
        //         .into_iter()
        //         .map(|x| x.to_be_bytes())
        //         .collect::<Vec<Vec<u8>>>()
        // );

        // layouter.assign_region(
        //     || "region 0",
        //     |region| {
        //         let offset = 0;
        //         let ctx = &mut RegionCtx::new(region, offset);
        //         let main_gate = MainGate::<Fr>::new(config.main_gate_config.clone());

        //         for i in 0..digest.len() {
        //             let c1 = main_gate.assign_to_column(ctx, digest[i], MainGateColumn::A)?;
        //             let c2 = main_gate.assign_to_column(ctx, output[i], MainGateColumn::B)?;
        //             main_gate.assert_equal(ctx, &c1, &c2)?;
        //         }

        //         Ok(())
        //     },
        // )?;

        Ok(())
    }

    pub(crate) fn add_ecdsa_secp256k1_constrain(
        &self,
        hashed_message: Vec<Witness>,
        signature: Vec<Witness>,
        public_key_x: Vec<Witness>,
        public_key_y: Vec<Witness>,
        layouter: &mut impl Layouter<Fr>,
        ecc_chip: GeneralEccChip<Secp256k1Affine, Fr, 4, 68>,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        let r = self.noir_field_to_secp255k1_fq_field(signature[..32].to_vec());
        let s = self.noir_field_to_secp255k1_fq_field(signature[32..].to_vec());
        let msghash = self.noir_field_to_secp255k1_fq_field(hashed_message);
        let public_key_x = self.noir_field_to_secp255k1_fp_field(public_key_x);
        let public_key_y = self.noir_field_to_secp255k1_fp_field(public_key_y);

        let pk = Secp256k1Affine::from_xy(public_key_x, public_key_y).unwrap();

        let signature = Value::known((r, s));
        let public_key = Value::known(pk);
        let msg_hash = Value::known(msghash);

        // layouter.assign_region(
        //     || "assign aux values",
        //     |region| {
        //         let offset = 0;
        //         let ctx = &mut RegionCtx::new(region, offset);

        //         ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
        //         ecc_chip.assign_aux(ctx, self.window_size, 2)?;
        //         Ok(())
        //     },
        // )?;

        let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());
        let scalar_chip = ecc_chip.scalar_field_chip();

        layouter.assign_region(
            || "region 1",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let r = signature.map(|signature| signature.0);
                let s = signature.map(|signature| signature.1);
                let integer_r = ecc_chip.new_unassigned_scalar(r);
                let integer_s = ecc_chip.new_unassigned_scalar(s);
                let msg_hash = ecc_chip.new_unassigned_scalar(msg_hash);

                let r_assigned = scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;
                let s_assigned = scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;
                let sig = AssignedEcdsaSig {
                    r: r_assigned,
                    s: s_assigned,
                };

                let pk_in_circuit = ecc_chip.assign_point(ctx, public_key)?;
                let pk_assigned = AssignedPublicKey {
                    point: pk_in_circuit,
                };
                let msg_hash = scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;
                ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)
            },
        )?;

        Ok(())
    }
}

impl NoirHalo2Translator<Fr> {
    fn _process_hash_output(&self, witnesses: Vec<Witness>) -> Vec<Fr> {
        let mut noir_field_elements = Vec::new();
        for i in witnesses {
            let element = *self.witness_values.get(&i).unwrap_or(&FieldElement::zero());
            noir_field_elements.push(element);
        }
        let mut halo2_field_elements = Vec::new();
        noir_field_elements.chunks(4).for_each(|bytes| {
            let mut first_byte = bytes[0].to_be_bytes();
            first_byte.reverse();
            let mut second_byte = bytes[1].to_be_bytes();
            second_byte.reverse();
            let mut third_byte = bytes[2].to_be_bytes();
            third_byte.reverse();
            let mut fourth_byte = bytes[3].to_be_bytes();
            fourth_byte.reverse();
            let mut halo_ele: [u8; 32] = [0; 32];
            halo_ele[..8].copy_from_slice(&first_byte[..8]);
            halo_ele[8..16].copy_from_slice(&second_byte[8..16]);
            halo_ele[16..24].copy_from_slice(&third_byte[16..24]);
            halo_ele[24..32].copy_from_slice(&fourth_byte[24..32]);
            halo2_field_elements.push(Fr::from_bytes(&halo_ele).unwrap());
        });

        halo2_field_elements
    }
}

impl_noir_field_to_secp255k1_field_conversion!(NoirHalo2Translator, Fr, Fp, Fq);

noir_field_to_halo2_field!(Fr);
