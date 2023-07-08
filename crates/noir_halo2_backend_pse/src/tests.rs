#[cfg(test)]
mod test {
    // put in pse folder to avoid publishing mods

    use crate::{circuit_translator::NoirHalo2Translator, dimension_measure::DimensionMeasurement};
    use acvm::{acir::native_types::Witness, FieldElement};
    use noir_halo2_backend_common::test_helpers::build_artifacts;
    use pse_halo2wrong::{
        curves::bn256::Fr,
        halo2::{
            dev::{FailureLocation, MockProver, VerifyFailure},
            plonk::Any,
        },
    };
    use std::marker::PhantomData;

    #[test]
    fn test_public_io_circuit_success() {
        // get circuit
        let (circuit, witness_values) = build_artifacts("9_public_io", "pse_halo2_backend");

        // instantiate halo2 circuit
        let translator =
            NoirHalo2Translator::<Fr> { circuit, witness_values, _marker: PhantomData::<Fr> };
        let dimension = DimensionMeasurement::measure(&translator).unwrap();

        // instance value (known to be 7)
        let instance = vec![Fr::from_raw([7u64, 0, 0, 0])];

        // run mock prover expecting success
        let prover = MockProver::run(dimension.k(), &translator, vec![instance]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_public_io_circuit_fail_instance() {
        // get circuit
        let (circuit, witness_values) = build_artifacts("9_public_io", "pse_halo2_backend");

        // instantiate halo2 circuit
        let translator =
            NoirHalo2Translator::<Fr> { circuit, witness_values, _marker: PhantomData::<Fr> };
        let dimension = DimensionMeasurement::measure(&translator).unwrap();

        // instance value (known to be 7, incorrectly set to 8)
        let instance = vec![Fr::from_raw([8u64, 0, 0, 0])];

        // define permutation error expected when instance value is not set or incorrect
        let permutation_error = Err(vec![
            VerifyFailure::Permutation {
                column: (Any::advice(), 0).into(),
                location: FailureLocation::InRegion { region: (7, "region 0").into(), offset: 0 },
            },
            VerifyFailure::Permutation {
                column: (Any::Instance, 0usize).into(),
                location: FailureLocation::OutsideRegion { row: 0 },
            },
        ]);

        // run mock prover with incorrect instance expecting permutation failure
        let prover = MockProver::run(dimension.k(), &translator, vec![instance]).unwrap();
        assert_eq!(prover.verify(), permutation_error);

        // run mock prover with no instance expecting permutation failure
        let prover = MockProver::run(dimension.k(), &translator, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), permutation_error);
    }

    #[test]
    fn test_public_io_circuit_fail_witness() {
        // get circuit
        let (circuit, mut witness_values) = build_artifacts("9_public_io", "pse_halo2_backend");

        // mutate witness to be incorrect
        witness_values.insert(Witness(1), FieldElement::from(4u128));

        // instantiate halo2 circuit
        let translator =
            NoirHalo2Translator::<Fr> { circuit, witness_values, _marker: PhantomData::<Fr> };
        let dimension = DimensionMeasurement::measure(&translator).unwrap();

        // instance value (known to be 7)
        let instance = vec![Fr::from_raw([7u64, 0, 0, 0])];

        // run mock prover expecting success
        let prover = MockProver::run(dimension.k(), &translator, vec![instance]).unwrap();
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: ((0, "main_gate").into(), 0, "").into(),
                location: FailureLocation::InRegion { region: (5, "region 0").into(), offset: 5 },
                cell_values: vec![
                    (((Any::advice(), 0).into(), 0).into(), String::from("0x4")),
                    (((Any::advice(), 1).into(), 0).into(), String::from("0x4")),
                    (((Any::advice(), 2).into(), 0).into(), String::from("0x7")),
                    (((Any::advice(), 3).into(), 0).into(), String::from("0")),
                    (((Any::advice(), 4).into(), 0).into(), String::from("0")),
                    (((Any::advice(), 4).into(), 1).into(), String::from("0")),
                    (((Any::Fixed, 0).into(), 0).into(), String::from("-1")),
                    (((Any::Fixed, 1).into(), 0).into(), String::from("-1")),
                    (((Any::Fixed, 2).into(), 0).into(), String::from("1")),
                    (((Any::Fixed, 3).into(), 0).into(), String::from("0")),
                    (((Any::Fixed, 4).into(), 0).into(), String::from("0")),
                    (((Any::Fixed, 5).into(), 0).into(), String::from("0")),
                    (((Any::Fixed, 6).into(), 0).into(), String::from("0")),
                    (((Any::Fixed, 7).into(), 0).into(), String::from("0")),
                    (((Any::Fixed, 8).into(), 0).into(), String::from("0")),
                ]
            }])
        );
    }

    #[test]
    fn test_circuits_native() {
        let test_dirs_names = vec![
            "1_mul",
            "2_div",
            "3_add",
            "4_sub",
            "5_over",
            "6_array",
            "7_function",
            "8_bit_and",
        ];
        for program in test_dirs_names {
            // get circuit
            let (circuit, witness_values) = build_artifacts(program, "pse_halo2_backend");

            // instantiate halo2 circuit
            let translator =
                NoirHalo2Translator::<Fr> { circuit, witness_values, _marker: PhantomData::<Fr> };
            let dimension = DimensionMeasurement::measure(&translator).unwrap();

            // run mock prover expecting success
            let prover = MockProver::run(dimension.k(), &translator, vec![vec![]]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
