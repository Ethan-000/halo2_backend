use acvm::acir::{circuit::Circuit, native_types::WitnessMap};
use serde_json::Value;
use std::{fs::File, io::Read};

pub fn install_nargo(backend: &'static str) {
    // Clone noir into repo
    std::process::Command::new("git")
        .arg("clone")
        .arg("https://github.com/Ethan-000/noir")
        .arg("--branch")
        .arg("add_halo2_backend")
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    format!("\nInstalling {backend}. This may take a few moments.",);
    // Install specified backend into noir
    std::process::Command::new("cargo")
        .current_dir(std::fs::canonicalize("./noir/crates/nargo_cli").unwrap())
        .arg("install")
        .arg("--path")
        .arg(".")
        .arg("--locked")
        .arg("--features")
        .arg(backend)
        .arg("--no-default-features")
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}

/**
 * Given a test_program circuit program name, build the circuit and witness artifacts & return the deserialized objects
 *
 * @param program - program name for circuit to be compiled and solved
 * @return - the deserialized ACIR and solved witness (given the saved Prover.toml)
 */
#[allow(dead_code)]
pub fn build_artifacts(program: &'static str) -> (Circuit, WitnessMap) {
    install_nargo("axiom_halo2_backend");
    // format path to test program
    let path = format!("./tests/test_programs/{program}/");

    // build circuit bytecode
    _ = std::process::Command::new("nargo")
        .current_dir(&path)
        .arg("compile")
        .arg("circuit")
        .spawn()
        .unwrap()
        .wait_with_output();
    // generate circuit witness
    _ = std::process::Command::new("nargo")
        .current_dir(&path)
        .arg("execute")
        .arg("witness")
        .spawn()
        .unwrap()
        .wait_with_output();

    // load circuit
    let mut contents = String::new();
    File::open(format!("{path}target/circuit.json"))
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();
    let json: Value = serde_json::from_str(&contents).unwrap();
    let bytecode: Vec<u8> = json
        .get("bytecode")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(|v| v.as_u64().map(|n| n as u8))
        .collect();
    let circuit = Circuit::read(&*bytecode).unwrap();

    // load witness
    let mut witness_buffer = Vec::new();
    File::open(format!("{path}target/witness.tr"))
        .unwrap()
        .read_to_end(&mut witness_buffer)
        .unwrap();
    let witness = WitnessMap::try_from(&witness_buffer[..]).unwrap();

    (circuit, witness)
}

#[cfg(feature = "axiom_halo2")]
#[cfg(test)]
mod test {
    // put in axiom folder to avoid publishing mods
    use super::*;
    use crate::{
        axiom_halo2::circuit_translator::NoirHalo2Translator,
        dimension_measure::DimensionMeasurement,
    };
    use acvm::{acir::native_types::Witness, FieldElement};
    use halo2_base::halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
        plonk::Any,
    };
    use std::marker::PhantomData;

    // #[test]
    // fn test_public_io_circuit_success() {
    //     // get circuit
    //     let (circuit, witness_values) = build_artifacts("9_public_io");

    //     // instantiate halo2 circuit
    //     let translator = NoirHalo2Translator::<Fr> {
    //         circuit,
    //         witness_values,
    //         _marker: PhantomData::<Fr>,
    //     };
    //     let dimension = DimensionMeasurement::measure(&translator).unwrap();

    //     // instance value (known to be 7)
    //     let instance = vec![Fr::from_raw([7u64, 0, 0, 0])];

    //     // run mock prover expecting success
    //     let prover = MockProver::run(dimension.k(), &translator, vec![instance]).unwrap();
    //     assert_eq!(prover.verify(), Ok(()));
    // }

    // #[test]
    // fn test_public_io_circuit_fail_instance() {
    //     // get circuit
    //     let (circuit, witness_values) = build_artifacts("9_public_io");

    //     // instantiate halo2 circuit
    //     let translator = NoirHalo2Translator::<Fr> {
    //         circuit,
    //         witness_values,
    //         _marker: PhantomData::<Fr>,
    //     };
    //     let dimension = DimensionMeasurement::measure(&translator).unwrap();

    //     // instance value (known to be 7, incorrectly set to 8)
    //     let instance = vec![Fr::from_raw([8u64, 0, 0, 0])];

    //     // define permutation error expected when instance value is not set or incorrect
    //     let permutation_error = Err(vec![
    //         VerifyFailure::Permutation {
    //             column: (Any::advice(), 0).into(),
    //             location: FailureLocation::InRegion {
    //                 region: (7, "region 0").into(),
    //                 offset: 0,
    //             },
    //         },
    //         VerifyFailure::Permutation {
    //             column: (Any::Instance, 0usize).into(),
    //             location: FailureLocation::OutsideRegion { row: 0 },
    //         },
    //     ]);

    //     // run mock prover with incorrect instance expecting permutation failure
    //     let prover = MockProver::run(dimension.k(), &translator, vec![instance]).unwrap();
    //     assert_eq!(prover.verify(), permutation_error);

    //     // run mock prover with no instance expecting permutation failure
    //     let prover = MockProver::run(dimension.k(), &translator, vec![vec![]]).unwrap();
    //     assert_eq!(prover.verify(), permutation_error);
    // }

    // #[test]
    // fn test_public_io_circuit_fail_witness() {
    //     // get circuit
    //     let (circuit, mut witness_values) = build_artifacts("9_public_io");

    //     // mutate witness to be incorrect
    //     witness_values.insert(Witness(1), FieldElement::from(4u128));

    //     // instantiate halo2 circuit
    //     let translator = NoirHalo2Translator::<Fr> {
    //         circuit,
    //         witness_values,
    //         _marker: PhantomData::<Fr>,
    //     };
    //     let dimension = DimensionMeasurement::measure(&translator).unwrap();

    //     // instance value (known to be 7)
    //     let instance = vec![Fr::from_raw([7u64, 0, 0, 0])];

    //     // run mock prover expecting success
    //     let prover = MockProver::run(dimension.k(), &translator, vec![instance]).unwrap();
    //     assert_eq!(
    //         prover.verify(),
    //         Err(vec![VerifyFailure::ConstraintNotSatisfied {
    //             constraint: ((0, "main_gate").into(), 0, "").into(),
    //             location: FailureLocation::InRegion {
    //                 region: (5, "region 0").into(),
    //                 offset: 5,
    //             },
    //             cell_values: vec![
    //                 (((Any::advice(), 0).into(), 0).into(), String::from("0x4")),
    //                 (((Any::advice(), 1).into(), 0).into(), String::from("0x4")),
    //                 (((Any::advice(), 2).into(), 0).into(), String::from("0x7")),
    //                 (((Any::advice(), 3).into(), 0).into(), String::from("0")),
    //                 (((Any::advice(), 4).into(), 0).into(), String::from("0")),
    //                 (((Any::advice(), 4).into(), 1).into(), String::from("0")),
    //                 (((Any::Fixed, 0).into(), 0).into(), String::from("-1")),
    //                 (((Any::Fixed, 1).into(), 0).into(), String::from("-1")),
    //                 (((Any::Fixed, 2).into(), 0).into(), String::from("1")),
    //                 (((Any::Fixed, 3).into(), 0).into(), String::from("0")),
    //                 (((Any::Fixed, 4).into(), 0).into(), String::from("0")),
    //                 (((Any::Fixed, 5).into(), 0).into(), String::from("0")),
    //                 (((Any::Fixed, 6).into(), 0).into(), String::from("0")),
    //                 (((Any::Fixed, 7).into(), 0).into(), String::from("0")),
    //                 (((Any::Fixed, 8).into(), 0).into(), String::from("0")),
    //             ]
    //         }])
    //     );
    // }

    // #[test]
    // fn test_add_circuit_success() {
    //     // get circuit
    //     let (circuit, witness_values) = build_artifacts("9_public_io");
    //     // instantiate halo2 circuit
    //     let translator = NoirHalo2Translator::<Fr> {
    //         circuit,
    //         witness_values,
    //         _marker: PhantomData::<Fr>,
    //     };
    //     let dimension = DimensionMeasurement::measure(&translator).unwrap();

    //     // instance value (known to be equal to 7)
    //     let instance = vec![Fr::from_raw([7u64, 0, 0, 0])];

    //     // run mock prover expecting success
    //     let prover = MockProver::run(dimension.k(), &translator, vec![instance]).unwrap();
    //     assert_eq!(prover.verify(), Ok(()));
    // }

    // #[test]
    // fn test_add_circuit_success() {
    //     // get circuit
    //     let (circuit, witness_values) = build_artifacts("3_add");
    //     // instantiate halo2 circuit
    //     let translator = NoirHalo2Translator::<Fr> {
    //         circuit,
    //         witness_values,
    //         _marker: PhantomData::<Fr>,
    //     };
    //     let dimension = DimensionMeasurement::measure(&translator).unwrap();

    //     // instance value (known to be equal to 7)
    //     // let instance = vec![Fr::from_raw([7u64, 0, 0, 0])];
    //     // run mock prover expecting success
    //     let prover = MockProver::run(dimension.k(), &translator, vec![]).unwrap();
    //     assert_eq!(prover.verify(), Ok(()));
    // }

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
            let (circuit, witness_values) = build_artifacts(program);

            // instantiate halo2 circuit
            let translator = NoirHalo2Translator::<Fr> {
                circuit,
                witness_values,
                _marker: PhantomData::<Fr>,
            };
            let dimension = DimensionMeasurement::measure(&translator).unwrap();

            // run mock prover expecting success
            let prover = MockProver::run(dimension.k(), &translator, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
