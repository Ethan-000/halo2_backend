use acvm::acir::{circuit::Circuit, native_types::WitnessMap};
use std::{fs::File, io::Read};

/**
 * Read an example circuit & pre-solved witness from a stored file
 *
 * @param example - The name of the example circuit to read
 * @return A tuple containing the deserialized circuit ACIR and the solved PWG
 */
#[allow(dead_code)]
pub fn get_circuit(example: &'static str) -> Result<(Circuit, WitnessMap), std::io::Error> {
    // read binary
    let mut circuit_buffer = Vec::new();
    File::open(format!("src/pse_halo2/test/bin/{example}/circuit.bin"))?
        .read_to_end(&mut circuit_buffer)?;
    let mut witness_buffer = Vec::new();
    File::open(format!("src/pse_halo2/test/bin/{example}/witness.bin"))?
        .read_to_end(&mut witness_buffer)?;
    // deserialize representation
    let circuit = Circuit::read(&*circuit_buffer)?;
    let witness = WitnessMap::try_from(&witness_buffer[..]).unwrap();
    Ok((circuit, witness))
}

#[cfg(feature = "pse_halo2")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        dimension_measure::DimensionMeasurement, pse_halo2::circuit_translator::NoirHalo2Translator,
    };
    use pse_halo2wrong::{
        curves::bn256::Fr,
        halo2::dev::{FailureLocation, MockProver, VerifyFailure},
        halo2::plonk::Any,
    };
    use std::marker::PhantomData;

    #[test]
    fn deserialize() {
        // let (circuit, witness) = get_circuit("and").unwrap();
        // println!("Add Circuit: {circuit:?}");
        // println!("Add Witnesses: {witness:?}");
        let (circuit, witness) = get_circuit("bit_and").unwrap();
        println!("Add Circuit: {circuit:?}");
        println!("Add Witnesses: {witness:?}");
    }

    #[test]
    fn write_bin() {
        // File::create("witness.bin")
        //     .unwrap()
        //     .write_all(&bit_and_witnesses);
        // // file.write_all()?;
    }

    #[test]
    fn test_add_circuit_success() {
        // get circuit
        let (circuit, witness_values) = get_circuit("add").unwrap();

        // instantiate halo2 circuit
        let translator = NoirHalo2Translator::<Fr> {
            circuit,
            witness_values,
            _marker: PhantomData::<Fr>,
        };
        let dimension = DimensionMeasurement::measure(&translator).unwrap();

        // instance value (known to be equal to 7)
        let instance = vec![Fr::from_raw([7u64, 0, 0, 0])];

        // run mock prover expecting success
        let prover = MockProver::run(dimension.k(), &translator, vec![instance]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_add_circuit_fail_wrong_instance() {
        // get circuit
        let (circuit, witness_values) = get_circuit("add").unwrap();

        // instantiate halo2 circuit
        let translator = NoirHalo2Translator::<Fr> {
            circuit,
            witness_values,
            _marker: PhantomData::<Fr>,
        };
        let dimension = DimensionMeasurement::measure(&translator).unwrap();

        // instance value (known to be 7, incorrectly set to 8)
        let instance = vec![Fr::from_raw([8u64, 0, 0, 0])];

        // define permutation error expected when instance value is not set or incorrect
        let permutation_error = Err(vec![
            VerifyFailure::Permutation {
                column: (Any::advice(), 0).into(),
                location: FailureLocation::InRegion {
                    region: (7, "region 0").into(),
                    offset: 0,
                },
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
    fn test_bit_and_circuit_success() {
        // get circuit
        let (circuit, witness) = get_circuit("bit_and").unwrap();

        // instantiate halo2 circuit
        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit,
            witness_values: witness,
            _marker: PhantomData::<Fr>,
        };
        let dimension = DimensionMeasurement::measure(&translator).unwrap();

        // run mock prover expecting success
        let prover = MockProver::run(dimension.k(), &translator, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
