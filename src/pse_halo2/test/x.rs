use crate::pse_halo2::circuit_translator::NoirHalo2Translator;
use crate::dimension_measure::DimensionMeasurement;
use acvm::acir::circuit::Circuit;
use acvm::acir::native_types::WitnessMap;
use pse_halo2wrong::curves::bn256::Fr;
use pse_halo2wrong::halo2::dev::MockProver;

use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;

/**
 * Read an example circuit & pre-solved witness from a stored file
 *
 * @param example - The name of the example circuit to read
 * @return A tuple containing the deserialized circuit ACIR and the solved PWG
 */
pub fn get_circuit(example: &'static str) -> Result<(Circuit, WitnessMap), std::io::Error> {
    // read binary
    let mut circuit_buffer = Vec::new();
    File::open(format!("src/pse_halo2/test/bin/{}/circuit.bin", example))?
        .read_to_end(&mut circuit_buffer)?;
    let mut witness_buffer = Vec::new();
    File::open(format!("src/pse_halo2/test/bin/{}/witness.bin", example))?
        .read_to_end(&mut witness_buffer)?;
    // deserialize representation
    let circuit = Circuit::read(&*circuit_buffer)?;
    let witness = WitnessMap::try_from(&witness_buffer[..]).unwrap();
    Ok((circuit, witness))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn deserialize() {
        let (circuit, witness) = get_circuit("add").unwrap();
        // println!("Add Circuit: {:?}", circuit);
        // println!("Add Witnesses: {:?}", witness);
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
        let (circuit, witness) = get_circuit("add").unwrap();

        // instantiate halo2 circuit
        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values: witness.clone(),
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
    fn test_bit_and_circuit_success() {
        // get circuit
        let (circuit, witness) = get_circuit("bit_and").unwrap();

        // instantiate halo2 circuit
        let translator = NoirHalo2Translator::<Fr> {
            circuit: circuit.clone(),
            witness_values: witness.clone(),
            _marker: PhantomData::<Fr>,
        };
        let dimension = DimensionMeasurement::measure(&translator).unwrap();

        // run mock prover expecting success
        let prover = MockProver::run(dimension.k(), &translator, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
