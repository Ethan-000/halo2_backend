use crate::pse_halo2::circuit_translator::NoirHalo2Translator;
use acvm::acir::circuit::Circuit;
use acvm::acir::native_types::WitnessMap;
use pse_halo2wrong::curves::bn256::Fr;

use std::fs::File;
use std::io::{self, Read, Write};

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
        println!("Add Circuit: {:?}", circuit);
        println!("Add Witnesses: {:?}", witness);
    }

    #[test]
    fn write_bin() {
        // File::create("witness.bin")
        //     .unwrap()
        //     .write_all(&bit_and_witnesses);
        // // file.write_all()?;
    }

    fn test_add_circuit() {
        // let translator = NoirHalo2Translator::<Fr> {
        //     circuit: circuit.clone(),
        //     witness_values,
        //     _marker: PhantomData::<Fr>,
        // };
    }
}
