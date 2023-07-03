// #[cfg(target_family = "wasm")]
// #[macro_export]
// macro_rules! impl_noir_halo2_backend_wasm_bindgen {
//     (
//         $halo2:ident
//     ) => {
//         use acvm::{
//             acir::{circuit::Circuit, native_types::WitnessMap},
//             CommonReferenceString, ProofSystemCompiler, SmartContract,
//         };
//         use tokio::runtime::Builder;
//         use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

//         #[wasm_bindgen]
//         pub fn init_panic_hook() {
//             console_error_panic_hook::set_once();
//         }

//         #[wasm_bindgen]
//         pub fn generate_common_reference_string(circuit_js: JsValue) -> Result<JsValue, JsValue> {
//             let runtime = Builder::new_current_thread().enable_all().build().unwrap();
//             let circuit: Circuit = serde_wasm_bindgen::from_value(circuit_js)?;

//             let fut = $halo2.generate_common_reference_string(&circuit);
//             let crs = runtime.block_on(fut).unwrap();

//             Ok(serde_wasm_bindgen::to_value(&crs)?)
//         }

//         #[wasm_bindgen]
//         pub fn get_exact_circuit_size(circuit_js: JsValue) -> Result<JsValue, JsValue> {
//             let circuit: Circuit = serde_wasm_bindgen::from_value(circuit_js)?;

//             let circuit_size = $halo2.get_exact_circuit_size(&circuit).unwrap();

//             Ok(serde_wasm_bindgen::to_value(&circuit_size)?)
//         }

//         #[wasm_bindgen]
//         pub fn get_proving_key(
//             common_reference_string_js: JsValue,
//             circuit_js: JsValue,
//         ) -> Result<JsValue, JsValue> {
//             let common_reference_string: Vec<u8> =
//                 serde_wasm_bindgen::from_value(common_reference_string_js)?;
//             let circuit: Circuit = serde_wasm_bindgen::from_value(circuit_js)?;

//             let (pk, _) = $halo2
//                 .preprocess(&common_reference_string, &circuit)
//                 .unwrap();

//             Ok(serde_wasm_bindgen::to_value(&pk)?)
//         }

//         #[wasm_bindgen]
//         pub fn get_verification_key(
//             common_reference_string_js: JsValue,
//             circuit_js: JsValue,
//         ) -> Result<JsValue, JsValue> {
//             let common_reference_string: Vec<u8> =
//                 serde_wasm_bindgen::from_value(common_reference_string_js)?;
//             let circuit: Circuit = serde_wasm_bindgen::from_value(circuit_js)?;

//             let (_, vk) = $halo2
//                 .preprocess(&common_reference_string, &circuit)
//                 .unwrap();

//             Ok(serde_wasm_bindgen::to_value(&vk)?)
//         }

//         #[wasm_bindgen]
//         pub fn prove_with_pk(
//             common_reference_string_js: JsValue,
//             circuit_js: JsValue,
//             witness_values_js: JsValue,
//             proving_key_js: JsValue,
//         ) -> Result<JsValue, JsValue> {
//             let common_reference_string: Vec<u8> =
//                 serde_wasm_bindgen::from_value(common_reference_string_js)?;
//             let circuit: Circuit = serde_wasm_bindgen::from_value(circuit_js)?;
//             let witness_values: WitnessMap = serde_wasm_bindgen::from_value(witness_values_js)?;
//             let proving_key: Vec<u8> = serde_wasm_bindgen::from_value(proving_key_js)?;

//             let proof = $halo2
//                 .prove_with_pk(
//                     &common_reference_string,
//                     &circuit,
//                     witness_values,
//                     &proving_key,
//                     false,
//                 )
//                 .unwrap();

//             Ok(serde_wasm_bindgen::to_value(&proof)?)
//         }

//         #[wasm_bindgen]
//         pub fn verify_with_pk(
//             common_reference_string_js: JsValue,
//             proof_js: JsValue,
//             public_inputs_js: JsValue,
//             circuit_js: JsValue,
//             verification_key_js: JsValue,
//         ) -> Result<JsValue, JsValue> {
//             let common_reference_string: Vec<u8> =
//                 serde_wasm_bindgen::from_value(common_reference_string_js)?;
//             let proof: Vec<u8> = serde_wasm_bindgen::from_value(proof_js)?;
//             let circuit: Circuit = serde_wasm_bindgen::from_value(circuit_js)?;
//             let public_inputs: WitnessMap = serde_wasm_bindgen::from_value(public_inputs_js)?;
//             let verification_key: Vec<u8> = serde_wasm_bindgen::from_value(verification_key_js)?;

//             let valid_proof = $halo2
//                 .verify_with_vk(
//                     &common_reference_string,
//                     &proof,
//                     public_inputs,
//                     &circuit,
//                     &verification_key,
//                     false,
//                 )
//                 .unwrap();

//             Ok(serde_wasm_bindgen::to_value(&valid_proof)?)
//         }

//         #[wasm_bindgen]
//         pub fn get_eth_verification_contract(
//             common_reference_string_js: JsValue,
//             verification_key_js: JsValue,
//         ) -> Result<String, JsValue> {
//             let common_reference_string: Vec<u8> =
//                 serde_wasm_bindgen::from_value(common_reference_string_js)?;
//             let verification_key: Vec<u8> = serde_wasm_bindgen::from_value(verification_key_js)?;

//             let contract = $halo2
//                 .eth_contract_from_vk(&common_reference_string, &verification_key)
//                 .unwrap();

//             Ok(contract)
//         }
//     };
// }
