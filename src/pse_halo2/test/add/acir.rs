// use acvm::acir::{
//     circuit::{
//         opcodes::{BlackBoxFuncCall, FunctionInput},
//         Opcode,
//     },

//     native_types::{Expression, Witness},
//     // BlackBoxFunc::
// };

// pub(crate) struct AddAcir {
//     pub opcodes: Vec<Opcode>,
//     pub witnesses: Vec<u32>,
// }

// const WITNESSES: Vec<u32> = vec![3, 4, 6, 7, 0, 0, 0, 0, 56, 0, 0, 0, 0, 4294967249, 7];

// pub(crate) const ADD_ACIR: AddAcir = AddAcir {
//     opcodes: vec![
//         Opcode::BlackBoxFuncCall::(BlackBoxFuncCall::RANGE { input: (Witness(WITNESES[0], 32)) })
//     ],
//     witnesses: WITNESSES,
// };
