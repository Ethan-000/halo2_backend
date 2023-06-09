use acvm::{
    acir::circuit::{opcodes::BlackBoxFuncCall, Opcode},
    FieldElement,
};

use pse_halo2wrong::halo2::{
    halo2curves::bn256::Fr,
    halo2curves::{
        bn256::{Bn256, G1Affine, G1},
        group::cofactor::CofactorCurve,
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ConstraintSystem, Error, ProvingKey,
        VerifyingKey,
    },
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverGWC, VerifierGWC},
        strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};

use pse_maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::pse_halo2::circuit_translator::NoirHalo2Translator;

/// Generate Halo2 Proving and Verifying Keys
pub fn halo2_keygen(
    circuit: &NoirHalo2Translator<Fr>,
    params: &ParamsKZG<Bn256>,
) -> (
    ProvingKey<<G1 as CofactorCurve>::Affine>,
    VerifyingKey<<G1 as CofactorCurve>::Affine>,
) {
    let vk = keygen_vk(params, circuit).expect("keygen_vk should not fail");
    let vk_return = vk.clone();
    let pk = keygen_pk(params, vk, circuit).expect("keygen_pk should not fail");
    (pk, vk_return)
}

/// Generate Halo2 Proof
pub fn halo2_prove(
    circuit: NoirHalo2Translator<Fr>,
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<<G1 as CofactorCurve>::Affine>,
    public_inputs: &[Fr],
) -> Vec<u8> {
    let rng = OsRng;
    let mut transcript: Blake2bWrite<Vec<u8>, _, Challenge255<_>> =
        Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
        _,
    >(
        params,
        pk,
        &[circuit],
        &[&[public_inputs]],
        rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    transcript.finalize()
}

/// Verify Halo2 Proof
pub fn halo2_verify(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<<G1 as CofactorCurve>::Affine>,
    proof: &[u8],
    public_inputs: &[Fr],
) -> Result<(), Error> {
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(params, vk, strategy, &[&[public_inputs]], &mut transcript)
}

#[derive(Clone, Debug)]
pub struct PlonkConfig {
    pub(crate) main_gate_config: MainGateConfig,
    pub(crate) range_config: RangeConfig,
}

impl PlonkConfig {
    /// Default configuration
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let main_gate_config = MainGate::<Fr>::configure(meta);

        let overflow_bit_lens: Vec<usize> = vec![1, 2, 3, 4, 5, 6, 7];
        let composition_bit_lens = vec![8];

        let range_config = RangeChip::<Fr>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        PlonkConfig {
            main_gate_config,
            range_config,
        }
    }

    pub(crate) fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        _opcodes_flags: OpcodeFlags,
    ) -> Self {
        let main_gate_config = MainGate::<Fr>::configure(meta);

        let overflow_bit_lens: Vec<usize> = vec![1, 2, 3, 4, 5, 6, 7];
        let composition_bit_lens = vec![8];

        let range_config = RangeChip::<Fr>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        PlonkConfig {
            main_gate_config,
            range_config,
        }
    }
}

#[derive(Clone, Hash, Debug, Serialize, Deserialize)]
pub(crate) struct NoirConstraint {
    pub(crate) a: i32,
    pub(crate) b: i32,
    pub(crate) c: i32,
    pub(crate) qm: FieldElement,
    pub(crate) ql: FieldElement,
    pub(crate) qr: FieldElement,
    pub(crate) qo: FieldElement,
    pub(crate) qc: FieldElement,
}

impl Default for NoirConstraint {
    fn default() -> Self {
        NoirConstraint {
            a: 0,
            b: 0,
            c: 0,
            qm: FieldElement::zero(),
            ql: FieldElement::zero(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: FieldElement::zero(),
        }
    }
}

impl NoirConstraint {
    pub(crate) fn set_linear_term(&mut self, x: FieldElement, witness: i32) {
        if self.a == 0 || self.a == witness {
            self.a = witness;
            self.ql = x;
        } else if self.b == 0 || self.b == witness {
            self.b = witness;
            self.qr = x;
        } else if self.c == 0 || self.c == witness {
            self.c = witness;
            self.qo = x;
        } else {
            unreachable!("Cannot assign linear term to a constrain of width 3");
        }
    }
}

/// Opcode flags that shows which opcode
/// is used given a circuit instance
#[allow(dead_code)]
#[derive(Default, Clone, Debug)]
pub struct OpcodeFlags {
    pub(crate) arithmetic: bool,
    pub(crate) range: bool,
    pub(crate) and: bool,
    pub(crate) xor: bool,
    pub(crate) sha256: bool,
    pub(crate) blake2s: bool,
    pub(crate) schnorr_verify: bool,
    pub(crate) pedersen: bool,
    pub(crate) hash_to_field: bool,
    pub(crate) ecdsa_secp256k1: bool,
    pub(crate) fixed_base_scalar_mul: bool,
    pub(crate) keccak256: bool,
    pub(crate) keccak256_variable_length: bool,
    pub(crate) recursive_aggregation: bool,
}

impl OpcodeFlags {
    pub(crate) fn new(opcodes: &[Opcode]) -> OpcodeFlags {
        // opcode params
        let mut arithmetic = false;
        let mut range = false;
        let mut and = false;
        let mut xor = false;
        let mut sha256 = false;
        let mut blake2s = false;
        let mut schnorr_verify = false;
        let mut pedersen = false;
        let mut hash_to_field = false;
        let mut ecdsa_secp256k1 = false;
        let mut fixed_base_scalar_mul = false;
        let mut keccak256 = false;
        let mut keccak256_variable_length = false;
        let mut recursive_aggregation = false;
        for opcode in opcodes {
            match opcode {
                Opcode::Arithmetic(..) => arithmetic = true,
                Opcode::BlackBoxFuncCall(gadget_call) => match gadget_call {
                    BlackBoxFuncCall::RANGE { .. } => range = true,
                    BlackBoxFuncCall::AND { .. } => and = true,
                    BlackBoxFuncCall::XOR { .. } => xor = true,
                    BlackBoxFuncCall::SHA256 { .. } => sha256 = true,
                    BlackBoxFuncCall::Blake2s { .. } => blake2s = true,
                    BlackBoxFuncCall::SchnorrVerify { .. } => schnorr_verify = true,
                    BlackBoxFuncCall::Pedersen { .. } => pedersen = true,
                    BlackBoxFuncCall::HashToField128Security { .. } => hash_to_field = true,
                    BlackBoxFuncCall::EcdsaSecp256k1 { .. } => ecdsa_secp256k1 = true,
                    BlackBoxFuncCall::FixedBaseScalarMul { .. } => fixed_base_scalar_mul = true,
                    BlackBoxFuncCall::Keccak256 { .. } => keccak256 = true,
                    BlackBoxFuncCall::Keccak256VariableLength { .. } => {
                        keccak256_variable_length = true
                    }
                    BlackBoxFuncCall::RecursiveAggregation { .. } => recursive_aggregation = true,
                },
                Opcode::Directive(_) | Opcode::Oracle(_) => {
                    // Directives are only needed by the pwg
                }
                Opcode::Block(_) => {
                    // Block is managed by ACVM
                }
                Opcode::RAM(_) | Opcode::ROM(_) => {}
                Opcode::Brillig(_) => {}
            }
        }

        OpcodeFlags {
            arithmetic,
            range,
            and,
            xor,
            sha256,
            blake2s,
            schnorr_verify,
            pedersen,
            hash_to_field,
            ecdsa_secp256k1,
            fixed_base_scalar_mul,
            keccak256,
            keccak256_variable_length,
            recursive_aggregation,
        }
    }
}
