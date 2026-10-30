use argon2::{Algorithm, Argon2, Params as ArgonParams, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
#[cfg(not(target_family = "wasm"))]
use miden_core::events::EventName;
use miden_field::Felt;
use miden_mast_package::Package;
use miden_vm::{
    DefaultHost, ExecutionOptions, ExecutionProof, Program, ProgramInfo, ProvingOptions,
    StackInputs, StackOutputs, Word, advice::AdviceInputs, crypto::hash::Poseidon2,
    serde::Deserializable,
};
use serde::{Deserialize, Serialize};
#[cfg(not(target_family = "wasm"))]
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

#[path = "../../bcrypt-circuit/src/bcrypt_miden/consts.rs"]
mod bcrypt_tables;

const PROGRAM_BYTES: &[u8] = include_bytes!("../../artifacts/argon2id_miden_circuit.masp");
const BCRYPT_PROGRAM_BYTES: &[u8] =
    include_bytes!("../../artifacts/bcrypt_password_miden_circuit.masp");
const MIMC_PROGRAM_BYTES: &[u8] =
    include_bytes!("../../artifacts/mimc_password_miden_circuit.masp");
const PASSWORD_CAPACITY: usize = 64;
const SALT_LENGTH: usize = 16;
const TAG_LENGTH: usize = 32;
const BCRYPT_TAG_LENGTH: usize = 23;
const MIMC_ROUNDS: usize = 220;
pub const MIN_STARK_SECURITY_LEVEL: u32 = 96;
const ADVICE_ELEMENTS: usize = 84;
const BCRYPT_ADVICE_ELEMENTS: usize = 1_128;
const BCRYPT_TABLE_DOMAIN: u64 = 0x4243_5259_5441_424c;
const STATEMENT_DOMAIN: u64 = 0x4152_474f_4e32_4944;
const BCRYPT_STATEMENT_DOMAIN: u64 = 0x4243_5259_5054_3242;
const MIMC_DOMAIN: u64 = 0x4d49_4d43_3750_5701;
const MIMC_STATEMENT_DOMAIN: u64 = 0x4d49_4d43_4352_4544;
const MIMC_RC_A: u64 = 1_724_911_711_848_099_566;
const MIMC_RC_B: u64 = 8_205_926_492_195_879_531;
#[cfg(not(target_family = "wasm"))]
const FRAME_END_EVENT: EventName = EventName::new("readonly::miden_debug::frame_end");
const ADVICE_KEY: [u64; 4] = [
    0x4152_474f_4e32_4944,
    0x5a4b_5354_4152_4b01,
    0x5246_4339_3130_3601,
    0x4252_4f57_5345_5201,
];
const BCRYPT_ADVICE_KEY: [u64; 4] = [
    0x4243_5259_5054_3242,
    0x5a4b_5354_4152_4b01,
    0x454b_5342_4c4f_5746,
    0x4252_4f57_5345_5201,
];
const MIMC_ADVICE_KEY: [u64; 4] = [
    0x4d49_4d43_3750_5701,
    0x5a4b_5354_4152_4b01,
    0x5041_5353_574f_5244,
    0x4252_4f57_5345_5201,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofAlgorithm {
    Argon2id,
    Bcrypt2b,
    Mimc7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub lanes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BcryptParams {
    pub cost: u32,
}

impl BcryptParams {
    pub fn validate(self) -> Result<Self, RuntimeError> {
        if !(4..=16).contains(&self.cost) {
            return Err(RuntimeError::InvalidInput("bcrypt cost must be in 4..=16"));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MimcParams {
    pub rounds: u32,
}

impl Default for MimcParams {
    fn default() -> Self {
        Self {
            rounds: MIMC_ROUNDS as u32,
        }
    }
}

impl MimcParams {
    pub fn validate(self) -> Result<Self, RuntimeError> {
        if self.rounds != MIMC_ROUNDS as u32 {
            return Err(RuntimeError::InvalidInput("MiMC rounds must equal 220"));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algorithm", content = "parameters", rename_all = "kebab-case")]
pub enum AlgorithmParameters {
    Argon2id(Argon2Params),
    Bcrypt2b(BcryptParams),
    Mimc7(MimcParams),
}

impl AlgorithmParameters {
    pub fn algorithm(self) -> ProofAlgorithm {
        match self {
            Self::Argon2id(_) => ProofAlgorithm::Argon2id,
            Self::Bcrypt2b(_) => ProofAlgorithm::Bcrypt2b,
            Self::Mimc7(_) => ProofAlgorithm::Mimc7,
        }
    }

    pub fn validate(self) -> Result<Self, RuntimeError> {
        match self {
            Self::Argon2id(params) => Ok(Self::Argon2id(params.validate()?)),
            Self::Bcrypt2b(params) => Ok(Self::Bcrypt2b(params.validate()?)),
            Self::Mimc7(params) => Ok(Self::Mimc7(params.validate()?)),
        }
    }
}

impl Argon2Params {
    pub fn validate(self) -> Result<Self, RuntimeError> {
        if self.lanes == 0 || self.lanes > 4 {
            return Err(RuntimeError::InvalidInput("lanes must be in 1..=4"));
        }
        if self.memory_kib < 8 * self.lanes {
            return Err(RuntimeError::InvalidInput(
                "memoryKiB must be at least eight times lanes",
            ));
        }
        if self.time_cost == 0 {
            return Err(RuntimeError::InvalidInput("timeCost must be positive"));
        }
        ArgonParams::new(
            self.memory_kib,
            self.time_cost,
            self.lanes,
            Some(TAG_LENGTH),
        )
        .map_err(|_| RuntimeError::InvalidInput("invalid Argon2 parameter combination"))?;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofEnvelope {
    pub format: String,
    pub algorithm: ProofAlgorithm,
    pub program_hash: [u64; 4],
    pub credential: [u64; 4],
    pub challenge: [u32; 4],
    pub salt_hex: String,
    pub params: AlgorithmParameters,
    pub output: Vec<u64>,
    pub proof_base64: String,
}

/// Values the relying party must supply independently of an untrusted proof envelope.
/// Keeping this separate prevents a verifier from accidentally accepting a statement
/// chosen by the prover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedStatement {
    pub credential: [u64; 4],
    pub challenge: [u32; 4],
    pub salt_hex: String,
    pub params: AlgorithmParameters,
}

impl ExpectedStatement {
    pub fn verify(&self, envelope: &ProofEnvelope) -> Result<VerificationReceipt, RuntimeError> {
        verify_envelope(
            envelope,
            self.credential,
            self.challenge,
            parse_hex_16(&self.salt_hex)?,
            self.params,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReceipt {
    pub valid: bool,
    pub security_level: u32,
    pub program_hash: [u64; 4],
    pub credential: [u64; 4],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionReceipt {
    pub output: Vec<u64>,
    pub observed_cycles: u32,
    pub credential: [u64; 4],
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid hex: {0}")]
    InvalidHex(&'static str),
    #[error("credential mismatch")]
    CredentialMismatch,
    #[error("program artifact is invalid: {0}")]
    Program(String),
    #[error("Argon2id failed")]
    Argon2,
    #[error("VM execution/proving failed: {0}")]
    Proving(String),
    #[error("proof encoding is invalid")]
    ProofEncoding,
    #[error("proof verification failed: {0}")]
    Verification(String),
    #[error("JSON is invalid: {0}")]
    Json(String),
}

pub fn program() -> Result<Program, RuntimeError> {
    let package = Package::read_from_bytes(PROGRAM_BYTES)
        .map_err(|error| RuntimeError::Program(error.to_string()))?;
    package
        .try_into_program()
        .map_err(|error| RuntimeError::Program(error.to_string()))
}

pub fn program_hash() -> Result<[u64; 4], RuntimeError> {
    let values: [Felt; 4] = program()?.hash().into();
    Ok(values.map(|value| value.as_canonical_u64()))
}

pub fn bcrypt_program() -> Result<Program, RuntimeError> {
    deserialize_program(BCRYPT_PROGRAM_BYTES)
}

pub fn bcrypt_program_hash() -> Result<[u64; 4], RuntimeError> {
    let values: [Felt; 4] = bcrypt_program()?.hash().into();
    Ok(values.map(|value| value.as_canonical_u64()))
}

pub fn mimc_program() -> Result<Program, RuntimeError> {
    deserialize_program(MIMC_PROGRAM_BYTES)
}

pub fn mimc_program_hash() -> Result<[u64; 4], RuntimeError> {
    let values: [Felt; 4] = mimc_program()?.hash().into();
    Ok(values.map(|value| value.as_canonical_u64()))
}

fn deserialize_program(bytes: &[u8]) -> Result<Program, RuntimeError> {
    let package = Package::read_from_bytes(bytes)
        .map_err(|error| RuntimeError::Program(error.to_string()))?;
    package
        .try_into_program()
        .map_err(|error| RuntimeError::Program(error.to_string()))
}

fn argon2_tag_for(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
    params: Argon2Params,
) -> Result<[u8; TAG_LENGTH], RuntimeError> {
    validate_password(password)?;
    let params = params.validate()?;
    let argon_params = ArgonParams::new(
        params.memory_kib,
        params.time_cost,
        params.lanes,
        Some(TAG_LENGTH),
    )
    .map_err(|_| RuntimeError::Argon2)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut tag = [0u8; TAG_LENGTH];
    argon2
        .hash_password_into(password, salt, &mut tag)
        .map_err(|_| RuntimeError::Argon2)?;
    Ok(tag)
}

pub fn credential_for(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
    params: Argon2Params,
) -> Result<[u64; 4], RuntimeError> {
    let params = params.validate()?;
    let tag = argon2_tag_for(password, salt, params)?;
    let statement = credential_statement(&tag, salt, params);
    let digest: [Felt; 4] = Poseidon2::hash_elements(&statement).into();
    Ok(digest.map(|value| value.as_canonical_u64()))
}

pub fn bcrypt_credential_for(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
    params: BcryptParams,
) -> Result<[u64; 4], RuntimeError> {
    validate_password(password)?;
    let params = params.validate()?;
    let mut nul_terminated = [0u8; PASSWORD_CAPACITY + 1];
    nul_terminated[..password.len()].copy_from_slice(password);
    let raw = bcrypt::bcrypt(params.cost, *salt, &nul_terminated[..password.len() + 1]);
    let mut statement = Vec::with_capacity(2 + BCRYPT_TAG_LENGTH + SALT_LENGTH + 2);
    statement.push(Felt::new_unchecked(BCRYPT_STATEMENT_DOMAIN));
    statement.push(Felt::new_unchecked(
        (BCRYPT_TAG_LENGTH + SALT_LENGTH + 2) as u64,
    ));
    statement.extend(
        raw[..BCRYPT_TAG_LENGTH]
            .iter()
            .map(|byte| Felt::new_unchecked(*byte as u64)),
    );
    statement.extend(salt.iter().map(|byte| Felt::new_unchecked(*byte as u64)));
    statement.push(Felt::new_unchecked(params.cost as u64));
    statement.push(Felt::new_unchecked(BCRYPT_TAG_LENGTH as u64));
    let digest: [Felt; 4] = Poseidon2::hash_elements(&statement).into();
    Ok(digest.map(|value| value.as_canonical_u64()))
}

pub fn bcrypt_table_commitment() -> [u64; 4] {
    let mut statement = Vec::with_capacity(2 + bcrypt_tables::P.len() + bcrypt_tables::S.len());
    statement.push(Felt::new_unchecked(BCRYPT_TABLE_DOMAIN));
    statement.push(Felt::new_unchecked(
        (bcrypt_tables::P.len() + bcrypt_tables::S.len()) as u64,
    ));
    statement.extend(
        bcrypt_tables::P
            .iter()
            .chain(bcrypt_tables::S.iter())
            .map(|value| Felt::new_unchecked(*value as u64)),
    );
    let digest: [Felt; 4] = Poseidon2::hash_elements(&statement).into();
    digest.map(|value| value.as_canonical_u64())
}

pub fn mimc_credential_for(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
    params: MimcParams,
) -> Result<[u64; 4], RuntimeError> {
    validate_password(password)?;
    let params = params.validate()?;
    let output = mimc7_password_hash(password, salt);
    let mut statement = Vec::with_capacity(2 + SALT_LENGTH + 3);
    statement.push(Felt::new_unchecked(MIMC_STATEMENT_DOMAIN));
    statement.push(Felt::new_unchecked((SALT_LENGTH + 3) as u64));
    statement.push(output);
    statement.extend(salt.iter().map(|byte| Felt::new_unchecked(*byte as u64)));
    statement.push(Felt::new_unchecked(password.len() as u64));
    statement.push(Felt::new_unchecked(params.rounds as u64));
    let digest: [Felt; 4] = Poseidon2::hash_elements(&statement).into();
    Ok(digest.map(|value| value.as_canonical_u64()))
}

#[cfg(not(target_family = "wasm"))]
pub fn prove_sync(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: Argon2Params,
    challenge: [u32; 4],
    expected_credential: Option<[u64; 4]>,
) -> Result<ProofEnvelope, RuntimeError> {
    let params = params.validate()?;
    let computed = credential_for(password, &salt, params)?;
    let credential = expected_credential.unwrap_or(computed);
    if computed != credential {
        return Err(RuntimeError::CredentialMismatch);
    }
    let (stack_inputs, advice_inputs) =
        execution_inputs(password, &salt, params, credential, challenge)?;
    let program = program()?;
    let mut host = compiler_host()?;
    let (outputs, proof) = miden_vm::prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::default(),
    )
    .map_err(|error| RuntimeError::Proving(format!("{error:#?}")))?;
    build_envelope(
        &program,
        "argon2id-miden-stark-v1",
        credential,
        challenge,
        salt,
        AlgorithmParameters::Argon2id(params),
        outputs,
        proof,
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn prove_bcrypt_sync(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: BcryptParams,
    challenge: [u32; 4],
    expected_credential: Option<[u64; 4]>,
) -> Result<ProofEnvelope, RuntimeError> {
    let params = params.validate()?;
    let computed = bcrypt_credential_for(password, &salt, params)?;
    let credential = expected_credential.unwrap_or(computed);
    if computed != credential {
        return Err(RuntimeError::CredentialMismatch);
    }
    let (stack_inputs, advice_inputs) =
        bcrypt_execution_inputs(password, &salt, params, credential, challenge)?;
    let program = bcrypt_program()?;
    let mut host = compiler_host()?;
    let (outputs, proof) = miden_vm::prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::default(),
    )
    .map_err(|error| RuntimeError::Proving(format!("{error:#?}")))?;
    build_envelope(
        &program,
        "bcrypt2b-miden-stark-v1",
        credential,
        challenge,
        salt,
        AlgorithmParameters::Bcrypt2b(params),
        outputs,
        proof,
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn prove_mimc_sync(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: MimcParams,
    challenge: [u32; 4],
    expected_credential: Option<[u64; 4]>,
) -> Result<ProofEnvelope, RuntimeError> {
    let params = params.validate()?;
    let computed = mimc_credential_for(password, &salt, params)?;
    let credential = expected_credential.unwrap_or(computed);
    if computed != credential {
        return Err(RuntimeError::CredentialMismatch);
    }
    let (stack_inputs, advice_inputs) =
        mimc_execution_inputs(password, &salt, credential, challenge)?;
    let program = mimc_program()?;
    let mut host = compiler_host()?;
    let (outputs, proof) = miden_vm::prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::default(),
    )
    .map_err(|error| RuntimeError::Proving(format!("{error:#?}")))?;
    build_envelope(
        &program,
        "mimc7-miden-stark-v1",
        credential,
        challenge,
        salt,
        AlgorithmParameters::Mimc7(params),
        outputs,
        proof,
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn execute_measure_sync(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: Argon2Params,
    challenge: [u32; 4],
) -> Result<ExecutionReceipt, RuntimeError> {
    let params = params.validate()?;
    let credential = credential_for(password, &salt, params)?;
    let (stack_inputs, advice_inputs) =
        execution_inputs(password, &salt, params, credential, challenge)?;
    let program = program()?;
    let mut host = compiler_host()?;
    let observed_cycles = Arc::new(AtomicU32::new(0));
    let clock = observed_cycles.clone();
    host.replace_handler(
        FRAME_END_EVENT,
        Arc::new(move |state: &miden_processor::ProcessorState<'_>| {
            clock.store(state.clock().as_u32(), Ordering::Relaxed);
            Ok(Vec::new())
        }),
    );
    let execution = miden_vm::execute_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
    )
    .map_err(|error| RuntimeError::Proving(format!("{error:#?}")))?;
    Ok(ExecutionReceipt {
        output: execution
            .stack
            .get_num_elements(1)
            .iter()
            .map(|value| value.as_canonical_u64())
            .collect(),
        observed_cycles: observed_cycles.load(Ordering::Relaxed),
        credential,
    })
}

#[cfg(not(target_family = "wasm"))]
pub fn execute_bcrypt_measure_sync(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: BcryptParams,
    challenge: [u32; 4],
) -> Result<ExecutionReceipt, RuntimeError> {
    let params = params.validate()?;
    let credential = bcrypt_credential_for(password, &salt, params)?;
    let (stack_inputs, advice_inputs) =
        bcrypt_execution_inputs(password, &salt, params, credential, challenge)?;
    execute_and_measure(bcrypt_program()?, stack_inputs, advice_inputs, credential)
}

/// Diagnostic entry point used by the circuit build/test workflow to execute an external
/// bcrypt Miden package before it replaces the embedded, verifier-pinned artifact.
#[cfg(not(target_family = "wasm"))]
pub fn execute_bcrypt_program_bytes_measure_sync(
    package_bytes: &[u8],
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: BcryptParams,
    challenge: [u32; 4],
) -> Result<ExecutionReceipt, RuntimeError> {
    let params = params.validate()?;
    let credential = bcrypt_credential_for(password, &salt, params)?;
    let (stack_inputs, advice_inputs) =
        bcrypt_execution_inputs(password, &salt, params, credential, challenge)?;
    execute_and_measure(
        deserialize_program(package_bytes)?,
        stack_inputs,
        advice_inputs,
        credential,
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn execute_mimc_measure_sync(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: MimcParams,
    challenge: [u32; 4],
) -> Result<ExecutionReceipt, RuntimeError> {
    params.validate()?;
    let credential = mimc_credential_for(password, &salt, params)?;
    let (stack_inputs, advice_inputs) =
        mimc_execution_inputs(password, &salt, credential, challenge)?;
    execute_and_measure(mimc_program()?, stack_inputs, advice_inputs, credential)
}

#[cfg(not(target_family = "wasm"))]
fn execute_and_measure(
    program: Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    credential: [u64; 4],
) -> Result<ExecutionReceipt, RuntimeError> {
    let mut host = compiler_host()?;
    let observed_cycles = Arc::new(AtomicU32::new(0));
    let clock = observed_cycles.clone();
    host.replace_handler(
        FRAME_END_EVENT,
        Arc::new(move |state: &miden_processor::ProcessorState<'_>| {
            clock.store(state.clock().as_u32(), Ordering::Relaxed);
            Ok(Vec::new())
        }),
    );
    let execution = miden_vm::execute_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
    )
    .map_err(|error| RuntimeError::Proving(format!("{error:#?}")))?;
    Ok(ExecutionReceipt {
        output: execution
            .stack
            .get_num_elements(1)
            .iter()
            .map(|value| value.as_canonical_u64())
            .collect(),
        observed_cycles: observed_cycles.load(Ordering::Relaxed),
        credential,
    })
}

#[cfg(target_family = "wasm")]
async fn prove_async(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: Argon2Params,
    challenge: [u32; 4],
    expected_credential: Option<[u64; 4]>,
) -> Result<ProofEnvelope, RuntimeError> {
    let params = params.validate()?;
    let computed = credential_for(password, &salt, params)?;
    let credential = expected_credential.unwrap_or(computed);
    if computed != credential {
        return Err(RuntimeError::CredentialMismatch);
    }
    let (stack_inputs, advice_inputs) =
        execution_inputs(password, &salt, params, credential, challenge)?;
    let program = program()?;
    let mut host = compiler_host()?;
    let (outputs, proof) = miden_vm::prove(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::default(),
    )
    .await
    .map_err(|error| RuntimeError::Proving(format!("{error:#?}")))?;
    build_envelope(
        &program,
        "argon2id-miden-stark-v1",
        credential,
        challenge,
        salt,
        AlgorithmParameters::Argon2id(params),
        outputs,
        proof,
    )
}

#[cfg(target_family = "wasm")]
async fn prove_bcrypt_async(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: BcryptParams,
    challenge: [u32; 4],
    expected_credential: Option<[u64; 4]>,
) -> Result<ProofEnvelope, RuntimeError> {
    let params = params.validate()?;
    let computed = bcrypt_credential_for(password, &salt, params)?;
    let credential = expected_credential.unwrap_or(computed);
    if computed != credential {
        return Err(RuntimeError::CredentialMismatch);
    }
    let (stack_inputs, advice_inputs) =
        bcrypt_execution_inputs(password, &salt, params, credential, challenge)?;
    let program = bcrypt_program()?;
    let mut host = compiler_host()?;
    let (outputs, proof) = miden_vm::prove(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::default(),
    )
    .await
    .map_err(|error| RuntimeError::Proving(format!("{error:#?}")))?;
    build_envelope(
        &program,
        "bcrypt2b-miden-stark-v1",
        credential,
        challenge,
        salt,
        AlgorithmParameters::Bcrypt2b(params),
        outputs,
        proof,
    )
}

#[cfg(target_family = "wasm")]
async fn prove_mimc_async(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    params: MimcParams,
    challenge: [u32; 4],
    expected_credential: Option<[u64; 4]>,
) -> Result<ProofEnvelope, RuntimeError> {
    let params = params.validate()?;
    let computed = mimc_credential_for(password, &salt, params)?;
    let credential = expected_credential.unwrap_or(computed);
    if computed != credential {
        return Err(RuntimeError::CredentialMismatch);
    }
    let (stack_inputs, advice_inputs) =
        mimc_execution_inputs(password, &salt, credential, challenge)?;
    let program = mimc_program()?;
    let mut host = compiler_host()?;
    let (outputs, proof) = miden_vm::prove(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::default(),
    )
    .await
    .map_err(|error| RuntimeError::Proving(format!("{error:#?}")))?;
    build_envelope(
        &program,
        "mimc7-miden-stark-v1",
        credential,
        challenge,
        salt,
        AlgorithmParameters::Mimc7(params),
        outputs,
        proof,
    )
}

pub fn verify_envelope(
    envelope: &ProofEnvelope,
    expected_credential: [u64; 4],
    expected_challenge: [u32; 4],
    expected_salt: [u8; SALT_LENGTH],
    expected_params: AlgorithmParameters,
) -> Result<VerificationReceipt, RuntimeError> {
    let expected_params = expected_params.validate()?;
    let (expected_format, program) = match expected_params {
        AlgorithmParameters::Argon2id(_) => ("argon2id-miden-stark-v1", program()?),
        AlgorithmParameters::Bcrypt2b(_) => ("bcrypt2b-miden-stark-v1", bcrypt_program()?),
        AlgorithmParameters::Mimc7(_) => ("mimc7-miden-stark-v1", mimc_program()?),
    };
    if envelope.format != expected_format || envelope.algorithm != expected_params.algorithm() {
        return Err(RuntimeError::InvalidInput(
            "unsupported proof format or algorithm",
        ));
    }
    if envelope.credential != expected_credential {
        return Err(RuntimeError::CredentialMismatch);
    }
    if envelope.challenge != expected_challenge {
        return Err(RuntimeError::InvalidInput("challenge mismatch"));
    }
    if envelope.params != expected_params {
        return Err(RuntimeError::InvalidInput("algorithm parameters mismatch"));
    }
    if parse_hex_16(&envelope.salt_hex)? != expected_salt {
        return Err(RuntimeError::InvalidInput("salt mismatch"));
    }

    let fixed_program_hash = word_to_u64(program.hash());
    if envelope.program_hash != fixed_program_hash {
        return Err(RuntimeError::InvalidInput("program hash mismatch"));
    }
    if envelope.output != vec![1] {
        return Err(RuntimeError::InvalidInput("unexpected public output"));
    }

    let stack_inputs = public_stack_inputs(expected_credential, expected_challenge)?;
    let stack_outputs = StackOutputs::new(&[Felt::ONE])
        .map_err(|error| RuntimeError::Verification(error.to_string()))?;
    let proof_bytes = BASE64
        .decode(&envelope.proof_base64)
        .map_err(|_| RuntimeError::ProofEncoding)?;
    let proof =
        ExecutionProof::read_from_bytes(&proof_bytes).map_err(|_| RuntimeError::ProofEncoding)?;
    let security_level = miden_vm::verify(
        ProgramInfo::from(program),
        stack_inputs,
        stack_outputs,
        proof,
    )
    .map_err(|error| RuntimeError::Verification(error.to_string()))?;
    if security_level < MIN_STARK_SECURITY_LEVEL {
        return Err(RuntimeError::Verification(format!(
            "proof security level {security_level} is below required minimum {MIN_STARK_SECURITY_LEVEL}"
        )));
    }

    Ok(VerificationReceipt {
        valid: true,
        security_level,
        program_hash: fixed_program_hash,
        credential: expected_credential,
    })
}

pub fn parse_hex_16(value: &str) -> Result<[u8; SALT_LENGTH], RuntimeError> {
    if value.len() != SALT_LENGTH * 2 {
        return Err(RuntimeError::InvalidHex("expected exactly 16 bytes"));
    }
    // Decode byte pairs directly so non-ASCII input is rejected instead of
    // panicking on a UTF-8 character boundary.
    fn nibble(c: u8) -> Result<u8, RuntimeError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(RuntimeError::InvalidHex("non-hex character")),
        }
    }
    let bytes = value.as_bytes();
    let mut output = [0u8; SALT_LENGTH];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (nibble(bytes[index * 2])? << 4) | nibble(bytes[index * 2 + 1])?;
    }
    Ok(output)
}

fn validate_password(password: &[u8]) -> Result<(), RuntimeError> {
    if password.is_empty() || password.len() > PASSWORD_CAPACITY {
        return Err(RuntimeError::InvalidInput(
            "password must encode to 1..=64 UTF-8 bytes",
        ));
    }
    Ok(())
}

fn credential_statement(
    tag: &[u8; TAG_LENGTH],
    salt: &[u8; SALT_LENGTH],
    params: Argon2Params,
) -> Vec<Felt> {
    let mut statement = Vec::with_capacity(2 + TAG_LENGTH + SALT_LENGTH + 4);
    statement.push(Felt::new_unchecked(STATEMENT_DOMAIN));
    statement.push(Felt::new_unchecked((TAG_LENGTH + SALT_LENGTH + 4) as u64));
    statement.extend(tag.iter().map(|byte| Felt::new_unchecked(*byte as u64)));
    statement.extend(salt.iter().map(|byte| Felt::new_unchecked(*byte as u64)));
    statement.push(Felt::new_unchecked(params.memory_kib as u64));
    statement.push(Felt::new_unchecked(params.time_cost as u64));
    statement.push(Felt::new_unchecked(params.lanes as u64));
    statement.push(Felt::new_unchecked(TAG_LENGTH as u64));
    statement
}

fn execution_inputs(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
    params: Argon2Params,
    credential: [u64; 4],
    challenge: [u32; 4],
) -> Result<(StackInputs, AdviceInputs), RuntimeError> {
    validate_password(password)?;
    let stack_inputs = public_stack_inputs(credential, challenge)?;
    let mut witness = Vec::with_capacity(ADVICE_ELEMENTS);
    witness.push(Felt::new_unchecked(password.len() as u64));
    witness.extend(
        password
            .iter()
            .map(|byte| Felt::new_unchecked(*byte as u64)),
    );
    witness.resize(1 + PASSWORD_CAPACITY, Felt::ZERO);
    witness.extend(salt.iter().map(|byte| Felt::new_unchecked(*byte as u64)));
    witness.push(Felt::new_unchecked(params.memory_kib as u64));
    witness.push(Felt::new_unchecked(params.time_cost as u64));
    witness.push(Felt::new_unchecked(params.lanes as u64));
    debug_assert_eq!(witness.len(), ADVICE_ELEMENTS);

    let key: Word = ADVICE_KEY.map(Felt::new_unchecked).into();
    let advice_inputs = AdviceInputs::default().with_map([(key, witness)]);
    Ok((stack_inputs, advice_inputs))
}

fn bcrypt_execution_inputs(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
    params: BcryptParams,
    credential: [u64; 4],
    challenge: [u32; 4],
) -> Result<(StackInputs, AdviceInputs), RuntimeError> {
    validate_password(password)?;
    params.validate()?;
    let stack_inputs = public_stack_inputs(credential, challenge)?;
    let mut witness = Vec::with_capacity(BCRYPT_ADVICE_ELEMENTS);
    witness.push(Felt::new_unchecked(password.len() as u64));
    witness.extend(
        password
            .iter()
            .map(|byte| Felt::new_unchecked(*byte as u64)),
    );
    witness.resize(1 + PASSWORD_CAPACITY, Felt::ZERO);
    witness.extend(salt.iter().map(|byte| Felt::new_unchecked(*byte as u64)));
    witness.push(Felt::new_unchecked(params.cost as u64));
    witness.push(Felt::ZERO);
    witness.push(Felt::ZERO);
    witness.extend(
        bcrypt_tables::P
            .iter()
            .chain(bcrypt_tables::S.iter())
            .map(|value| Felt::new_unchecked(*value as u64)),
    );
    witness.push(Felt::ZERO);
    witness.push(Felt::ZERO);
    debug_assert_eq!(witness.len(), BCRYPT_ADVICE_ELEMENTS);
    let key: Word = BCRYPT_ADVICE_KEY.map(Felt::new_unchecked).into();
    Ok((
        stack_inputs,
        AdviceInputs::default().with_map([(key, witness)]),
    ))
}

fn mimc_execution_inputs(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
    credential: [u64; 4],
    challenge: [u32; 4],
) -> Result<(StackInputs, AdviceInputs), RuntimeError> {
    validate_password(password)?;
    let stack_inputs = public_stack_inputs(credential, challenge)?;
    let mut witness = Vec::with_capacity(ADVICE_ELEMENTS);
    witness.push(Felt::new_unchecked(password.len() as u64));
    witness.extend(
        password
            .iter()
            .map(|byte| Felt::new_unchecked(*byte as u64)),
    );
    witness.resize(1 + PASSWORD_CAPACITY, Felt::ZERO);
    witness.extend(salt.iter().map(|byte| Felt::new_unchecked(*byte as u64)));
    witness.push(Felt::ZERO);
    witness.push(Felt::ZERO);
    witness.push(Felt::ZERO);
    debug_assert_eq!(witness.len(), ADVICE_ELEMENTS);
    let key: Word = MIMC_ADVICE_KEY.map(Felt::new_unchecked).into();
    Ok((
        stack_inputs,
        AdviceInputs::default().with_map([(key, witness)]),
    ))
}

fn mimc7_password_hash(password: &[u8], salt: &[u8; SALT_LENGTH]) -> Felt {
    let mut preimage = Vec::with_capacity(3 + PASSWORD_CAPACITY + SALT_LENGTH);
    preimage.push(Felt::new_unchecked(MIMC_DOMAIN));
    preimage.push(Felt::new_unchecked(
        (PASSWORD_CAPACITY + SALT_LENGTH + 1) as u64,
    ));
    preimage.push(Felt::new_unchecked(password.len() as u64));
    preimage.extend(
        password
            .iter()
            .copied()
            .chain(core::iter::repeat(0).take(PASSWORD_CAPACITY - password.len()))
            .map(|byte| Felt::new_unchecked(byte as u64)),
    );
    preimage.extend(salt.iter().map(|byte| Felt::new_unchecked(*byte as u64)));
    let absorbed: [Felt; 4] = Poseidon2::hash_elements(&preimage).into();
    mimc_compress(Felt::new_unchecked(MIMC_DOMAIN), absorbed[0])
}

fn mimc_compress(key: Felt, message: Felt) -> Felt {
    let mut value = message;
    let mut rc = Felt::new_unchecked(MIMC_RC_A);
    for i in 0..MIMC_ROUNDS {
        rc = rc * Felt::new_unchecked(MIMC_RC_B)
            + Felt::new_unchecked(i as u64) * Felt::new_unchecked(MIMC_RC_A)
            + Felt::ONE;
        if rc == Felt::ZERO {
            rc = Felt::ONE;
        }
        let t = value + key + rc;
        let t2 = t * t;
        let t4 = t2 * t2;
        value = t4 * t2 * t;
    }
    value + key + key + message
}

fn public_stack_inputs(
    credential: [u64; 4],
    challenge: [u32; 4],
) -> Result<StackInputs, RuntimeError> {
    if credential.iter().any(|value| Felt::new(*value).is_err()) {
        return Err(RuntimeError::InvalidInput(
            "non-canonical credential field element",
        ));
    }
    let mut public = Vec::with_capacity(12);
    for value in credential {
        public.push(Felt::new_unchecked(value as u32 as u64));
        public.push(Felt::new_unchecked((value >> 32) as u32 as u64));
    }
    public.extend(challenge.map(|value| Felt::new_unchecked(value as u64)));
    StackInputs::new(&public).map_err(|error| {
        RuntimeError::InvalidInput(match error {
            _ => "invalid public stack inputs",
        })
    })
}

fn build_envelope(
    program: &Program,
    format: &str,
    credential: [u64; 4],
    challenge: [u32; 4],
    salt: [u8; SALT_LENGTH],
    params: AlgorithmParameters,
    outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<ProofEnvelope, RuntimeError> {
    if outputs.get_element(0) != Some(Felt::ONE) {
        return Err(RuntimeError::Proving("circuit returned failure".to_owned()));
    }
    Ok(ProofEnvelope {
        format: format.to_owned(),
        algorithm: params.algorithm(),
        program_hash: word_to_u64(program.hash()),
        credential,
        challenge,
        salt_hex: hex_16(&salt),
        params,
        output: vec![1],
        proof_base64: BASE64.encode(proof.to_bytes()),
    })
}

fn compiler_host() -> Result<DefaultHost, RuntimeError> {
    let mut host = DefaultHost::default();
    let core_library = miden_core_lib::CoreLibrary::default();
    host.load_library(&core_library)
        .map_err(|error| RuntimeError::Program(error.to_string()))?;
    Ok(host)
}

fn word_to_u64(word: Word) -> [u64; 4] {
    let values: [Felt; 4] = word.into();
    values.map(|value| value.as_canonical_u64())
}

fn hex_16(value: &[u8; SALT_LENGTH]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(SALT_LENGTH * 2);
    for byte in value {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(target_family = "wasm")]
mod browser {
    use super::*;
    use wasm_bindgen::prelude::*;

    fn js_error(error: RuntimeError) -> JsValue {
        JsValue::from_str(&error.to_string())
    }

    #[wasm_bindgen(start)]
    pub fn start() {
        console_error_panic_hook::set_once();
    }

    #[wasm_bindgen]
    pub fn credential_argon2id(
        password: String,
        salt_hex: String,
        memory_kib: u32,
        time_cost: u32,
        lanes: u32,
    ) -> Result<JsValue, JsValue> {
        let salt = parse_hex_16(&salt_hex).map_err(js_error)?;
        let credential = credential_for(
            password.as_bytes(),
            &salt,
            Argon2Params {
                memory_kib,
                time_cost,
                lanes,
            },
        )
        .map_err(js_error)?;
        credential
            .serialize(
                &serde_wasm_bindgen::Serializer::new()
                    .serialize_large_number_types_as_bigints(true),
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen]
    pub fn credential_bcrypt2b(
        password: String,
        salt_hex: String,
        cost: u32,
    ) -> Result<JsValue, JsValue> {
        let salt = parse_hex_16(&salt_hex).map_err(js_error)?;
        serialize_bigints(
            &bcrypt_credential_for(password.as_bytes(), &salt, BcryptParams { cost })
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen]
    pub fn credential_mimc7(password: String, salt_hex: String) -> Result<JsValue, JsValue> {
        let salt = parse_hex_16(&salt_hex).map_err(js_error)?;
        serialize_bigints(
            &mimc_credential_for(password.as_bytes(), &salt, MimcParams::default())
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen]
    pub fn circuit_program_hash() -> Result<JsValue, JsValue> {
        program_hash()
            .map_err(js_error)?
            .serialize(
                &serde_wasm_bindgen::Serializer::new()
                    .serialize_large_number_types_as_bigints(true),
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen]
    pub fn bcrypt_circuit_program_hash() -> Result<JsValue, JsValue> {
        serialize_bigints(&bcrypt_program_hash().map_err(js_error)?)
    }

    #[wasm_bindgen]
    pub fn mimc_circuit_program_hash() -> Result<JsValue, JsValue> {
        serialize_bigints(&mimc_program_hash().map_err(js_error)?)
    }

    #[wasm_bindgen]
    pub async fn prove_argon2id(
        password: String,
        salt_hex: String,
        memory_kib: u32,
        time_cost: u32,
        lanes: u32,
        challenge: Vec<u32>,
        expected_credential: JsValue,
    ) -> Result<JsValue, JsValue> {
        let salt = parse_hex_16(&salt_hex).map_err(js_error)?;
        let challenge: [u32; 4] = challenge
            .try_into()
            .map_err(|_| JsValue::from_str("challenge must contain four u32 values"))?;
        let expected = if expected_credential.is_null() || expected_credential.is_undefined() {
            None
        } else {
            Some(
                serde_wasm_bindgen::from_value(expected_credential)
                    .map_err(|error| JsValue::from_str(&error.to_string()))?,
            )
        };
        let envelope = prove_async(
            password.as_bytes(),
            salt,
            Argon2Params {
                memory_kib,
                time_cost,
                lanes,
            },
            challenge,
            expected,
        )
        .await
        .map_err(js_error)?;
        envelope
            .serialize(
                &serde_wasm_bindgen::Serializer::new()
                    .serialize_large_number_types_as_bigints(true),
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen]
    pub async fn prove_bcrypt2b(
        password: String,
        salt_hex: String,
        cost: u32,
        challenge: Vec<u32>,
        expected_credential: JsValue,
    ) -> Result<JsValue, JsValue> {
        let salt = parse_hex_16(&salt_hex).map_err(js_error)?;
        let challenge: [u32; 4] = challenge
            .try_into()
            .map_err(|_| JsValue::from_str("challenge must contain four u32 values"))?;
        let expected = optional_credential(expected_credential)?;
        let envelope = prove_bcrypt_async(
            password.as_bytes(),
            salt,
            BcryptParams { cost },
            challenge,
            expected,
        )
        .await
        .map_err(js_error)?;
        serialize_bigints(&envelope)
    }

    #[wasm_bindgen]
    pub async fn prove_mimc7(
        password: String,
        salt_hex: String,
        challenge: Vec<u32>,
        expected_credential: JsValue,
    ) -> Result<JsValue, JsValue> {
        let salt = parse_hex_16(&salt_hex).map_err(js_error)?;
        let challenge: [u32; 4] = challenge
            .try_into()
            .map_err(|_| JsValue::from_str("challenge must contain four u32 values"))?;
        let expected = optional_credential(expected_credential)?;
        let envelope = prove_mimc_async(
            password.as_bytes(),
            salt,
            MimcParams::default(),
            challenge,
            expected,
        )
        .await
        .map_err(js_error)?;
        serialize_bigints(&envelope)
    }

    #[wasm_bindgen]
    pub fn verify_argon2id(
        envelope: JsValue,
        expected_credential: JsValue,
        expected_challenge: Vec<u32>,
        expected_salt_hex: String,
        memory_kib: u32,
        time_cost: u32,
        lanes: u32,
    ) -> Result<JsValue, JsValue> {
        let envelope: ProofEnvelope = serde_wasm_bindgen::from_value(envelope)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let credential: [u64; 4] = serde_wasm_bindgen::from_value(expected_credential)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let challenge: [u32; 4] = expected_challenge
            .try_into()
            .map_err(|_| JsValue::from_str("challenge must contain four u32 values"))?;
        let receipt = verify_envelope(
            &envelope,
            credential,
            challenge,
            parse_hex_16(&expected_salt_hex).map_err(js_error)?,
            AlgorithmParameters::Argon2id(Argon2Params {
                memory_kib,
                time_cost,
                lanes,
            }),
        )
        .map_err(js_error)?;
        receipt
            .serialize(
                &serde_wasm_bindgen::Serializer::new()
                    .serialize_large_number_types_as_bigints(true),
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen]
    pub fn verify_bcrypt2b(
        envelope: JsValue,
        expected_credential: JsValue,
        expected_challenge: Vec<u32>,
        expected_salt_hex: String,
        cost: u32,
    ) -> Result<JsValue, JsValue> {
        verify_for_browser(
            envelope,
            expected_credential,
            expected_challenge,
            expected_salt_hex,
            AlgorithmParameters::Bcrypt2b(BcryptParams { cost }),
        )
    }

    #[wasm_bindgen]
    pub fn verify_mimc7(
        envelope: JsValue,
        expected_credential: JsValue,
        expected_challenge: Vec<u32>,
        expected_salt_hex: String,
    ) -> Result<JsValue, JsValue> {
        verify_for_browser(
            envelope,
            expected_credential,
            expected_challenge,
            expected_salt_hex,
            AlgorithmParameters::Mimc7(MimcParams::default()),
        )
    }

    fn optional_credential(value: JsValue) -> Result<Option<[u64; 4]>, JsValue> {
        if value.is_null() || value.is_undefined() {
            Ok(None)
        } else {
            serde_wasm_bindgen::from_value(value)
                .map(Some)
                .map_err(|error| JsValue::from_str(&error.to_string()))
        }
    }

    fn serialize_bigints<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
        value
            .serialize(
                &serde_wasm_bindgen::Serializer::new()
                    .serialize_large_number_types_as_bigints(true),
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    fn verify_for_browser(
        envelope: JsValue,
        expected_credential: JsValue,
        expected_challenge: Vec<u32>,
        expected_salt_hex: String,
        params: AlgorithmParameters,
    ) -> Result<JsValue, JsValue> {
        let envelope: ProofEnvelope = serde_wasm_bindgen::from_value(envelope)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let credential: [u64; 4] = serde_wasm_bindgen::from_value(expected_credential)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let challenge: [u32; 4] = expected_challenge
            .try_into()
            .map_err(|_| JsValue::from_str("challenge must contain four u32 values"))?;
        let receipt = verify_envelope(
            &envelope,
            credential,
            challenge,
            parse_hex_16(&expected_salt_hex).map_err(js_error)?,
            params,
        )
        .map_err(js_error)?;
        serialize_bigints(&receipt)
    }
}
