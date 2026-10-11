use std::{env, fs, process::ExitCode};

use argon2id_zk_runtime::{
    Argon2Params, BcryptParams, ExpectedStatement, MimcParams, ProofEnvelope,
    bcrypt_credential_for, bcrypt_program_hash, bcrypt_table_commitment, credential_for,
    execute_bcrypt_measure_sync, execute_bcrypt_program_bytes_measure_sync, execute_measure_sync,
    execute_mimc_measure_sync, mimc_credential_for, mimc_program_hash, parse_hex_16, program_hash,
    prove_bcrypt_sync, prove_mimc_sync, prove_sync,
};

fn main() -> ExitCode {
    match run() {
        Ok(value) => {
            let args: Vec<String> = env::args().collect();
            if let Some(index) = args.iter().position(|arg| arg == "--out") {
                let Some(path) = args.get(index + 1) else {
                    eprintln!("--out requires a file path");
                    return ExitCode::FAILURE;
                };
                match fs::write(path, value.as_bytes()) {
                    Ok(()) => {
                        println!("wrote UTF-8 proof envelope to {path}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("could not write {path}: {error}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                println!("{value}");
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("program-hash") => serde_json::to_string(&program_hash().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string()),
        Some("program-hashes") => serde_json::to_string(&serde_json::json!({
            "argon2id": program_hash().map_err(|e| e.to_string())?,
            "bcrypt2b": bcrypt_program_hash().map_err(|e| e.to_string())?,
            "mimc7": mimc_program_hash().map_err(|e| e.to_string())?,
        }))
        .map_err(|e| e.to_string()),
        Some("bcrypt-table-commitment") => {
            serde_json::to_string(&bcrypt_table_commitment()).map_err(|e| e.to_string())
        }
        Some("credential") => {
            let password = args.get(2).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(3).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            let params = params_from_args(&args, 4)?;
            serde_json::to_string(
                &credential_for(password.as_bytes(), &salt, params).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        Some("credential-bcrypt") => {
            let password = args.get(2).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(3).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            let cost = parse_u32(args.get(4), "cost")?;
            serde_json::to_string(
                &bcrypt_credential_for(password.as_bytes(), &salt, BcryptParams { cost })
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        Some("credential-mimc") => {
            let password = args.get(2).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(3).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            serde_json::to_string(
                &mimc_credential_for(password.as_bytes(), &salt, MimcParams::default())
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        Some("prove") => {
            let password = args.get(2).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(3).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            let params = params_from_args(&args, 4)?;
            let challenge = challenge_from_args(&args, 7)?;
            let proof = prove_sync(password.as_bytes(), salt, params, challenge, None)
                .map_err(|e| e.to_string())?;
            serde_json::to_string(&proof).map_err(|e| e.to_string())
        }
        Some("prove-bcrypt") => {
            let password = args.get(2).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(3).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            let cost = parse_u32(args.get(4), "cost")?;
            let challenge = challenge_from_args(&args, 5)?;
            serde_json::to_string(
                &prove_bcrypt_sync(
                    password.as_bytes(),
                    salt,
                    BcryptParams { cost },
                    challenge,
                    None,
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        Some("prove-mimc") => {
            let password = args.get(2).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(3).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            let challenge = challenge_from_args(&args, 4)?;
            serde_json::to_string(
                &prove_mimc_sync(
                    password.as_bytes(),
                    salt,
                    MimcParams::default(),
                    challenge,
                    None,
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        Some("execute") => {
            let password = args.get(2).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(3).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            let params = params_from_args(&args, 4)?;
            let challenge = challenge_from_args(&args, 7)?;
            let receipt = execute_measure_sync(password.as_bytes(), salt, params, challenge)
                .map_err(|e| e.to_string())?;
            serde_json::to_string(&receipt).map_err(|e| e.to_string())
        }
        Some("execute-bcrypt") => {
            let password = args.get(2).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(3).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            let cost = parse_u32(args.get(4), "cost")?;
            let challenge = challenge_from_args(&args, 5)?;
            serde_json::to_string(
                &execute_bcrypt_measure_sync(
                    password.as_bytes(),
                    salt,
                    BcryptParams { cost },
                    challenge,
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        Some("execute-bcrypt-package") => {
            let package_path = args.get(2).ok_or("missing package path")?;
            let password = args.get(3).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(4).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            let cost = parse_u32(args.get(5), "cost")?;
            let challenge = challenge_from_args(&args, 6)?;
            let package_bytes = fs::read(package_path).map_err(|e| e.to_string())?;
            serde_json::to_string(
                &execute_bcrypt_program_bytes_measure_sync(
                    &package_bytes,
                    password.as_bytes(),
                    salt,
                    BcryptParams { cost },
                    challenge,
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        Some("execute-mimc") => {
            let password = args.get(2).ok_or("missing password")?;
            let salt = parse_hex_16(args.get(3).ok_or("missing salt hex")?)
                .map_err(|e| e.to_string())?;
            let challenge = challenge_from_args(&args, 4)?;
            serde_json::to_string(
                &execute_mimc_measure_sync(
                    password.as_bytes(),
                    salt,
                    MimcParams::default(),
                    challenge,
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        Some("verify-file") => {
            let path = args.get(2).ok_or("missing envelope file")?;
            let expected_path = args.get(3).ok_or("missing expected statement file")?;
            let envelope: ProofEnvelope = serde_json::from_str(
                &fs::read_to_string(path).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let expected: ExpectedStatement = serde_json::from_str(
                &fs::read_to_string(expected_path).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let receipt = expected.verify(&envelope).map_err(|e| e.to_string())?;
            serde_json::to_string(&receipt).map_err(|e| e.to_string())
        }
        _ => Err("usage: argon2id-zk-prover program-hashes | credential[-bcrypt|-mimc] ... | execute[-bcrypt|-mimc] ... | prove[-bcrypt|-mimc] ... [--out proof.json] | verify-file <envelope.json> <expected-statement.json>".to_owned()),
    }
}

fn params_from_args(args: &[String], offset: usize) -> Result<Argon2Params, String> {
    Ok(Argon2Params {
        memory_kib: parse_u32(args.get(offset), "memoryKiB")?,
        time_cost: parse_u32(args.get(offset + 1), "timeCost")?,
        lanes: parse_u32(args.get(offset + 2), "lanes")?,
    })
}

fn challenge_from_args(args: &[String], offset: usize) -> Result<[u32; 4], String> {
    Ok([
        parse_u32(args.get(offset), "challenge[0]")?,
        parse_u32(args.get(offset + 1), "challenge[1]")?,
        parse_u32(args.get(offset + 2), "challenge[2]")?,
        parse_u32(args.get(offset + 3), "challenge[3]")?,
    ])
}

fn parse_u32(value: Option<&String>, name: &str) -> Result<u32, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .parse()
        .map_err(|_| format!("invalid {name}"))
}
