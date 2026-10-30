use argon2id_zk_runtime::{
    AlgorithmParameters, Argon2Params, BcryptParams, ExpectedStatement, MIN_STARK_SECURITY_LEVEL,
    MimcParams, ProofAlgorithm, ProofEnvelope, RuntimeError, bcrypt_credential_for,
    bcrypt_program_hash, bcrypt_table_commitment, credential_for, execute_bcrypt_measure_sync,
    execute_measure_sync, execute_mimc_measure_sync, mimc_credential_for, mimc_program_hash,
    parse_hex_16, program_hash, prove_bcrypt_sync, prove_mimc_sync, prove_sync,
};

const SALT: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

fn minimal_params() -> Argon2Params {
    Argon2Params {
        memory_kib: 8,
        time_cost: 1,
        lanes: 1,
    }
}

fn expected_statement() -> ExpectedStatement {
    ExpectedStatement {
        credential: credential_for(b"hunter2", &SALT, minimal_params()).unwrap(),
        challenge: [0x1234_5678, 0x9abc_def0, 0x0fed_cba9, 0x8765_4321],
        salt_hex: "000102030405060708090a0b0c0d0e0f".to_owned(),
        params: AlgorithmParameters::Argon2id(minimal_params()),
    }
}

fn untrusted_envelope() -> ProofEnvelope {
    let expected = expected_statement();
    ProofEnvelope {
        format: "argon2id-miden-stark-v1".to_owned(),
        algorithm: ProofAlgorithm::Argon2id,
        program_hash: program_hash().unwrap(),
        credential: expected.credential,
        challenge: expected.challenge,
        salt_hex: expected.salt_hex,
        params: expected.params,
        output: vec![1],
        proof_base64: "not-a-proof".to_owned(),
    }
}

#[test]
fn known_minimal_credential_and_program_are_stable() {
    assert_eq!(MIN_STARK_SECURITY_LEVEL, 96);
    assert_eq!(
        credential_for(b"hunter2", &SALT, minimal_params()).unwrap(),
        [
            14_003_553_230_994_514_291,
            17_501_336_355_793_343_691,
            14_150_596_336_398_746_883,
            11_817_552_983_452_184_436,
        ]
    );
    assert_eq!(
        program_hash().unwrap(),
        [
            7_414_375_205_037_963_537,
            6_936_894_371_163_969_737,
            5_606_295_635_567_605_248,
            14_554_023_635_893_857_426,
        ]
    );
}

#[test]
fn bcrypt_and_mimc_program_bindings_are_stable() {
    assert_eq!(
        bcrypt_program_hash().unwrap(),
        [
            5_380_308_799_974_435_194,
            17_174_608_301_180_550_111,
            15_788_955_599_884_494_609,
            8_070_629_447_958_685_485,
        ]
    );
    assert_eq!(
        mimc_program_hash().unwrap(),
        [
            3_706_684_623_668_685_261,
            3_213_429_259_195_923_014,
            3_585_804_632_091_340_585,
            11_041_704_685_863_744_209,
        ]
    );
    assert_eq!(
        bcrypt_table_commitment(),
        [
            11_934_322_110_593_991_474,
            5_005_372_264_145_646_159,
            4_383_011_660_075_928_681,
            1_918_514_189_970_762_585,
        ]
    );
}

#[test]
fn credential_commits_to_password_salt_and_each_parameter() {
    let baseline = credential_for(b"hunter2", &SALT, minimal_params()).unwrap();
    assert_ne!(
        baseline,
        credential_for(b"hunter3", &SALT, minimal_params()).unwrap()
    );

    let mut changed_salt = SALT;
    changed_salt[15] ^= 1;
    assert_ne!(
        baseline,
        credential_for(b"hunter2", &changed_salt, minimal_params()).unwrap()
    );

    for params in [
        Argon2Params {
            memory_kib: 16,
            ..minimal_params()
        },
        Argon2Params {
            time_cost: 2,
            ..minimal_params()
        },
        Argon2Params {
            memory_kib: 16,
            lanes: 2,
            ..minimal_params()
        },
    ] {
        assert_ne!(baseline, credential_for(b"hunter2", &SALT, params).unwrap());
    }
}

#[test]
fn bcrypt_and_mimc_credentials_commit_to_the_private_input_and_salt() {
    let bcrypt = BcryptParams { cost: 4 };
    let mimc = MimcParams::default();
    let mut changed_salt = SALT;
    changed_salt[0] ^= 1;

    for (baseline, other_password, other_salt) in [
        (
            bcrypt_credential_for(b"hunter2", &SALT, bcrypt).unwrap(),
            bcrypt_credential_for(b"hunter3", &SALT, bcrypt).unwrap(),
            bcrypt_credential_for(b"hunter2", &changed_salt, bcrypt).unwrap(),
        ),
        (
            mimc_credential_for(b"hunter2", &SALT, mimc).unwrap(),
            mimc_credential_for(b"hunter3", &SALT, mimc).unwrap(),
            mimc_credential_for(b"hunter2", &changed_salt, mimc).unwrap(),
        ),
    ] {
        assert_ne!(baseline, other_password);
        assert_ne!(baseline, other_salt);
    }

    assert_ne!(
        bcrypt_credential_for(b"hunter2", &SALT, bcrypt).unwrap(),
        bcrypt_credential_for(b"hunter2", &SALT, BcryptParams { cost: 5 }).unwrap()
    );
}

#[test]
fn circuit_executes_the_full_minimal_statement() {
    let receipt = execute_measure_sync(
        b"hunter2",
        SALT,
        minimal_params(),
        expected_statement().challenge,
    )
    .unwrap();
    assert_eq!(receipt.output, vec![1]);
    assert_eq!(receipt.credential, expected_statement().credential);
    assert!(receipt.observed_cycles > 19_000_000);
}

#[test]
fn mimc_circuit_executes_the_complete_password_hash() {
    let challenge = expected_statement().challenge;
    let receipt =
        execute_mimc_measure_sync(b"hunter2", SALT, MimcParams::default(), challenge).unwrap();
    assert_eq!(receipt.output, vec![1]);
    assert_eq!(
        receipt.credential,
        mimc_credential_for(b"hunter2", &SALT, MimcParams::default()).unwrap()
    );
    assert!(receipt.observed_cycles > 400_000);
}

#[test]
fn bcrypt_circuit_executes_complete_eksblowfish_at_cost_four() {
    let challenge = expected_statement().challenge;
    let params = BcryptParams { cost: 4 };
    let receipt = execute_bcrypt_measure_sync(b"hunter2", SALT, params, challenge).unwrap();
    assert_eq!(receipt.output, vec![1]);
    assert_eq!(
        receipt.credential,
        bcrypt_credential_for(b"hunter2", &SALT, params).unwrap()
    );
    assert!(receipt.observed_cycles > 360_000_000);
}

#[test]
fn verifier_fails_closed_on_every_external_binding() {
    let envelope = untrusted_envelope();
    let expected = expected_statement();

    let error = expected.verify(&envelope).unwrap_err();
    assert!(matches!(error, RuntimeError::ProofEncoding));

    let mut changed = expected.clone();
    changed.credential[0] ^= 1;
    assert!(matches!(
        changed.verify(&envelope),
        Err(RuntimeError::CredentialMismatch)
    ));

    let mut changed = expected.clone();
    changed.challenge[3] ^= 1;
    assert!(matches!(
        changed.verify(&envelope),
        Err(RuntimeError::InvalidInput("challenge mismatch"))
    ));

    let mut changed = expected.clone();
    changed.salt_hex.replace_range(30..32, "00");
    assert!(matches!(
        changed.verify(&envelope),
        Err(RuntimeError::InvalidInput("salt mismatch"))
    ));

    let mut changed = expected.clone();
    changed.params = AlgorithmParameters::Argon2id(Argon2Params {
        time_cost: 2,
        ..minimal_params()
    });
    assert!(matches!(
        changed.verify(&envelope),
        Err(RuntimeError::InvalidInput("algorithm parameters mismatch"))
    ));

    let mut changed_envelope = envelope.clone();
    changed_envelope.program_hash[0] ^= 1;
    assert!(matches!(
        expected.verify(&changed_envelope),
        Err(RuntimeError::InvalidInput("program hash mismatch"))
    ));

    let mut changed_envelope = envelope.clone();
    changed_envelope.output = vec![0];
    assert!(matches!(
        expected.verify(&changed_envelope),
        Err(RuntimeError::InvalidInput("unexpected public output"))
    ));

    let mut changed_envelope = envelope;
    changed_envelope.format.push_str("-unknown");
    assert!(matches!(
        expected.verify(&changed_envelope),
        Err(RuntimeError::InvalidInput(
            "unsupported proof format or algorithm"
        ))
    ));
}

#[test]
fn malformed_inputs_are_rejected_without_panics() {
    for salt in [
        "",
        "00",
        "000102030405060708090a0b0c0d0e0",
        "gg0102030405060708090a0b0c0d0e0f",
    ] {
        assert!(parse_hex_16(salt).is_err());
    }
    for password in [&b""[..], &[7u8; 65][..]] {
        assert!(credential_for(password, &SALT, minimal_params()).is_err());
        assert!(bcrypt_credential_for(password, &SALT, BcryptParams { cost: 4 }).is_err());
        assert!(mimc_credential_for(password, &SALT, MimcParams::default()).is_err());
    }
    for params in [
        Argon2Params {
            memory_kib: 7,
            time_cost: 1,
            lanes: 1,
        },
        Argon2Params {
            memory_kib: 8,
            time_cost: 0,
            lanes: 1,
        },
        Argon2Params {
            memory_kib: 8,
            time_cost: 1,
            lanes: 0,
        },
        Argon2Params {
            memory_kib: 40,
            time_cost: 1,
            lanes: 5,
        },
    ] {
        assert!(credential_for(b"hunter2", &SALT, params).is_err());
    }
    for cost in [0, 3, 17, u32::MAX] {
        assert!(bcrypt_credential_for(b"hunter2", &SALT, BcryptParams { cost }).is_err());
    }
    assert!(mimc_credential_for(b"hunter2", &SALT, MimcParams { rounds: 219 }).is_err());
}

#[test]
fn wrong_expected_credential_is_rejected_before_trace_construction() {
    let mut wrong = expected_statement().credential;
    wrong[0] ^= 1;
    assert!(matches!(
        prove_sync(
            b"hunter2",
            SALT,
            minimal_params(),
            expected_statement().challenge,
            Some(wrong),
        ),
        Err(RuntimeError::CredentialMismatch),
    ));

    assert!(matches!(
        prove_bcrypt_sync(
            b"hunter2",
            SALT,
            BcryptParams { cost: 4 },
            expected_statement().challenge,
            Some(wrong),
        ),
        Err(RuntimeError::CredentialMismatch),
    ));
    assert!(matches!(
        prove_mimc_sync(
            b"hunter2",
            SALT,
            MimcParams::default(),
            expected_statement().challenge,
            Some(wrong),
        ),
        Err(RuntimeError::CredentialMismatch),
    ));
}

#[test]
fn verifier_rejects_cross_algorithm_envelopes_before_proof_decoding() {
    let envelope = untrusted_envelope();
    let expected = ExpectedStatement {
        credential: envelope.credential,
        challenge: envelope.challenge,
        salt_hex: envelope.salt_hex.clone(),
        params: AlgorithmParameters::Mimc7(MimcParams::default()),
    };
    assert!(matches!(
        expected.verify(&envelope),
        Err(RuntimeError::InvalidInput(
            "unsupported proof format or algorithm"
        ))
    ));
}

#[test]
fn noncanonical_public_field_is_rejected() {
    let envelope = untrusted_envelope();
    let mut expected = expected_statement();
    expected.credential[0] = u64::MAX;
    let mut matching = envelope;
    matching.credential = expected.credential;
    assert!(matches!(
        expected.verify(&matching),
        Err(RuntimeError::InvalidInput(
            "non-canonical credential field element"
        )),
    ));
}

#[test]
fn envelope_schema_never_contains_the_password() {
    let json = serde_json::to_string(&untrusted_envelope()).unwrap();
    assert!(!json.contains("hunter2"));
    assert!(!json.contains("password"));
}

#[test]
fn non_ascii_salt_is_rejected_without_panicking() {
    // 32 bytes whose second character is a multibyte UTF-8 sequence.
    let salt = format!("0{}{}", '\u{20ac}', "0".repeat(28));
    assert_eq!(salt.len(), 32);
    assert!(matches!(parse_hex_16(&salt), Err(RuntimeError::InvalidHex(_))));
    assert!(parse_hex_16("+f0102030405060708090a0b0c0d0e0f").is_err());
    assert_eq!(parse_hex_16("000102030405060708090A0B0C0D0E0F").unwrap(), SALT);
}
