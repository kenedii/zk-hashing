import { argon2id } from 'hash-wasm';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { PARAMETERS, PROTOCOL, challengeMessage } from '../../server/protocol.js';

export async function derivePasswordKey(password, salt) {
  const hash = await argon2id({
    password, salt: hexToBytes(salt), memorySize: PARAMETERS.memoryKiB,
    iterations: PARAMETERS.iterations, parallelism: PARAMETERS.parallelism,
    hashLength: PARAMETERS.hashLength, outputType: 'binary',
  });
  // 48 HKDF bytes allow reduction to a secp256k1 scalar with negligible bias.
  const expanded = hkdf(sha256, hash, hexToBytes(salt), utf8ToBytes(PROTOCOL), 48);
  const scalar = BigInt(`0x${bytesToHex(expanded)}`) % (secp256k1.CURVE.n - 1n) + 1n;
  expanded.fill(0);
  const secretKey = hexToBytes(scalar.toString(16).padStart(64, '0'));
  return { hash, secretKey, publicKey: bytesToHex(schnorr.getPublicKey(secretKey)) };
}

export function makeLoginProof(key, accountId, challenge) {
  return bytesToHex(schnorr.sign(
    challengeMessage(accountId, challenge.challengeId, challenge.challenge), key,
  ));
}

export { PARAMETERS, bytesToHex };
