import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';

export const PARAMETERS = Object.freeze({ algorithm: 'argon2id', memoryKiB: 32768, iterations: 3, parallelism: 1, hashLength: 32 });
export const PROTOCOL = 'zkhash-argon2id-schnorr-v1';

// Both sides bind the proof to the protocol, account, and server-issued challenge.
export function challengeMessage(accountId, challengeId, challenge) {
  return sha256(utf8ToBytes(JSON.stringify([PROTOCOL, accountId, challengeId, challenge])));
}
