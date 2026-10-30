/* tslint:disable */
/* eslint-disable */

export function bcrypt_circuit_program_hash(): any;

export function circuit_program_hash(): any;

export function credential_argon2id(password: string, salt_hex: string, memory_kib: number, time_cost: number, lanes: number): any;

export function credential_bcrypt2b(password: string, salt_hex: string, cost: number): any;

export function credential_mimc7(password: string, salt_hex: string): any;

export function mimc_circuit_program_hash(): any;

export function prove_argon2id(password: string, salt_hex: string, memory_kib: number, time_cost: number, lanes: number, challenge: Uint32Array, expected_credential: any): Promise<any>;

export function prove_bcrypt2b(password: string, salt_hex: string, cost: number, challenge: Uint32Array, expected_credential: any): Promise<any>;

export function prove_mimc7(password: string, salt_hex: string, challenge: Uint32Array, expected_credential: any): Promise<any>;

export function start(): void;

export function verify_argon2id(envelope: any, expected_credential: any, expected_challenge: Uint32Array, expected_salt_hex: string, memory_kib: number, time_cost: number, lanes: number): any;

export function verify_bcrypt2b(envelope: any, expected_credential: any, expected_challenge: Uint32Array, expected_salt_hex: string, cost: number): any;

export function verify_mimc7(envelope: any, expected_credential: any, expected_challenge: Uint32Array, expected_salt_hex: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly bcrypt_circuit_program_hash: () => [number, number, number];
    readonly circuit_program_hash: () => [number, number, number];
    readonly credential_argon2id: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly credential_bcrypt2b: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly credential_mimc7: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly mimc_circuit_program_hash: () => [number, number, number];
    readonly prove_argon2id: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: any) => any;
    readonly prove_bcrypt2b: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: any) => any;
    readonly prove_mimc7: (a: number, b: number, c: number, d: number, e: number, f: number, g: any) => any;
    readonly start: () => void;
    readonly verify_argon2id: (a: any, b: any, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
    readonly verify_bcrypt2b: (a: any, b: any, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly verify_mimc7: (a: any, b: any, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly wasm_bindgen_99e65c84e16d0539___convert__closures_____invoke___wasm_bindgen_99e65c84e16d0539___JsValue__core_a53d42feb9a9484c___result__Result_____wasm_bindgen_99e65c84e16d0539___JsError___true_: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen_99e65c84e16d0539___convert__closures_____invoke___js_sys_7ae411a37f990134___Function_fn_wasm_bindgen_99e65c84e16d0539___JsValue_____wasm_bindgen_99e65c84e16d0539___sys__Undefined___js_sys_7ae411a37f990134___Function_fn_wasm_bindgen_99e65c84e16d0539___JsValue_____wasm_bindgen_99e65c84e16d0539___sys__Undefined_______true_: (a: number, b: number, c: any, d: any) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
