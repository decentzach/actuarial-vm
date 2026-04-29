// Copyright 2026 The Solven Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Solven — BitVM 2 Taproot script builder (no_std-compatible).
//!
//! Translates the AVM `OP_ASSERT_SOLVENCY` predicate (Ψ ≥ 1.5, fixed-point
//! per [`crate::vm`]) into raw Bitcoin Script suitable for embedding in a
//! Taproot leaf and bisected on L1 by the Vigilance Game (Section 8.2).
//!
//! Protocol invariants honored:
//!
//! * **I-1 / I-2** — the emitted script is straight-line and constant-length;
//!   builder loops are bounded by the 9-byte ceiling on a `u64` minimal push.
//! * **I-3** — only checked integer math; no floats, no wall-clock, no RNG.
//! * **I-7** — `α_max` is an input parameter so the script is statically
//!   analyzable prior to deployment.

use alloc::string::String;
use alloc::vec::Vec;

use crate::vm::{PSI_MIN_SCALED, PSI_SCALE};

// ---------------------------------------------------------------------------
// Bitcoin Script opcode bytes (subset used by the solvency predicate).
// ---------------------------------------------------------------------------

/// `OP_MUL` — multiply top two stack items (BitVM 2 emulated).
pub const OP_MUL: u8 = 0x95;
/// `OP_SWAP` — swap top two stack items.
pub const OP_SWAP: u8 = 0x7c;
/// `OP_GREATERTHANOREQUAL` — `a b -- (a >= b)`.
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
/// `OP_LESSTHANOREQUAL` — `a b -- (a <= b)`.
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
/// `OP_VERIFY` — fail the script unless top of stack is true.
pub const OP_VERIFY: u8 = 0x69;
/// `OP_PUSHDATA1` prefix (next byte = payload length in [76, 255]).
pub const OP_PUSHDATA1: u8 = 0x4c;
/// `OP_0` — pushes empty byte vector (numeric zero).
pub const OP_0: u8 = 0x00;
/// `OP_1` through `OP_16` — push small integers 1..=16.
pub const OP_1: u8 = 0x51;
/// `OP_2` — small-int push for 2 (used by the v2 predicate).
pub const OP_2: u8 = 0x52;
/// `OP_3` — small-int push for 3 (used by the v2 predicate).
pub const OP_3: u8 = 0x53;
/// `OP_SUB` — subtract top two stack items: `a b -- (a - b)`.
pub const OP_SUB: u8 = 0x94;
/// `OP_ADD` — add top two stack items: `a b -- (a + b)`.
pub const OP_ADD: u8 = 0x93;

/// Maximum length of a `u64` minimally-encoded as a Bitcoin Script number.
pub const MAX_SCRIPT_NUM_LEN: usize = 9;

/// Errors raised while emitting the solvency challenge script.
#[derive(Debug, PartialEq, Eq)]
pub enum ScriptError {
    /// Encoded payload exceeded the bounded push window. Should be unreachable
    /// for `u64` inputs; surfaces as a fail-closed guard.
    PushTooLarge,
    /// Arithmetic overflow computing pre-multiplied witness operands.
    Overflow,
}

/// Build the BitVM 2 solvency challenge script committing to the predicate
/// `B * 10 ≥ α_max * 15`.
pub fn generate_solvency_challenge_script(
    pool_balance: u64,
    alpha_max: u64,
) -> Result<Vec<u8>, ScriptError> {
    let mut script = Vec::with_capacity(64);

    push_u64(&mut script, pool_balance)?;
    push_small_int(&mut script, PSI_SCALE as u8);
    script.push(OP_MUL);

    push_u64(&mut script, alpha_max)?;
    push_small_int(&mut script, PSI_MIN_SCALED as u8);
    script.push(OP_MUL);

    script.push(OP_GREATERTHANOREQUAL);
    script.push(OP_VERIFY);

    Ok(script)
}

// ---------------------------------------------------------------------------
// v2 — witness-scaled solvency predicate ("vByte Crusher").
// ---------------------------------------------------------------------------

/// Constant body of the v2 (witness-scaled) solvency predicate.
///
/// **Semantics.** The predicate Ψ ≥ 1.5 is rewritten as
///
/// $$2\mathcal{B}\;\ge\;3\alpha_{\max}$$
///
/// then divided through by the GCD $k = \gcd(\mathcal{B}, \alpha_{\max})$ so
/// that the script consumes only the *reduced* operands
/// $\mathcal{B}' = \mathcal{B}/k$ and $\alpha'_{\max} = \alpha_{\max}/k$ from
/// the witness. Because $k$ cancels on both sides of the inequality, the
/// predicate is preserved exactly:
///
/// $$2\mathcal{B}\ge 3\alpha_{\max}\;\Longleftrightarrow\;
///   2\mathcal{B}'\ge 3\alpha'_{\max}.$$
///
/// **Witness layout.** Push order is `<B'> <α'>` (i.e. balance first, then
/// liability), so after the pushes `α'` is on top of stack. The body then:
///
/// ```text
/// OP_3 OP_MUL  OP_SWAP  OP_2 OP_MUL  OP_LESSTHANOREQUAL  OP_VERIFY
/// ```
///
/// computes `[B', α']  →  [3α', 2B']  →  (3α' ≤ 2B')  →  OP_VERIFY`.
///
/// **Footprint.** The body is **7 bytes**, constant for any (𝓑, α_max) — vs
/// 11–17 bytes for [`generate_solvency_challenge_script`] depending on the
/// magnitude of the literals. See [`SOLVENCY_PREDICATE_V2_HEX`] for the
/// canonical hex encoding.
///
/// **Security caveat.** Because the operands are pulled from the witness
/// rather than being inlined, the leaf hash no longer binds the specific
/// `(𝓑, α_max)` values. A real BitVM 2 deployment MUST bind the witness
/// operands to the underlying funding UTXO via a separate commitment
/// (e.g. a sibling hashlock leaf or a CSV-locked covenant leaf). This is
/// an explicit follow-up for the community bounty (see Challenge #2).
pub const SOLVENCY_PREDICATE_V2: [u8; 7] = [
    OP_3,                  // 0x53
    OP_MUL,                // 0x95
    OP_SWAP,               // 0x7c
    OP_2,                  // 0x52
    OP_MUL,                // 0x95
    OP_LESSTHANOREQUAL,    // 0xa1
    OP_VERIFY,             // 0x69
];

/// Hex of [`SOLVENCY_PREDICATE_V2`] (`"53957c5295a169"`, 14 chars / 7 bytes).
pub const SOLVENCY_PREDICATE_V2_HEX: &str = "53957c5295a169";

/// Reduced operands `(B', α', k)` for the v2 witness, where `k = gcd(B, α)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalingWitness {
    /// Reduced balance: `B / k`.
    pub balance_scaled: u64,
    /// Reduced liability cap: `α_max / k`.
    pub alpha_max_scaled: u64,
    /// `gcd(B, α_max)`. Always ≥ 1 (we treat `gcd(_, 0) = max(_, 1)`).
    pub gcd: u64,
}

impl ScalingWitness {
    /// Compute the reduced witness for a `(pool_balance, alpha_max)` pair.
    ///
    /// `O(log min(B, α))` via Euclid's algorithm — a *bounded* loop with at
    /// most ~92 iterations for any `u64` inputs (Lamé's theorem). This stays
    /// inside protocol invariant **I-2** because the bound is a compile-time
    /// constant of the type, not a function of user-controlled data.
    pub fn from_raw(pool_balance: u64, alpha_max: u64) -> Self {
        let k = gcd_u64(pool_balance, alpha_max).max(1);
        Self {
            balance_scaled: pool_balance / k,
            alpha_max_scaled: alpha_max / k,
            gcd: k,
        }
    }
}

/// Build the witness-scaled v2 solvency challenge script.
///
/// Returns the constant 7-byte [`SOLVENCY_PREDICATE_V2`] body. The `_pool_balance`
/// and `_alpha_max` arguments are accepted for API symmetry with v1 but are
/// **unused** — v2 inlines no operands into the script.
///
/// To produce the witness operands the prover must push, call
/// [`ScalingWitness::from_raw`].
pub fn generate_solvency_challenge_script_v2(
    _pool_balance: u64,
    _alpha_max: u64,
) -> Result<Vec<u8>, ScriptError> {
    Ok(SOLVENCY_PREDICATE_V2.to_vec())
}

/// Bounded Euclidean GCD on `u64`. `gcd(0, 0) = 0`.
const fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    // Lamé's theorem bounds the loop at ~92 iterations for u64 inputs.
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Hex-encode a script for printout / Taproot leaf inclusion.
pub fn encode_script_hex(script: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(script.len() * 2);
    for &b in script {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Internal helpers shared by v1 and v2.
// ---------------------------------------------------------------------------

/// Minimally encode `n` as a Bitcoin Script number and append to `script`.
///
/// Uses the `OP_1`..`OP_16` single-byte opcodes for values 1–16, `OP_0` for
/// zero, and a length-prefixed little-endian signed encoding otherwise. The
/// encoding is the same as Bitcoin Core's `CScriptNum`.
pub fn push_u64(script: &mut Vec<u8>, n: u64) -> Result<(), ScriptError> {
    match n {
        0 => {
            script.push(OP_0);
        }
        1..=16 => {
            push_small_int(script, n as u8);
        }
        _ => {
            let encoded = script_num_encode(n);
            let len = encoded.len();
            if len > MAX_SCRIPT_NUM_LEN {
                return Err(ScriptError::PushTooLarge);
            }
            script.push(len as u8);
            script.extend_from_slice(&encoded);
        }
    }
    Ok(())
}

/// Push a small integer (1–16) using the `OP_1`..`OP_16` opcodes.
pub fn push_small_int(script: &mut Vec<u8>, n: u8) {
    debug_assert!((1..=16).contains(&n));
    script.push(OP_1 - 1 + n); // OP_1 = 0x51, so OP_n = 0x50 + n
}

/// Minimally encode an unsigned 64-bit integer as a Bitcoin Script number
/// (little-endian, sign bit in the high bit of the last byte).
fn script_num_encode(mut n: u64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(9);
    while n > 0 {
        result.push((n & 0xff) as u8);
        n >>= 8;
    }
    // If the high bit of the last byte is set we need a zero sign byte.
    if result.last().unwrap() & 0x80 != 0 {
        result.push(0x00);
    }
    result
}

// ---------------------------------------------------------------------------
// v3 — pre-multiplied witness predicate ("vByte Crusher v3").
// ---------------------------------------------------------------------------

/// Constant body of the v3 (pre-multiplied witness) solvency predicate.
///
/// **Semantics.** The predicate Ψ ≥ 1.5 is rewritten as
///
/// $$2\mathcal{B}\;\ge\;3\alpha_{\max}$$
///
/// The prover supplies the *already-multiplied* values `u = 2·B/k` and
/// `v = 3·α_max/k` directly in the witness (where `k = gcd(2B, 3α_max)`),
/// so the script body only needs to verify `v ≤ u`, i.e.:
///
/// ```text
/// OP_LESSTHANOREQUAL  OP_VERIFY
/// ```
///
/// **Witness layout.** Push order is `<u> <v>` so `v` is on top. The body
/// then checks `v ≤ u` and fails if not.
///
/// **Footprint.** The body is **2 bytes** (`a169`), constant for any
/// (𝓑, α_max). Witness operands are minimal-push encoded by the prover.
/// For the reference example B=100,000 / α_max=150,000:
///   2B = 200,000 and 3α = 450,000, gcd = 50,000 → u=4, v=9 → 2 witness bytes.
/// Total on-chain cost: **4 bytes** (2 script + 2 witness) vs 7 bytes (v2).
///
/// **Security caveat.** Same as v2: the leaf hash does not bind the specific
/// operand values. A real deployment MUST bind them via a separate commitment.
/// Additionally, the prover must ensure `u` and `v` are correctly derived from
/// `2B` and `3α_max` respectively; a verifier can check `u * k == 2B` and
/// `v * k == 3α_max` out-of-band. This is noted as a follow-up (Challenge #2).
pub const SOLVENCY_PREDICATE_V3: [u8; 2] = [
    OP_LESSTHANOREQUAL,    // 0xa1
    OP_VERIFY,             // 0x69
];

/// Hex of [`SOLVENCY_PREDICATE_V3`] (`"a169"`, 4 chars / 2 bytes).
pub const SOLVENCY_PREDICATE_V3_HEX: &str = "a169";

/// Pre-multiplied witness operands `(u, v, k)` for the v3 predicate.
///
/// `u = 2 * pool_balance / k`, `v = 3 * alpha_max / k`,
/// `k = gcd(2 * pool_balance, 3 * alpha_max)`.
///
/// The script checks `v ≤ u`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreMultipliedWitness {
    /// `2 * pool_balance / k` — pushed first (deeper in stack).
    pub u: u64,
    /// `3 * alpha_max / k` — pushed second (top of stack).
    pub v: u64,
    /// `gcd(2 * pool_balance, 3 * alpha_max)`. Always ≥ 1.
    pub gcd: u64,
}

impl PreMultipliedWitness {
    /// Compute the pre-multiplied witness for a `(pool_balance, alpha_max)` pair.
    ///
    /// Returns `None` if the intermediate multiplication `2 * pool_balance` or
    /// `3 * alpha_max` overflows `u64`.
    pub fn from_raw(pool_balance: u64, alpha_max: u64) -> Option<Self> {
        let two_b = pool_balance.checked_mul(2)?;
        let three_a = alpha_max.checked_mul(3)?;
        let k = gcd_u64(two_b, three_a).max(1);
        Some(Self {
            u: two_b / k,
            v: three_a / k,
            gcd: k,
        })
    }

    /// Returns `true` if the solvency invariant `2B ≥ 3α_max` holds.
    pub fn is_solvent(&self) -> bool {
        self.v <= self.u
    }
}

/// Build the v3 (pre-multiplied witness) solvency challenge script.
///
/// Returns the constant 2-byte [`SOLVENCY_PREDICATE_V3`] body. Both parameters
/// are accepted for API symmetry but are **unused** — v3 inlines no operands.
///
/// To produce the witness operands the prover must push, call
/// [`PreMultipliedWitness::from_raw`].
pub fn generate_solvency_challenge_script_v3(
    _pool_balance: u64,
    _alpha_max: u64,
) -> Result<Vec<u8>, ScriptError> {
    Ok(SOLVENCY_PREDICATE_V3.to_vec())
}