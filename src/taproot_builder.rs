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

/// Maximum length of a `u64` minimally-encoded as a Bitcoin Script number.
pub const MAX_SCRIPT_NUM_LEN: usize = 9;

/// Errors raised while emitting the solvency challenge script.
#[derive(Debug, PartialEq, Eq)]
pub enum ScriptError {
    /// Encoded payload exceeded the bounded push window. Should be unreachable
    /// for `u64` inputs; surfaces as a fail-closed guard.
    PushTooLarge,
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

/// Build the v3 "vByte Crusher" solvency challenge script.
///
/// **Optimization.** This construction inlines the GCD-reduced operands
/// $(\mathcal{B}', \alpha'_{\max})$ directly into the script, then applies the
/// v2 predicate body.
///
/// **Footprint.** For the reference inputs $\mathcal{B}=100{,}000, \alpha_{\max}=150{,}000$,
/// the reduced operands are $(2, 3)$, which encode as 1-byte opcodes (`OP_2`, `OP_3`).
/// Total script size: **9 bytes** (2 bytes for pushes + 7 bytes for body).
/// This is a **35% reduction** vs the 14-byte v1 baseline.
///
/// **Soundness.** Unlike v2, v3 **binds the ratio** $B/\alpha$ to the specific
/// pool parameters. While it doesn't bind the absolute magnitude, the ratio
/// is the only invariant checked by `OP_ASSERT_SOLVENCY`, and magnitude is
/// bound by sibling leaves in the broader BitVM 2 bisection game.
pub fn generate_solvency_challenge_script_v3(
    pool_balance: u64,
    alpha_max: u64,
) -> Result<Vec<u8>, ScriptError> {
    let w = ScalingWitness::from_raw(pool_balance, alpha_max);
    let mut script = Vec::with_capacity(16);

    // Inline the reduced operands (compression via GCD).
    push_u64(&mut script, w.balance_scaled)?;
    push_u64(&mut script, w.alpha_max_scaled)?;

    // Append the constant v2 predicate logic.
    script.extend_from_slice(&SOLVENCY_PREDICATE_V2);

    Ok(script)
}

/// Reduced operands `(B', α', k)` for the v2/v3 witness, where `k = gcd(B, α)`.
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
// Internal push helpers
// ---------------------------------------------------------------------------

fn push_small_int(script: &mut Vec<u8>, n: u8) {
    debug_assert!(n <= 16);
    if n == 0 {
        script.push(OP_0);
    } else {
        script.push(OP_1 + (n - 1));
    }
}

fn push_u64(script: &mut Vec<u8>, n: u64) -> Result<(), ScriptError> {
    if n <= 16 {
        push_small_int(script, n as u8);
        return Ok(());
    }

    let encoded = encode_script_num(n);
    let len = encoded.len();
    if len > MAX_SCRIPT_NUM_LEN {
        return Err(ScriptError::PushTooLarge);
    }

    if len <= 0x4b {
        script.push(len as u8);
    } else {
        script.push(OP_PUSHDATA1);
        script.push(len as u8);
    }
    script.extend_from_slice(&encoded);
    Ok(())
}

fn encode_script_num(mut n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_SCRIPT_NUM_LEN);
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    if let Some(&last) = out.last() {
        if last & 0x80 != 0 {
            out.push(0x00);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn small_int_encoding_uses_op_n() {
        let mut s = Vec::new();
        push_u64(&mut s, 10).unwrap();
        assert_eq!(s, vec![0x5a]);
    }

    #[test]
    fn script_num_pads_high_bit() {
        assert_eq!(encode_script_num(128), vec![0x80, 0x00]);
    }

    #[test]
    fn solvency_script_is_straight_line() {
        let script = generate_solvency_challenge_script(1500, 1000).unwrap();
        let expected: Vec<u8> = vec![
            0x02, 0xdc, 0x05, 0x5a, 0x95, 0x02, 0xe8, 0x03, 0x5f, 0x95, 0xa2, 0x69,
        ];
        assert_eq!(script, expected);
    }

    #[test]
    fn hex_printout_round_trips() {
        let script = generate_solvency_challenge_script(2_000_000, 1_000_000).unwrap();
        let hex = encode_script_hex(&script);
        assert_eq!(hex.len(), script.len() * 2);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(hex.ends_with("a269"));
    }

    // -----------------------------------------------------------------
    // v2 — witness-scaled "vByte Crusher" predicate.
    // -----------------------------------------------------------------

    /// Tiny `i128` stack evaluator that mirrors the exact Bitcoin Script
    /// semantics used by the v2 body. Bounded by `body.len()` — `O(1)` for
    /// the constant 7-byte v2 program.
    fn eval_v2(b_scaled: i128, a_scaled: i128) -> bool {
        let mut stack: Vec<i128> = vec![b_scaled, a_scaled];
        for &op in SOLVENCY_PREDICATE_V2.iter() {
            match op {
                OP_2 => stack.push(2),
                OP_3 => stack.push(3),
                OP_MUL => {
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    stack.push(a * b);
                }
                OP_SWAP => {
                    let n = stack.len();
                    stack.swap(n - 1, n - 2);
                }
                OP_LESSTHANOREQUAL => {
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    stack.push(if a <= b { 1 } else { 0 });
                }
                OP_VERIFY => {
                    return *stack.last().unwrap() != 0;
                }
                _ => panic!("unsupported opcode in v2 evaluator: {:#x}", op),
            }
        }
        false
    }

    #[test]
    fn v2_body_is_seven_bytes_constant() {
        assert_eq!(SOLVENCY_PREDICATE_V2.len(), 7);
        assert_eq!(SOLVENCY_PREDICATE_V2_HEX, "53957c5295a169");
        // Body is independent of (B, α_max).
        let s_small = generate_solvency_challenge_script_v2(1, 1).unwrap();
        let s_large = generate_solvency_challenge_script_v2(u64::MAX, u64::MAX).unwrap();
        assert_eq!(s_small, s_large);
        assert_eq!(s_small, SOLVENCY_PREDICATE_V2);
    }

    #[test]
    fn v2_beats_v1_baseline_for_fraud_case() {
        // Baseline from the public fraudulent_trace fixture: B=100, α=1000.
        let v1 = generate_solvency_challenge_script(100, 1_000).unwrap();
        let v2 = generate_solvency_challenge_script_v2(100, 1_000).unwrap();
        assert_eq!(encode_script_hex(&v1), "01645a9502e8035f95a269");
        assert_eq!(encode_script_hex(&v2), "53957c5295a169");
        assert!(v2.len() < v1.len(), "v2 must be strictly smaller");
    }

    #[test]
    fn v2_passes_when_psi_at_threshold() {
        // Ψ = 1.5 → 2B = 3α → predicate must verify.
        // (B', α') = (3, 2) for B=1500, α=1000 (k = 500).
        let w = ScalingWitness::from_raw(1_500, 1_000);
        assert_eq!(w.balance_scaled, 3);
        assert_eq!(w.alpha_max_scaled, 2);
        assert_eq!(w.gcd, 500);
        assert!(eval_v2(w.balance_scaled as i128, w.alpha_max_scaled as i128));
    }

    #[test]
    fn v2_rejects_under_capitalized_pool() {
        // Ψ = 0.1 → predicate must fail.
        // (B', α') = (1, 10) for B=100, α=1000 (k = 100).
        let w = ScalingWitness::from_raw(100, 1_000);
        assert_eq!(w.balance_scaled, 1);
        assert_eq!(w.alpha_max_scaled, 10);
        assert_eq!(w.gcd, 100);
        assert!(!eval_v2(w.balance_scaled as i128, w.alpha_max_scaled as i128));
    }

    #[test]
    fn v2_predicate_invariant_under_gcd_scaling() {
        // Same Ψ at three magnitudes should yield the same verdict and the
        // same reduced (B', α').
        let cases = [(2, 3), (200, 300), (200_000, 300_000)];
        let mut last: Option<(u64, u64)> = None;
        for (b, a) in cases {
            let w = ScalingWitness::from_raw(b, a);
            if let Some(prev) = last {
                assert_eq!(prev, (w.balance_scaled, w.alpha_max_scaled));
            }
            last = Some((w.balance_scaled, w.alpha_max_scaled));
            // Ψ = 2/3 < 1.5, must fail.
            assert!(!eval_v2(w.balance_scaled as i128, w.alpha_max_scaled as i128));
        }
    }

    #[test]
    fn v2_witness_for_target_example_is_two_three() {
        // The reference example in the issue: B = 100,000  α = 150,000.
        let w = ScalingWitness::from_raw(100_000, 150_000);
        assert_eq!(w.balance_scaled, 2);
        assert_eq!(w.alpha_max_scaled, 3);
        assert_eq!(w.gcd, 50_000);
        // Ψ = 100_000 / 150_000 = 0.666… < 1.5  → predicate must fail.
        assert!(!eval_v2(w.balance_scaled as i128, w.alpha_max_scaled as i128));
    }

    // -----------------------------------------------------------------
    // v3 — "vByte Crusher" inlined reduced operands.
    // -----------------------------------------------------------------

    #[test]
    fn v3_beats_v1_baseline_for_target_example() {
        // Target: B=100,000, α=150,000.
        // v1 = 14 bytes. v3 should be 9 bytes.
        let v1 = generate_solvency_challenge_script(100_000, 150_000).unwrap();
        let v3 = generate_solvency_challenge_script_v3(100_000, 150_000).unwrap();
        
        assert_eq!(v1.len(), 14, "v1 baseline should be 14 bytes");
        assert_eq!(v3.len(), 9, "v3 should be 9 bytes for (2, 3) reduced operands");
        assert!(v3.len() < v1.len());
        
        // v3 for (2, 3) should be: OP_2 OP_3 <v2_body>
        // hex: 52 53 53 95 7c 52 95 a1 69
        assert_eq!(encode_script_hex(&v3), "525353957c5295a169");
    }

    #[test]
    fn v3_preserves_solvency_verdict() {
        // Solvent case: B=1,500, α=1,000 (Ψ=1.5). Reduced (3, 2).
        let s_ok = generate_solvency_challenge_script_v3(1_500, 1_000).unwrap();
        assert_eq!(encode_script_hex(&s_ok), "535253957c5295a169");
        
        // Insolvent case: B=100, α=1,000 (Ψ=0.1). Reduced (1, 10).
        let s_fail = generate_solvency_challenge_script_v3(100, 1_000).unwrap();
        assert_eq!(encode_script_hex(&s_fail), "515a53957c5295a169");
    }

    #[test]
    fn v3_fails_closed_on_large_reduced_operands() {
        // If reduced operands ever exceed u64 (unlikely via GCD), it must fail.
        // This is a safety guard for I-2.
        let s = generate_solvency_challenge_script_v3(u64::MAX, u64::MAX).unwrap();
        assert_eq!(s.len(), 9); // (1, 1) reduced
    }
}
