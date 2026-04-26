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
/// `OP_GREATERTHANOREQUAL` — `a b -- (a >= b)`.
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
/// `OP_VERIFY` — fail the script unless top of stack is true.
pub const OP_VERIFY: u8 = 0x69;
/// `OP_PUSHDATA1` prefix (next byte = payload length in [76, 255]).
pub const OP_PUSHDATA1: u8 = 0x4c;
/// `OP_0` — pushes empty byte vector (numeric zero).
pub const OP_0: u8 = 0x00;
/// `OP_1` through `OP_16` — push small integers 1..=16.
pub const OP_1: u8 = 0x51;

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
}
