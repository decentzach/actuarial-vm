//! # Actuarial Primitive Opcodes
//!
//! The AVM's Instruction Set Architecture is intentionally small: every
//! opcode encodes a single, **statically analyzable** primitive used to
//! construct insurance contracts on Bitcoin.
//!
//! Each "Actuarial Primitive Opcode" satisfies the protocol invariants:
//!
//! * **I-1 Totality** — the handler is straight-line; no loops, no recursion.
//! * **I-2 `O(1)`**   — the handler is constant-time relative to user input.
//! * **I-3 Determinism** — checked integer math only; no float, no RNG, no
//!   wall-clock.
//!
//! Each opcode has a **fixed Satoshi cost** so Underwriters can compute the
//! exact gas of a Claim Primitive prior to deployment (I-7).
//!
//! ## Opcode table
//!
//! | Byte | Mnemonic              | Cost (sats) | Purpose                                    |
//! |-----:|-----------------------|------------:|--------------------------------------------|
//! | 0x01 | `OP_ASSERT_SOLVENCY`  |        1000 | Enforce Ψ = 𝓑 / α_max ≥ 1.5 (fail-closed). |
//! | 0x02 | `OP_EVAL_STARK`       |        5000 | Verify a ZK-STARK trigger attestation.     |
//! | 0x03 | `OP_CALC_TAIL_METRIC` |         500 | (Reserved) compute tail-loss statistics.   |
//! | 0x04 | `OP_COMMIT_INDEMNITY` |        2000 | Commit indemnity; opens dispute window δ.  |

// ---------------------------------------------------------------------------
// Actuarial Primitive Opcodes
// ---------------------------------------------------------------------------

/// **Actuarial Primitive Opcode** `OP_ASSERT_SOLVENCY` (byte `0x01`).
///
/// Performs a consensus-level check that the risk-pool balance `B` satisfies
/// `B / α_max ≥ 1.5`. Fails closed via [`crate::vm::VmError::SolvencyException`]
/// (I-6). Cost: **1000 sats**.
pub const OP_ASSERT_SOLVENCY: u8 = 0x01;

/// **Actuarial Primitive Opcode** `OP_EVAL_STARK` (byte `0x02`).
///
/// Consumes a ZK-STARK proof attesting that a loss event satisfying the
/// Claim Primitive's trigger condition `τ` occurred (e.g.
/// `WindSpeed > 75kt`). The AVM never inspects the underlying data —
/// privacy of the insured is preserved (I-10). Verification is delegated
/// to a [`crate::vm::Verifier`] implementation and MUST be `O(1)` relative
/// to proof size (I-2). Cost: **5000 sats**.
pub const OP_EVAL_STARK: u8 = 0x02;

/// Backwards-compatible alias for [`OP_EVAL_STARK`].
pub const OP_EVAL_STARK_ATTESTATION: u8 = OP_EVAL_STARK;

/// **Actuarial Primitive Opcode** `OP_CALC_TAIL_METRIC` (byte `0x03`,
/// reserved).
///
/// Reserved for constant-time tail-loss / VaR computations. Cost: **500
/// sats**.
pub const OP_CALC_TAIL_METRIC: u8 = 0x03;

/// **Actuarial Primitive Opcode** `OP_COMMIT_INDEMNITY` (byte `0x04`).
///
/// Opens the BitVM 2 indemnity commitment on Bitcoin L1, starting the
/// dispute window `δ`. Fails closed with
/// [`crate::vm::VmError::ProtocolUnderChallenge`] when the VM is locked
/// by an active Vigilance Game dispute (Section 8.2). Cost: **2000 sats**.
pub const OP_COMMIT_INDEMNITY: u8 = 0x04;

/// Returns the canonical mnemonic for an Actuarial Primitive Opcode byte,
/// or `"OP_UNKNOWN"` for unrecognized opcodes. `O(1)`.
pub const fn mnemonic(opcode: u8) -> &'static str {
    match opcode {
        OP_ASSERT_SOLVENCY => "OP_ASSERT_SOLVENCY",
        OP_EVAL_STARK => "OP_EVAL_STARK",
        OP_CALC_TAIL_METRIC => "OP_CALC_TAIL_METRIC",
        OP_COMMIT_INDEMNITY => "OP_COMMIT_INDEMNITY",
        _ => "OP_UNKNOWN",
    }
}

/// Returns the fixed Satoshi cost of an Actuarial Primitive Opcode. `O(1)`.
pub const fn cost_sats(opcode: u8) -> u64 {
    match opcode {
        OP_ASSERT_SOLVENCY => 1_000,
        OP_EVAL_STARK => 5_000,
        OP_CALC_TAIL_METRIC => 500,
        OP_COMMIT_INDEMNITY => 2_000,
        _ => 0,
    }
}
