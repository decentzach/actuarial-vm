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

//! Solven AVM — interpreter (no_std-compatible).
//!
//! See crate-level docs for invariants. This module hosts the minimal
//! [`Vm`] state machine and an [`Vm::execute`] entry point that dispatches
//! [`ClaimPrimitive`] tuples through the Actuarial Primitive Opcodes
//! defined in [`crate::opcodes`].

use crate::opcodes::{OP_ASSERT_SOLVENCY, OP_COMMIT_INDEMNITY, OP_EVAL_STARK};

/// Minimum Solvency Ratio Ψ, scaled by [`PSI_SCALE`] to stay in integer math.
///
/// Ψ_min = 1.5  →  encoded as `15` with `PSI_SCALE = 10`.
pub const PSI_MIN_SCALED: u128 = 15;
/// Fixed-point scale factor for Ψ (deterministic, no floating point).
pub const PSI_SCALE: u128 = 10;

/// Formal Claim Primitive 𝒞 = { π, τ, α, δ }.
#[derive(Debug, Clone)]
pub struct ClaimPrimitive {
    /// π — ZK commitment hash anchoring off-chain policy terms.
    pub pi: [u8; 32],
    /// τ — Trigger condition descriptor (opaque, statically sized).
    pub tau: [u8; 32],
    /// α_max — maximum adjusted payout, denominated in Satoshis.
    pub alpha_max_sats: u64,
    /// δ — Dispute window, measured in Bitcoin blocks.
    pub delta_blocks: u32,
}

/// Typed VM errors. No `panic!` is permitted on the consensus path.
#[derive(Debug, PartialEq, Eq)]
pub enum VmError {
    /// Ψ < 1.5 — under-capitalized ("naked") risk; commitment refused.
    SolvencyException,
    /// STARK attestation failed verification against the Claim Primitive.
    AttestationRejected,
    /// `OP_EVAL_STARK` invoked without a registered [`Verifier`] in context.
    MissingVerifier,
    /// Opcode byte is not recognized by the current ISA revision.
    UnknownOpcode(u8),
    /// Arithmetic would overflow; consensus paths must use checked math.
    ArithmeticOverflow,
    /// Protocol state is locked because an open BitVM 2 challenge exists
    /// against this VM's risk pool. No new indemnity commitments may be made
    /// until the challenge resolves (Section 8.2 — Vigilance Game).
    ProtocolUnderChallenge,
}

/// STARK attestation verifier. Real implementations consume a ZK-STARK proof
/// and validate it against the Claim Primitive's trigger condition `τ`.
///
/// Implementors MUST be `O(1)` in proof size and side-effect free (I-2, I-3).
pub trait Verifier {
    /// Returns `true` iff `proof` is a valid attestation that the trigger
    /// condition encoded in `claim.tau` has fired.
    fn verify_attestation(&self, claim: &ClaimPrimitive, proof: &[u8]) -> bool;
}

/// Test/dev verifier that accepts a proof iff its first 32 bytes match a
/// hard-coded sensor signature. Strictly constant-time: a single fixed-width
/// slice comparison, no iteration over user-controlled length.
///
/// **Not for production.** Production deployments MUST replace this with a
/// real STARK verifier.
pub struct MockWeatherVerifier {
    /// 32-byte hard-coded "signed hash" identifying a known sensor.
    pub sensor_signature: [u8; 32],
}

impl MockWeatherVerifier {
    /// Construct a verifier bound to a specific sensor signature.
    pub const fn new(sensor_signature: [u8; 32]) -> Self {
        Self { sensor_signature }
    }
}

impl Verifier for MockWeatherVerifier {
    fn verify_attestation(&self, _claim: &ClaimPrimitive, proof: &[u8]) -> bool {
        // O(1): fixed 32-byte equality check on the proof prefix.
        if proof.len() < 32 {
            return false;
        }
        proof[..32] == self.sensor_signature
    }
}

/// Per-instruction execution context. Carries opcode operands (e.g. STARK
/// proof bytes) and resolved capabilities (e.g. the active [`Verifier`]).
///
/// Lifetimes keep the context strictly borrowed; the VM never retains it
/// beyond a single `execute` call (I-4).
#[derive(Default)]
pub struct ExecCtx<'a> {
    /// Raw STARK proof bytes for `OP_EVAL_STARK`. Empty for opcodes that
    /// do not consume a proof.
    pub proof: &'a [u8],
    /// Verifier used by `OP_EVAL_STARK`. `None` for opcodes that do not
    /// require attestation.
    pub verifier: Option<&'a dyn Verifier>,
}

/// Minimal AVM state. The VM is a pure function of its inputs; it carries no
/// hidden mutable state beyond the current risk-pool balance snapshot.
#[derive(Debug, Clone)]
pub struct Vm {
    /// 𝓑 — risk-pool UTXO balance snapshot, in Satoshis.
    pub pool_balance_sats: u64,
    /// Vigilance Game state lock (Section 8.2). When `true`, an active BitVM 2
    /// challenge is in progress and `OP_COMMIT_INDEMNITY` MUST fail closed.
    pub is_under_challenge: bool,
}

impl Vm {
    /// Construct a VM bound to a specific risk-pool balance snapshot 𝓑.
    pub fn new(pool_balance_sats: u64) -> Self {
        Self {
            pool_balance_sats,
            is_under_challenge: false,
        }
    }

    /// Execute a single AVM instruction against `claim`.
    ///
    /// `O(1)`: dispatch is a constant-time match on `opcode`. No iteration,
    /// no recursion, no re-entry into `execute` from handlers (I-4).
    pub fn execute(
        &self,
        opcode: u8,
        claim: &ClaimPrimitive,
        ctx: &ExecCtx<'_>,
    ) -> Result<(), VmError> {
        match opcode {
            OP_ASSERT_SOLVENCY => self.op_assert_solvency(claim),
            OP_EVAL_STARK => self.op_eval_stark(claim, ctx),
            OP_COMMIT_INDEMNITY => self.op_commit_indemnity(claim),
            other => Err(VmError::UnknownOpcode(other)),
        }
    }

    /// `OP_ASSERT_SOLVENCY` (0x01).
    ///
    /// Computes Ψ = 𝓑 / α_max in fixed-point (`PSI_SCALE`) and enforces
    /// Ψ ≥ 1.5. Uses `checked_mul` to honor I-3 (deterministic, no wrap).
    pub(crate) fn op_assert_solvency(&self, claim: &ClaimPrimitive) -> Result<(), VmError> {
        if claim.alpha_max_sats == 0 {
            return Ok(());
        }

        let balance_scaled = (self.pool_balance_sats as u128)
            .checked_mul(PSI_SCALE)
            .ok_or(VmError::ArithmeticOverflow)?;

        let threshold = (claim.alpha_max_sats as u128)
            .checked_mul(PSI_MIN_SCALED)
            .ok_or(VmError::ArithmeticOverflow)?;

        if balance_scaled >= threshold {
            Ok(())
        } else {
            Err(VmError::SolvencyException)
        }
    }

    /// `OP_EVAL_STARK` (0x02).
    pub(crate) fn op_eval_stark(
        &self,
        claim: &ClaimPrimitive,
        ctx: &ExecCtx<'_>,
    ) -> Result<(), VmError> {
        let verifier = ctx.verifier.ok_or(VmError::MissingVerifier)?;
        if verifier.verify_attestation(claim, ctx.proof) {
            Ok(())
        } else {
            Err(VmError::AttestationRejected)
        }
    }

    /// `OP_COMMIT_INDEMNITY` (0x04).
    pub(crate) fn op_commit_indemnity(&self, _claim: &ClaimPrimitive) -> Result<(), VmError> {
        if self.is_under_challenge {
            return Err(VmError::ProtocolUnderChallenge);
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // v3 — witness-bound solvency check (Issue #4 / PR #9).
    // -----------------------------------------------------------------

    /// Verify that a witness pair `(trace_b, trace_alpha)` is *proportional*
    /// to the actual `(𝓑, α_max)` known to the VM.
    ///
    /// Enforces the cross-product equality
    ///
    /// $$\text{trace\_b} \cdot \alpha_{\max} \;=\; \text{trace\_alpha} \cdot \mathcal{B}$$
    ///
    /// which holds iff $\text{trace\_b}/\text{trace\_alpha} = \mathcal{B}/\alpha_{\max}$.
    /// All math is `u128` so the products cannot overflow for any `u64`
    /// inputs. Constant-time (no iteration), satisfies **I-2**.
    ///
    /// Used by [`Vm::execute_assert_solvency_v3`] to bind the witness-scaled
    /// operands of [`crate::taproot_builder::SOLVENCY_PREDICATE_V2`] to the
    /// underlying funding UTXO without requiring an additional Taproot leaf.
    pub fn validate_witness_trace(
        &self,
        claim_alpha_max: u64,
        pool_balance: u64,
        trace_b: u64,
        trace_alpha: u64,
    ) -> bool {
        if trace_b == 0 || trace_alpha == 0 {
            return false;
        }
        (trace_b as u128) * (claim_alpha_max as u128)
            == (trace_alpha as u128) * (pool_balance as u128)
    }

    /// `OP_ASSERT_SOLVENCY` with a witness-bound proportional trace.
    ///
    /// Two-stage check (both stages fail-closed per **I-6**):
    ///
    /// 1. **Binding.** [`Self::validate_witness_trace`] confirms the witness
    ///    pair is a faithful proportional representation of the on-chain
    ///    `(𝓑, α_max)`. Tampering yields [`VmError::AttestationRejected`].
    /// 2. **Solvency.** Verifies $2\mathcal{B} \ge 3\alpha_{\max}$
    ///    ($\equiv \Psi \ge 1.5$). Failure yields
    ///    [`VmError::SolvencyException`].
    ///
    /// All arithmetic is `u128` saturating-multiply on `u64` inputs, so the
    /// products are bounded by `2^128` and cannot wrap. `O(1)`.
    pub fn execute_assert_solvency_v3(
        &self,
        claim: &ClaimPrimitive,
        trace_b: u64,
        trace_alpha: u64,
    ) -> Result<(), VmError> {
        if !self.validate_witness_trace(
            claim.alpha_max_sats,
            self.pool_balance_sats,
            trace_b,
            trace_alpha,
        ) {
            return Err(VmError::AttestationRejected);
        }

        let lhs = (self.pool_balance_sats as u128)
            .checked_mul(2)
            .ok_or(VmError::ArithmeticOverflow)?;
        let rhs = (claim.alpha_max_sats as u128)
            .checked_mul(3)
            .ok_or(VmError::ArithmeticOverflow)?;

        if lhs >= rhs {
            Ok(())
        } else {
            Err(VmError::SolvencyException)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_claim(alpha_max_sats: u64) -> ClaimPrimitive {
        ClaimPrimitive {
            pi: [0u8; 32],
            tau: [0u8; 32],
            alpha_max_sats,
            delta_blocks: 144, // ~1 day on Bitcoin L1
        }
    }

    #[test]
    fn solvency_passes_when_psi_at_threshold() {
        let vm = Vm::new(1_500);
        assert!(vm
            .execute(OP_ASSERT_SOLVENCY, &mock_claim(1_000), &ExecCtx::default())
            .is_ok());
    }

    #[test]
    fn solvency_fails_below_threshold() {
        let vm = Vm::new(1_499);
        assert_eq!(
            vm.execute(OP_ASSERT_SOLVENCY, &mock_claim(1_000), &ExecCtx::default()),
            Err(VmError::SolvencyException)
        );
    }

    #[test]
    fn unknown_opcode_is_rejected() {
        let vm = Vm::new(10_000);
        assert_eq!(
            vm.execute(0xFF, &mock_claim(1), &ExecCtx::default()),
            Err(VmError::UnknownOpcode(0xFF))
        );
    }

    #[test]
    fn eval_stark_without_verifier_fails_closed() {
        let vm = Vm::new(10_000);
        assert_eq!(
            vm.execute(OP_EVAL_STARK, &mock_claim(1), &ExecCtx::default()),
            Err(VmError::MissingVerifier)
        );
    }

    #[test]
    fn eval_stark_rejects_unsigned_proof() {
        let sig = [0xA5u8; 32];
        let verifier = MockWeatherVerifier::new(sig);
        let bad_proof = [0x00u8; 32];
        let vm = Vm::new(10_000);
        let ctx = ExecCtx {
            proof: &bad_proof,
            verifier: Some(&verifier),
        };
        assert_eq!(
            vm.execute(OP_EVAL_STARK, &mock_claim(1_000), &ctx),
            Err(VmError::AttestationRejected)
        );
    }

    #[test]
    fn test_hurricane_claim_flow() {
        let hurricane_sig: [u8; 32] = *b"HURRICANE-SENSOR::SIGNED-HASH-01";
        let verifier = MockWeatherVerifier::new(hurricane_sig);

        let mut proof = [0u8; 64];
        proof[..32].copy_from_slice(&hurricane_sig);

        let claim = mock_claim(1_000_000);
        let vm = Vm::new(2_000_000);

        let ctx = ExecCtx {
            proof: &proof,
            verifier: Some(&verifier),
        };

        vm.execute(OP_ASSERT_SOLVENCY, &claim, &ExecCtx::default())
            .expect("Ψ = 2.0 should satisfy Ψ ≥ 1.5");

        vm.execute(OP_EVAL_STARK, &claim, &ctx)
            .expect("valid sensor-signed proof must verify");

        vm.execute(OP_COMMIT_INDEMNITY, &claim, &ExecCtx::default())
            .expect("commitment must succeed once solvency + attestation pass");
    }

    #[test]
    fn commit_indemnity_blocked_while_under_challenge() {
        let mut vm = Vm::new(2_000_000);
        vm.is_under_challenge = true;
        let claim = mock_claim(1_000_000);
        assert_eq!(
            vm.execute(OP_COMMIT_INDEMNITY, &claim, &ExecCtx::default()),
            Err(VmError::ProtocolUnderChallenge)
        );
    }
}
