// Copyright 2026 The Solven Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Integration tests for the v3 witness-bound solvency check
//! (`Vm::execute_assert_solvency_v3`) introduced via Issue #4 / PR #9.

use actuarial_vm::{ClaimPrimitive, Vm, VmError};

fn claim_with(alpha_max_sats: u64) -> ClaimPrimitive {
    ClaimPrimitive {
        pi: [0u8; 32],
        tau: [0u8; 32],
        alpha_max_sats,
        delta_blocks: 144,
    }
}

#[test]
fn v3_accepts_at_threshold_with_proportional_witness() {
    // Ψ = 150/100 = 1.5  → predicate must accept.
    let vm = Vm::new(150);
    let claim = claim_with(100);
    assert_eq!(vm.execute_assert_solvency_v3(&claim, 150, 100), Ok(()));
}

#[test]
fn v3_accepts_at_threshold_with_reduced_witness() {
    // Same Ψ = 1.5, witness reduced by gcd(1500, 1000) = 500 → (3, 2).
    // Cross-check: 3 * 1000 == 2 * 1500.
    let vm = Vm::new(1_500);
    let claim = claim_with(1_000);
    assert_eq!(vm.execute_assert_solvency_v3(&claim, 3, 2), Ok(()));
}

#[test]
fn v3_rejects_under_capitalized_pool() {
    // Ψ = 100/100 = 1.0 < 1.5  → SolvencyException.
    let vm = Vm::new(100);
    let claim = claim_with(100);
    assert_eq!(
        vm.execute_assert_solvency_v3(&claim, 100, 100),
        Err(VmError::SolvencyException)
    );
}

#[test]
fn v3_rejects_tampered_witness() {
    // Pool = 150, α_max = 100, but witness claims ratio 2.0 ≠ 1.5.
    let vm = Vm::new(150);
    let claim = claim_with(100);
    assert_eq!(
        vm.execute_assert_solvency_v3(&claim, 200, 100),
        Err(VmError::AttestationRejected)
    );
}

#[test]
fn v3_rejects_zero_witness_components() {
    let vm = Vm::new(150);
    let claim = claim_with(100);
    assert_eq!(
        vm.execute_assert_solvency_v3(&claim, 0, 100),
        Err(VmError::AttestationRejected)
    );
    assert_eq!(
        vm.execute_assert_solvency_v3(&claim, 150, 0),
        Err(VmError::AttestationRejected)
    );
}

#[test]
fn v3_validate_witness_trace_is_pure() {
    let vm = Vm::new(150);
    assert!(vm.validate_witness_trace(100, 150, 3, 2));
    assert!(vm.validate_witness_trace(100, 150, 150, 100));
    assert!(!vm.validate_witness_trace(100, 150, 200, 100));
    assert!(!vm.validate_witness_trace(100, 150, 0, 0));
}
