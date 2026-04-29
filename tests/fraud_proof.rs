use actuarial_vm::taproot_builder::{
    encode_script_hex, generate_solvency_challenge_script, generate_solvency_challenge_script_v2,
    generate_solvency_challenge_script_v3, ScalingWitness, SOLVENCY_PREDICATE_V2_HEX,
};
use actuarial_vm::{BisectionTrace, ClaimPrimitive, ExecCtx, Vm, VmError, OP_ASSERT_SOLVENCY};

fn mock_claim(alpha_max_sats: u64) -> ClaimPrimitive {
    ClaimPrimitive {
        pi: [0u8; 32],
        tau: [0u8; 32],
        alpha_max_sats,
        delta_blocks: 144,
    }
}

#[test]
fn fraudulent_trace_predicate_matches_fixture() {
    let script = generate_solvency_challenge_script(100, 1_000).unwrap();
    assert_eq!(encode_script_hex(&script), "01645a9502e8035f95a269");
}

#[test]
fn vm_rejects_the_fraudulent_trace_scenario() {
    let vm = Vm::new(100);
    let err = vm
        .execute(OP_ASSERT_SOLVENCY, &mock_claim(1_000), &ExecCtx::default())
        .unwrap_err();
    assert_eq!(err, VmError::SolvencyException);
}

#[test]
fn trace_records_fail_closed_stack_after_for_the_fraud_case() {
    let script = generate_solvency_challenge_script(100, 1_000).unwrap();
    let mut trace = BisectionTrace::new();
    trace.record_opcode(
        OP_ASSERT_SOLVENCY,
        vec!["100".to_string(), "1000".to_string()],
        vec!["false".to_string()],
        "0xabc1230000000000000000000000000000000000000000000000000000000000".to_string(),
        encode_script_hex(&script),
    );

    let json = trace.to_json();
    assert!(json.contains("\"stack_after\": [\"false\"]"));
    assert!(json.contains("\"l1_predicate\": \"01645a9502e8035f95a269\""));
}

#[test]
fn vbyte_crusher_v2_is_smaller_than_v1_for_fraud_case() {
    // Issue: [BOUNTY] vByte Crusher.
    // v2 must produce a strictly shorter on-chain script for B=100, α=1000.
    let v1 = generate_solvency_challenge_script(100, 1_000).unwrap();
    let v2 = generate_solvency_challenge_script_v2(100, 1_000).unwrap();
    assert!(v2.len() < v1.len(), "v2 must beat v1 vByte footprint");
    assert_eq!(encode_script_hex(&v2), SOLVENCY_PREDICATE_V2_HEX);
}

#[test]
fn vbyte_crusher_v2_witness_for_target_example() {
    // Issue example: B = 100,000  α = 150,000  →  reduced witness (2, 3, k=50_000).
    let w = ScalingWitness::from_raw(100_000, 150_000);
    assert_eq!((w.balance_scaled, w.alpha_max_scaled, w.gcd), (2, 3, 50_000));
}

#[test]
fn v3_is_smaller_than_v1_for_fraud_case() {
    let v1 = generate_solvency_challenge_script(100, 1_000).unwrap();
    let v3 = generate_solvency_challenge_script_v3(100, 1_000).unwrap();
    assert!(v3.len() < v1.len(), "v3 must beat v1 vByte footprint");
    assert_ne!(
        encode_script_hex(&v3),
        SOLVENCY_PREDICATE_V2_HEX,
        "v3 must differ from v2 (v3 inlines operands)"
    );
}

#[test]
fn v3_leaf_hash_binds_operands() {
    let s1 = generate_solvency_challenge_script_v3(1_500, 1_000).unwrap();
    let s2 = generate_solvency_challenge_script_v3(100, 1_000).unwrap();
    assert_ne!(s1, s2, "different inputs must produce different leaf scripts");
}

#[test]
fn v3_never_exceeds_v1_for_wide_range() {
    let cases = vec![
        (100, 1_000),
        (1_500, 1_000),
        (100_000, 150_000),
        (2_000_000, 1_000_000),
        (7, 11),
        (1, 1),
    ];
    for (b, a) in cases {
        let v1 = generate_solvency_challenge_script(b, a).unwrap();
        let v3 = generate_solvency_challenge_script_v3(b, a).unwrap();
        assert!(
            v3.len() <= v1.len(),
            "v3 must be ≤ v1 for (B={}, α={})",
            b,
            a
        );
    }
}
