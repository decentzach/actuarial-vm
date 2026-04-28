use actuarial_vm::taproot_builder::{encode_script_hex, generate_solvency_challenge_script};
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
