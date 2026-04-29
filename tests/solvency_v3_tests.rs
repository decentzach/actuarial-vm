#[test]
fn test_valid_solvency() {
    let vm = VM::default();

    let valid_claim = ClaimPrimitive { b: 150, alpha_max: 100 };
    let valid_trace = BisectionTrace::mock(150, 100);

    assert!(vm.execute_assert_solvency_v3(&valid_claim, &valid_trace).is_ok());
}

#[test]
fn test_under_collateralized() {
    let vm = VM::default();

    let bad_claim = ClaimPrimitive { b: 100, alpha_max: 100 };
    let valid_trace = BisectionTrace::mock(100, 100);

    assert!(vm.execute_assert_solvency_v3(&bad_claim, &valid_trace).is_err());
}

#[test]
fn test_tampered_witness() {
    let vm = VM::default();

    let claim = ClaimPrimitive { b: 150, alpha_max: 100 };
    let tampered_trace = BisectionTrace::mock(200, 100); // breaks ratio

    assert!(vm.execute_assert_solvency_v3(&claim, &tampered_trace).is_err());
      }
