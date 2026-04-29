//! # cheating_trace — generate a fraudulent BitVM 2 execution trace.
//!
//! This example simulates a malicious Underwriter who *claims* a policy is
//! solvent when it is not. The honest [`actuarial_vm::Vm`] would refuse
//! ([`actuarial_vm::VmError::SolvencyException`]); instead we run a local
//! `CheatingSolver` whose `OP_ASSERT_SOLVENCY` always returns `true`,
//! capture the resulting [`BisectionTrace`], and write it to
//! `crates/actuarial-vm/fixtures/fraudulent_trace.json`.
//!
//! ## The math error
//!
//! For 𝓑 = 100, α_max = 1000:
//!
//! Ψ = 𝓑 / α_max = 0.1  ≪  1.5
//!
//! `OP_ASSERT_SOLVENCY` MUST fail closed. The fraudulent trace claims
//! `stack_after = ["true"]`. Anyone re-executing the predicate against the
//! committed L1 Taproot script
//!
//! ```text
//! 100 OP_10 OP_MUL  1000 OP_15 OP_MUL  OP_GREATERTHANOREQUAL OP_VERIFY
//! ```
//!
//! computes `1000 ≥ 15000` → `false` → `OP_VERIFY` aborts. The Watcher
//! generates the bisection path that proves the cheat.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p actuarial-vm --example cheating_trace
//! ```

use std::fs;
use std::path::PathBuf;

use actuarial_vm::taproot_builder::{encode_script_hex, generate_solvency_challenge_script};
use actuarial_vm::{BisectionTrace, OP_ASSERT_SOLVENCY};

/// Hard-coded "naked-risk" scenario: 100 sats backing a 1000 sat exposure.
const POOL_BALANCE_SATS: u64 = 100;
const ALPHA_MAX_SATS: u64 = 1_000;

/// Stand-in for a malicious Underwriter's solver. **DO NOT** copy this
/// pattern into the real VM — it deliberately violates I-6 (fail-closed).
fn cheating_assert_solvency(_balance: u64, _alpha_max: u64) -> bool {
    true
}

fn main() {
    // 1. Build the L1 predicate the Underwriter committed to.
    let l1_script = generate_solvency_challenge_script(POOL_BALANCE_SATS, ALPHA_MAX_SATS)
        .expect("script generation must succeed for u64 inputs");
    let l1_hex = encode_script_hex(&l1_script);

    // 2. Run the cheating solver and capture its claimed result.
    let claimed = cheating_assert_solvency(POOL_BALANCE_SATS, ALPHA_MAX_SATS);
    assert!(
        claimed,
        "cheating solver must return true for the fraud scenario"
    );

    // 3. Record the divergent step into the trace.
    let mut trace = BisectionTrace::new();
    trace.record_opcode(
        OP_ASSERT_SOLVENCY,
        vec![POOL_BALANCE_SATS.to_string(), ALPHA_MAX_SATS.to_string()],
        vec![claimed.to_string()],
        // Synthetic witness commitment — opaque digest of the claim tuple.
        "0xabc1230000000000000000000000000000000000000000000000000000000000".to_string(),
        l1_hex,
    );

    // 4. Export and persist.
    let json = trace.to_json();
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut out_path = PathBuf::from(manifest_dir);
    out_path.push("fixtures");
    fs::create_dir_all(&out_path).expect("create fixtures dir");
    out_path.push("fraudulent_trace.json");
    fs::write(&out_path, &json).expect("write fraudulent_trace.json");

    println!("wrote {}", out_path.display());
    println!("\n--- trace ---\n{}", json);
}
