# actuarial-vm

> **Domain-Specific VM for Bitcoin Settlement via BitVM 2.**

`actuarial-vm` is a `no_std`-compatible Rust library that exposes the
Solven Protocol's **Actuarial Virtual Machine (AVM)** as a reusable
crate. It gives BitVM 2 developers a small, statically-analyzable ISA
purpose-built for **insurance-grade contracts on Bitcoin**.

The AVM is a Total Functional Language: every program terminates, every
opcode runs in `O(1)`, and every payout is bounded *before* a single
satoshi is committed. Execution traces are bisectable on Bitcoin L1, so
a single honest Watcher is sufficient to slash a fraudulent operator.

---

## Why use this crate?

If you are building anything that pays out on Bitcoin contingent on a
real-world event — parametric insurance, prediction markets, structured
notes, sovereign reinsurance pools — you need three properties that
general-purpose VMs cannot give you:

1. **Provable solvency** before liability is taken on.
2. **Constant-time** opcode dispatch so on-chain bisection is cheap.
3. **Privacy** of the underlying policy terms.

`actuarial-vm` provides all three out of the box via the **Actuarial
Primitive Opcodes**.

## Actuarial Primitive Opcodes

| Byte | Mnemonic              | Cost (sats) | Purpose                                    |
|-----:|-----------------------|------------:|--------------------------------------------|
| 0x01 | `OP_ASSERT_SOLVENCY`  |        1000 | Enforce Ψ = 𝓑 / α_max ≥ 1.5 (fail-closed). |
| 0x02 | `OP_EVAL_STARK`       |        5000 | Verify a ZK-STARK trigger attestation.     |
| 0x03 | `OP_CALC_TAIL_METRIC` |         500 | (Reserved) tail-loss / VaR statistics.     |
| 0x04 | `OP_COMMIT_INDEMNITY` |        2000 | Commit indemnity; opens dispute window δ.  |

Every opcode is documented inline as an *Actuarial Primitive Opcode*
with its byte, Satoshi cost, and totality argument.

## Quick start

```toml
[dependencies]
actuarial-vm = "0.1"
```

```rust
use actuarial_vm::{ClaimPrimitive, ExecCtx, Vm, OP_ASSERT_SOLVENCY};

let claim = ClaimPrimitive {
    pi: [0u8; 32],
    tau: [0u8; 32],
    alpha_max_sats: 1_000_000,
    delta_blocks: 144,
};
let vm = Vm::new(2_000_000); // Ψ = 2.0
vm.execute(OP_ASSERT_SOLVENCY, &claim, &ExecCtx::default())
    .expect("Ψ = 2.0 satisfies Ψ ≥ 1.5");
```

## `no_std`

The crate is `no_std` by default-compatible — only `core` and `alloc`
are required. The `std` feature is on by default for ergonomics; turn
it off for embedded / Watcher firmware:

```toml
[dependencies]
actuarial-vm = { version = "0.1", default-features = false }
```

## BitVM 2 bisection

The [`BisectionTrace`](src/trace.rs) struct records every step of an
AVM execution — the input stack, the opcode, and the output stack —
plus a witness hash and the Bitcoin L1 Taproot predicate the step
commits to. Use [`BisectionTrace::to_json`] to export the trace for
external auditing or to construct a fraud proof:

```rust
let mut trace = BisectionTrace::new();
trace.record_opcode(
    OP_ASSERT_SOLVENCY,
    vec!["100".into(), "1000".into()],
    vec!["false".into()],
    "0xabc123".into(),
    "0380841e5a950340420f5f95a269".into(),
);
println!("{}", trace.to_json());
```

The Taproot script committing to the `OP_ASSERT_SOLVENCY` predicate is
emitted by [`taproot_builder::generate_solvency_challenge_script`] — the
same constants (`PSI_SCALE = 10`, `PSI_MIN_SCALED = 15`) that the
interpreter enforces at L2.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
