# Fraud proof for Challenge #1

This PR adds a deterministic BitVM 2 fraud-proof artifact for the published
`fixtures/fraudulent_trace.json` scenario and documents exactly why the
operator's claimed `stack_after = ["true"]` is invalid.

## Taproot script-path witness

For the published predicate `01645a9502e8035f95a269`, the script-path witness
stack that replays the operator's claimed inputs is:

- `0x64` (pool balance = 100)
- `0xe803` (max payout = 1000, minimally encoded little-endian)

As a minimal push-only witness vector:

```text
[0x64, 0xe803]
```

When these witness elements are placed on the initial Bitcoin Script stack and
executed against the committed predicate bytes, evaluation reaches
`OP_VERIFY (0x69)` with `false` on top of the stack, so the script aborts.

## Stack walk

Committed predicate bytes:

```text
01 64 5a 95 02 e8 03 5f 95 a2 69
```

Decoded:

```text
PUSH(100) OP_10 OP_MUL PUSH(1000) OP_15 OP_MUL OP_GREATERTHANOREQUAL OP_VERIFY
```

Execution:

1. `PUSH(100)` → stack: `[100]`
2. `OP_10` → stack: `[100, 10]`
3. `OP_MUL` → stack: `[1000]`
4. `PUSH(1000)` → stack: `[1000, 1000]`
5. `OP_15` → stack: `[1000, 1000, 15]`
6. `OP_MUL` → stack: `[1000, 15000]`
7. `OP_GREATERTHANOREQUAL` → evaluates `1000 >= 15000` = `false`
8. `OP_VERIFY` (`0x69`) aborts because the top stack item is `false`

The bisection terminates at this single step because the trace only contains
one disputed transition, and the committed L1 predicate for that transition is
self-contained and deterministic.
