//! BitVM 2 execution trace.
//!
//! [`BisectionTrace`] records the input state, opcode, and output state for
//! every step of an AVM execution. Watchers compare their honest re-execution
//! of the trace against an Underwriter's claimed trace; the first divergent
//! [`TraceStep`] becomes the bisection target on Bitcoin L1.
//!
//! The trace can be exported as JSON via [`BisectionTrace::to_json`] for
//! external auditing and fraud-proof construction. The serializer is hand-
//! rolled (no `serde` dependency) so the crate stays `no_std`-friendly.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::opcodes::mnemonic;

/// One step of an AVM execution trace — the unit of BitVM 2 bisection.
///
/// Each field is a `String` so the trace can serialize uniformly across
/// stack-element types (numbers, booleans, hex hashes) without leaking
/// the AVM's typed value enum into auditing infrastructure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceStep {
    /// Monotonic step index, starting at 0.
    pub step: u64,
    /// Mnemonic of the executed Actuarial Primitive Opcode (e.g.
    /// `"OP_ASSERT_SOLVENCY"`).
    pub opcode: String,
    /// Stringified stack contents *before* the opcode executed.
    pub stack_before: Vec<String>,
    /// Stringified stack contents *after* the opcode executed.
    pub stack_after: Vec<String>,
    /// Hex-encoded witness commitment for this step (e.g. claim digest).
    /// Empty string when no witness applies.
    pub witness_hash: String,
    /// Hex-encoded Bitcoin L1 predicate this step commits to. Empty when
    /// the step does not surface a Taproot leaf (e.g. pure stack ops).
    pub l1_predicate: String,
}

/// Ordered, append-only execution trace.
///
/// `record_step` is the only mutator; trace integrity is guaranteed by the
/// monotonic [`TraceStep::step`] index assigned at insertion time.
#[derive(Debug, Default, Clone)]
pub struct BisectionTrace {
    steps: Vec<TraceStep>,
}

impl BisectionTrace {
    /// Construct an empty trace.
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Append a step to the trace. The step's `step` index is overwritten
    /// with the next monotonic value to guarantee ordering invariants.
    pub fn record_step(&mut self, mut step: TraceStep) {
        step.step = self.steps.len() as u64;
        self.steps.push(step);
    }

    /// Borrow the recorded steps in order.
    pub fn steps(&self) -> &[TraceStep] {
        &self.steps
    }

    /// Number of recorded steps.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// `true` when no steps have been recorded.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Convenience constructor for a step that records the executed opcode
    /// by its raw byte; the mnemonic is resolved via [`crate::opcodes::mnemonic`].
    pub fn record_opcode(
        &mut self,
        opcode: u8,
        stack_before: Vec<String>,
        stack_after: Vec<String>,
        witness_hash: String,
        l1_predicate: String,
    ) {
        self.record_step(TraceStep {
            step: 0, // overwritten by record_step
            opcode: mnemonic(opcode).to_string(),
            stack_before,
            stack_after,
            witness_hash,
            l1_predicate,
        });
    }

    /// Export the trace as a JSON array.
    ///
    /// Output layout matches the BitVM 2 bisection format:
    ///
    /// ```json
    /// [
    ///   {
    ///     "step": 42,
    ///     "opcode": "OP_ASSERT_SOLVENCY",
    ///     "stack_before": ["100", "1000"],
    ///     "stack_after": ["true"],
    ///     "witness_hash": "0xabc123...",
    ///     "l1_predicate": "0380841e5a950340420f5f95a269"
    ///   }
    /// ]
    /// ```
    ///
    /// The serializer escapes only the JSON-mandated control characters
    /// (`"`, `\`, and `\n`/`\r`/`\t`); callers MUST keep stack-element
    /// strings in printable ASCII to remain audit-clean.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(64 + self.steps.len() * 128);
        out.push_str("[\n");
        let n = self.steps.len();
        for (i, s) in self.steps.iter().enumerate() {
            out.push_str("  {\n");
            out.push_str(&format!("    \"step\": {},\n", s.step));
            out.push_str(&format!(
                "    \"opcode\": \"{}\",\n",
                escape_json(&s.opcode)
            ));
            out.push_str("    \"stack_before\": ");
            out.push_str(&json_string_array(&s.stack_before));
            out.push_str(",\n");
            out.push_str("    \"stack_after\": ");
            out.push_str(&json_string_array(&s.stack_after));
            out.push_str(",\n");
            out.push_str(&format!(
                "    \"witness_hash\": \"{}\",\n",
                escape_json(&s.witness_hash)
            ));
            out.push_str(&format!(
                "    \"l1_predicate\": \"{}\"\n",
                escape_json(&s.l1_predicate)
            ));
            out.push_str("  }");
            if i + 1 < n {
                out.push(',');
            }
            out.push('\n');
        }
        out.push(']');
        out
    }
}

// ---------------------------------------------------------------------------
// Internal JSON helpers (no_std, no serde).
// ---------------------------------------------------------------------------

fn json_string_array(items: &[String]) -> String {
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('"');
        out.push_str(&escape_json(item));
        out.push('"');
    }
    out.push(']');
    out
}

/// Minimal JSON string escaper for the control characters mandated by RFC
/// 8259 §7. Bounded by `s.len()` — `O(n)` in input length only, never in
/// any consensus-path quantity.
fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::OP_ASSERT_SOLVENCY;
    use alloc::vec;

    #[test]
    fn empty_trace_serializes_to_empty_array() {
        let t = BisectionTrace::new();
        assert_eq!(t.to_json(), "[\n]");
    }

    #[test]
    fn step_indices_are_monotonic() {
        let mut t = BisectionTrace::new();
        t.record_opcode(
            OP_ASSERT_SOLVENCY,
            vec!["100".to_string(), "1000".to_string()],
            vec!["false".to_string()],
            "0x00".to_string(),
            "".to_string(),
        );
        t.record_opcode(
            OP_ASSERT_SOLVENCY,
            vec!["1500".to_string(), "1000".to_string()],
            vec!["true".to_string()],
            "0x01".to_string(),
            "".to_string(),
        );
        assert_eq!(t.steps()[0].step, 0);
        assert_eq!(t.steps()[1].step, 1);
    }

    #[test]
    fn json_contains_required_fields() {
        let mut t = BisectionTrace::new();
        t.record_opcode(
            OP_ASSERT_SOLVENCY,
            vec!["100".to_string(), "1000".to_string()],
            vec!["true".to_string()],
            "0xabc123".to_string(),
            "0380841e5a950340420f5f95a269".to_string(),
        );
        let json = t.to_json();
        assert!(json.contains("\"opcode\": \"OP_ASSERT_SOLVENCY\""));
        assert!(json.contains("\"stack_before\": [\"100\", \"1000\"]"));
        assert!(json.contains("\"stack_after\": [\"true\"]"));
        assert!(json.contains("\"witness_hash\": \"0xabc123\""));
        assert!(json.contains("\"l1_predicate\": \"0380841e5a950340420f5f95a269\""));
    }

    #[test]
    fn json_escapes_quotes_and_backslashes() {
        let mut t = BisectionTrace::new();
        t.record_opcode(
            OP_ASSERT_SOLVENCY,
            vec!["with \"quotes\"".to_string()],
            vec!["back\\slash".to_string()],
            "".to_string(),
            "".to_string(),
        );
        let json = t.to_json();
        assert!(json.contains("with \\\"quotes\\\""));
        assert!(json.contains("back\\\\slash"));
    }
}
