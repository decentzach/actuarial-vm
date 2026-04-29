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

//! # actuarial-vm
//!
//! **Domain-Specific VM for Bitcoin Settlement via BitVM 2.**
//!
//! `actuarial-vm` is a `no_std`-compatible Rust library that exposes the
//! Solven Protocol's **Actuarial Virtual Machine (AVM)** — a Total Functional
//! ISA whose opcodes ("Actuarial Primitive Opcodes") encode insurance-grade
//! semantics directly on Bitcoin via BitVM 2.
//!
//! Other BitVM developers can depend on this crate to build insurance-
//! specific logic — solvency assertions, ZK-STARK trigger verification,
//! indemnity commitments — that is statically analyzable and bisectable
//! on Bitcoin L1.
//!
//! ## Modules
//!
//! * [`opcodes`]         — the Actuarial Primitive Opcode table.
//! * [`vm`]              — `O(1)` interpreter and `ClaimPrimitive` types.
//! * [`taproot_builder`] — emits the AVM solvency predicate as raw Bitcoin
//!                         Script for embedding in a Taproot leaf.
//! * [`trace`]           — [`trace::BisectionTrace`] records per-step
//!                         execution data for BitVM 2 bisection / external
//!                         auditing.
//!
//! ## Invariants
//!
//! All consensus paths uphold the Solven invariants (see
//! `.github/copilot-instructions.md`): I-1 totality, I-2 `O(1)` dispatch,
//! I-3 deterministic integer math, I-4 no re-entry, I-5/I-6 fail-closed
//! solvency, I-10 ZK privacy.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod opcodes;
pub mod taproot_builder;
pub mod trace;
pub mod vm;

pub use opcodes::*;
pub use trace::{BisectionTrace, TraceStep};
pub use vm::{ClaimPrimitive, ExecCtx, MockWeatherVerifier, Verifier, Vm, VmError};

/// Backwards-compatible alias for [`Vm`]. Older code referred to the
/// interpreter as `VM`.
pub type VM = Vm;
