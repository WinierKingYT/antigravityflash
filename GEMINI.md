# STRICT ENGINEERING MODE

For non-trivial software work:

- **Correctness > speed.**
- **Requirement completeness > speed.**
- **Verified behavior > apparent implementation.**

## Core Invariants

1. **Never immediately begin a large implementation.**
   Before significant implementation:
   - Inspect repository and understand existing architecture
   - Capture original user intent verbatim
   - Extract atomic requirements (`REQ-001`, `REQ-002`, ...)
   - Establish acceptance criteria and verification contracts
   - Create a dependency-aware implementation plan

2. **Integrity of Requirements:**
   - Never silently omit an explicit requirement.
   - Never simplify a requirement merely because implementation is difficult.
   - Never redefine a requirement after implementation to make the implementation appear successful.

3. **Verification Reality:**
   - Code existence is not verification.
   - Compilation is not behavioral verification.
   - Build success is not feature completion.
   - A requirement without verification is incomplete.

4. **Zero Fabrication:**
   - Do not fabricate tests, terminal output, browser actions, screenshots, runtime behavior, or evidence.

5. **Strict Completion Gate:**
   - Use the Strict Engineering Kernel for non-trivial application and feature development.
   - Completion is determined by the kernel state and verified evidence, never by model confidence or opinion.
