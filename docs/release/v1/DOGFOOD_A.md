# Dogfood-A: Explicit Small CLI (`hashmanifest`)

**Domain:** Utility Command-Line Interface  
**Goal:** Build a deterministic directory checksum generator emitting sorted JSON manifests.  
**Raw Request Intent:**
> "Build a Python command-line utility named hashmanifest that computes SHA-256 and MD5 checksums for files in a target directory and emits a deterministic JSON manifest file with relative paths and hexadecimal digests sorted alphabetically by file path. The CLI must accept --dir <path> and --output <path> flags, exit with code 0 on success, exit with code 2 if the target directory does not exist, and accept an optional --algorithm flag supporting sha256 or md5."

---

## Verification Pipeline & Invariants Tested

1. **Zero-Decision Direct Intent Compilation:**
   - Because the user request was fully explicit, the kernel bypassed unnecessary interrogation dialogues.
   - 7 atomic requirements (`REQ-001` through `REQ-007`) were compiled directly from user intents.
   - Questions Asked: **0**.
2. **Acceptance Contract Locking:**
   - Test Oracle locked behavioral Given-When-Then criteria for each requirement with strict token overlap and schema compliance.
3. **Builder Worktree Sandbox:**
   - Code developed in isolated worktree `agent-sandbox-task_a_cli`.
   - Unit tests executed cleanly inside sandbox.
4. **Clean Environment Factory:**
   - Reconstructed scratch environment with zero host pollution.
   - Unit test suite passed in clean environment.
   - Runtime CLI smoke test executed: `hashmanifest.py --dir . --output out.json` exited with code 0 and produced valid manifest.
5. **Verified Promotion:**
   - Candidate changeset promoted to canonical repository.
   - Post-promotion diff equivalence and regression checks confirmed.
6. **Completion Gate:**
   - 100% test coverage, evidence hash chain validated, zero stale requirements, gate approved completion.
