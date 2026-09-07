# Dogfood-D: State & Recovery (`taskjournal`)

**Domain:** Storage Durability & Recovery Engine  
**Goal:** Build an append-only task state transition log with recovery replay.  
**Raw Request Intent:**
> "Build a local task ledger application named taskjournal that logs state transitions (CREATED, IN_PROGRESS, COMPLETED, CANCELLED) and allows recovering state from a journal log."

---

## Verification Pipeline & Invariants Tested

1. **Dirty Workspace Worktree Isolation:**
   - Before building, an unrelated uncommitted user file (`user_notes.txt`) was placed in the working tree.
   - Kernel classified workspace state as `DIRTY_NON_OVERLAPPING`.
   - Worktree sandbox isolated development; user file remained completely untouched and identical after promotion.
2. **Defect Injection 2 (State Truncation Flaw):**
   - Injected bug where log file was opened with mode `"w"` instead of `"a"`, losing prior history.
   - Recovery test executed multiple state transitions and detected state loss.
   - Candidate rejected until repaired with append-only mode.
3. **Decision Alteration & Stale Propagation:**
   - After initial verified completion, user altered the persistence decision via `supersede_decision` (`Append-Only Journal` -> `Direct Snapshot Overwrite`).
   - Kernel marked the previous decision `SUPERSEDED` and recorded cryptographic ledger event.
   - `requirement_generator.compile_requirements_from_decisions` automatically propagated change:
     - Old requirement `REQ-001` transitioned from `PASS` to `STALE` (reason: `Derives from superseded decision`).
     - New requirement `REQ-002` was compiled with an updated contract fingerprint.
   - Completion Gate immediately blocked completion while `REQ-001` was `STALE`.
