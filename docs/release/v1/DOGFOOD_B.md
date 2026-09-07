# Dogfood-B: Ambiguous Local App (`memokeeper`)

**Domain:** Local Terminal Application  
**Goal:** Build a local offline developer memo manager for capturing code snippets with tag search.  
**Raw Request Intent:**
> "Build a local developer memo manager named memokeeper for capturing quick code snippets and notes from the terminal with search by tag. It should work completely offline on a single machine."

---

## Verification Pipeline & Invariants Tested

1. **Semantic Discovery Protocol (Schema 7.2):**
   - 3 heuristic advisory seeds were discovered.
   - Stopping Engine blocked transition to specification (`RUN_SEMANTIC_DISCOVERY`) because advisory seeds are not canonical concerns.
2. **Anti-Technology Prescription Invariant:**
   - Candidate concern proposals were verified to describe product behavior rather than hardcoding implementation technology (e.g. structured relational indexing vs single-file store).
   - Ingested canonical concern `CONC-001` (`Memo Persistence and Tag Search Indexing Architecture`).
3. **Question Utility & User Authority:**
   - Evaluated 4 candidate questions: 3 trivial/low-value questions avoided, 1 high-utility architectural question presented to user.
   - User selected Option 1 (`Structured Relational Indexing with Atomic Transactions`).
   - Authority recorded as `USER`.
4. **Requirements & Acceptance Locking:**
   - Atomic requirement compiled with full trace to user decision.
   - Acceptance criteria locked by Test Oracle.
5. **Clean Verification & Promotion:**
   - Builder sandbox constructed SQLite-backed memo storage and test suite.
   - Clean environment test suite passed.
   - Post-promotion verification succeeded on canonical repository.
   - Completion gate approved completion.
