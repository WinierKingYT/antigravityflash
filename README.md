# Antigravity Strict Engineering Kernel (V4.1 + Steps 2-5)

A deterministic, risk-adaptive, and adversarial reliability harness for Google Antigravity on Windows.

## 🛡️ Overview

The **Strict Engineering Kernel** prevents common AI coding assistant failure modes: premature coding, silent requirement omissions, false-positive test passes, host environment contamination, and unverified completions.

It operates through deep Antigravity lifecycle hooks (`PreInvocation`, `PreToolUse`, `Stop`) to enforce strict engineering invariants across every software development lifecycle step.

---

## 🚀 Architectural Layers

```mermaid
flowchart TD
    Req[User Request Intent] --> SpecLock[Spec Phase & Coverage Audit]
    SpecLock --> RiskEng[Risk Engine & Policy Compiler]
    RiskEng --> SandBox[Git Worktree Sandbox]
    
    subgraph AdvEngines [Adversarial Verification Suite]
        Prop[Property Testing]
        Fuzz[Boundary Fuzzing]
        Mut[Mutation Testing]
        Fault[Controlled Failure Injection]
    end
    
    SandBox --> AdvEngines
    
    subgraph CleanEnvFactory [Clean Environment & Reproducibility]
        FreshEnv[Scratch Environment Reconstruction]
        ZeroCache[Zero-Cache Frozen Restoration]
        DBVerify[DB Bootstrap & Migration Reversibility]
        Smoke[Runtime Startup & Smoke Journey]
        DoubleBuild[Run A vs Run B SHA-256 Double Build]
    end
    
    AdvEngines --> CleanEnvFactory
    CleanEnvFactory --> StopGate[Stop Completion Gate]
    StopGate --> Promotion[Verified Patch Promotion to Canonical]
```

### Core Invariants & Features:
- **Layer 1 (V4 Baseline):** Phase isolation (`SPECIFICATION` vs `IMPLEMENTATION`), 100% semantic requirement coverage, tamper-evident SHA-256 cryptographic evidence hash chain, and baseline regression detection.
- **Layer 2 (V4.1 Adversarial Hardening):** 7 protected critical harness artifacts, multi-replace tool interception, shell command write-vector inspection (`Set-Content`, `Out-File`, cmd `>`, Python `open().write()`, file ops), and single-writer state machines.
- **Layer 3 (Step 2 Git Worktree Sandbox):** Disposable git worktrees (`.git/worktrees/agent-sandbox-*`), isolated patch development, mergeability validation, and rollback safety.
- **Layer 4 (Step 3 Risk Engine & Policy Compiler):** 10-dimension requirement risk scoring (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), deterministic verification policy compilation, and dynamic risk escalation on defect discovery.
- **Layer 5 (Step 4 Test Quality & Adversarial Verification):** Property-based testing, boundary fuzz testing, semantic mutation testing (operator/boundary/statement mutation), controlled fault injection, and zero surviving mutants on high/critical paths.
- **Layer 6 (Step 5 Clean Environment & Reproducible Build Factory):** Non-blocking container probing, zero-cache scratch source reconstruction (excluding `node_modules`, `venv`, `dist`, `.env`), frozen lockfile enforcement, database migration rollback verification, runtime smoke tests, and double-build bit-for-bit SHA-256 reproducibility verification.

---

## 📂 Project Structure

```text
antigravity-strict-engineering-kernel/
├── src/strict_engineering/             # Core Kernel Python Modules
│   ├── __init__.py
│   ├── kernel.py                      # State machine & SHA-256 evidence chain
│   ├── gate.py                        # Stop gate & PreToolUse security matrix
│   ├── fingerprint.py                 # Deterministic SHA-256 workspace hashing
│   ├── baseline.py                    # Workspace health baseline & regression delta
│   ├── hooks_handler.py               # Antigravity CLI hook dispatcher
│   ├── sandbox.py                     # Git worktree sandbox manager
│   ├── risk_engine.py                 # Multi-factor requirement risk scoring
│   ├── verification_policy.py         # Dynamic policy compiler
│   ├── adversarial_verification.py    # Property, fuzz, mutation & fault injection
│   ├── environment_detector.py        # Container, ecosystem & lockfile inspector
│   ├── environment_factory.py         # Clean scratch environment factory
│   ├── reproducibility.py             # Double-build SHA-256 artifact comparator
│   └── reporting.py                   # Multi-schema canonical report generator
├── tests/                             # Comprehensive Test Suites (147 Tests)
│   ├── test_suite.py                  # V4 Baseline (12 tests)
│   ├── test_v41_adversarial.py        # V4.1 Adversarial validation (15 tests)
│   ├── test_step2_sandbox.py          # Step 2 Worktrees & Promotion (19 tests)
│   ├── test_step3_risk_policy.py      # Step 3 Risk & Policy (29 tests)
│   ├── test_step4_adversarial.py      # Step 4 Adversarial Verification (36 tests)
│   └── test_step5_clean_env.py        # Step 5 Clean Env & Repro (36 tests)
├── scripts/
│   ├── install.ps1                    # One-click installation into Antigravity
│   └── run_all_tests.py               # Complete test suite runner
├── GEMINI.md                          # Antigravity strict engineering system prompt
├── hooks.json                         # Antigravity lifecycle hooks configuration
├── pyproject.toml                     # Modern Python project configuration
└── README.md
```

---

## ⚡ Installation

### Option 1: Quick Install via PowerShell

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

This will:
1. Copy the strict engineering modules into `~/.gemini/config/strict-engineering/`.
2. Configure `~/.gemini/config/hooks.json` to attach the hooks.
3. Update `~/.gemini/GEMINI.md` with the strict engineering prompt rules.
4. Execute the verification suite to ensure 100% test pass rate.

---

## 🧪 Running Tests

To run the full 147-test suite:

```bash
python run_tests.py
```

Or using unittest discover:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 📊 Verification Metrics

- **Total Test Cases:** 147
- **Pass Rate:** 100% (147 / 147 PASS)
- **Zero External Dependencies:** Built with pure Python standard library for maximum reliability across diverse development environments.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
