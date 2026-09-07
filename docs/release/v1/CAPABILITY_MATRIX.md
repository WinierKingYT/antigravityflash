# Antigravity Strict Engineering Kernel V1 - Capability Matrix

| Capability Area | Mechanism | Invariant Guaranteed |
|---|---|---|
| **Intent Processing** | `frame.py`, `requirement_generator.py` | 100% semantic requirement coverage; zero silent omission of user intents. |
| **Semantic Discovery** | `discovery_protocol.py`, `concern.py` | High-impact ambiguity discovery; heuristic seeds marked advisory; zero premature implementation. |
| **User Authority** | `decision_engine.py`, `interaction_policy.py` | User makes product & architectural choices; agent never silently substitutes technology. |
| **Acceptance Contracts** | `acceptance_protocol.py`, `test-oracle` | Given-When-Then behavioral contracts locked prior to code construction; token overlap verified. |
| **Worktree Sandboxing** | `sandbox.py` | Builder operates in isolated disposable worktrees; user dirty working tree preserved intact. |
| **Clean Environment** | `environment_factory.py` | Scratch environment reconstruction with frozen lockfiles; missing dependencies caught deterministically. |
| **Defect Detection** | `final-verifier`, `counterexample-auditor` | Clean-room verification probes regressions, edge cases, and authorization flaws. |
| **Self-Cert Prevention** | `gate.py`, `kernel.py` | Builder claims without independent execution evidence are downgraded to `IMPLEMENTED_UNVERIFIED`. |
| **Change Propagation** | `kernel.py`, `decision_engine.py` | Altered decisions or contract changes automatically invalidate derived requirements to `STALE`. |
| **Completion Gate** | `gate.py` | Cryptographic evidence hash chain, zero stale requirements, verified promotion, and clean-room audit. |
