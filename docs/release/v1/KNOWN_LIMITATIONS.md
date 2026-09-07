# Antigravity Strict Engineering Kernel V1 - Known Limitations

1. **Operating System Optimization:**
   - The kernel is thoroughly validated on Windows 11 with PowerShell and Python 3.11+. While path normalization and git worktree operations are cross-platform, container sandboxing (Docker/Podman) is configured for non-blocking fallback when daemon is unavailable.
2. **Git Repository Prerequisite for Sandboxes:**
   - Full worktree isolation (`GIT_WORKTREE`) requires the workspace to be an initialized git repository. For non-git directories, the kernel automatically falls back to filesystem copy mode (`COPY_MODE`), which provides isolated directory build but requires file copying rather than git branching.
3. **Decision Coverage in Mixed Workflows:**
   - Direct-intent projects (zero decisions) and decision-driven projects are both supported. However, manually inserting requirements into `requirements.json` that lack trace to either an intent ID or decision ID will be flagged as orphaned by `decision_coverage.py`.
4. **Clean Virtualenv Creation Time:**
   - Full scratch virtualenv reconstruction (`venv` creation and dependency restoration) adds 5-15 seconds per clean test run depending on disk I/O.
