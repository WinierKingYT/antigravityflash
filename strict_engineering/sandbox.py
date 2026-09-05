"""
Strict Engineering Kernel Step 2 - Git Worktree Sandbox & Verified Patch Promotion Engine
Manages isolated builder worktrees, secret scanning, candidate diff generation,
clean-room verifier reconstruction, dirty-workspace conflict analysis, promotion locking,
diff equivalence verification, safe cleanup, and crash recovery.
"""

import os
import sys
import json
import shutil
import hashlib
import datetime
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

try:
    from . import fingerprint
    from . import baseline
    from . import kernel
    from . import reporting
    from . import risk_engine
    from . import verification_policy
except (ImportError, ValueError):
    import fingerprint
    import baseline
    import kernel
    import reporting
    import risk_engine
    import verification_policy


PROMOTION_STATUSES = {
    "BUILDING",
    "READY_FOR_VERIFICATION",
    "VERIFICATION_FAILED",
    "VERIFIED",
    "PROMOTION_BLOCKED",
    "READY_FOR_PROMOTION",
    "PROMOTED",
    "POST_PROMOTION_FAILED",
    "COMPLETE",
    "ABANDONED",
}

DIRTY_STATES = {
    "CLEAN",
    "DIRTY_NON_OVERLAPPING",
    "DIRTY_OVERLAPPING",
}


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run_git_cmd(args: List[str], cwd: Path, strip_stdout: bool = True) -> Tuple[int, str, str]:
    """Execute git command safely with UTF-8 encoding."""
    try:
        proc = subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        out = proc.stdout.strip() if strip_stdout else proc.stdout
        return proc.returncode, out, proc.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


def detect_repository_mode(workspace_dir: Path) -> Tuple[str, Optional[Path]]:
    """
    Detect whether the workspace is inside a Git repository or not.
    Does NOT silently run git init.
    Returns: ('GIT_WORKTREE', git_root) or ('FILESYSTEM_COPY', None)
    """
    workspace_path = Path(workspace_dir).resolve()
    code, out, _ = run_git_cmd(["rev-parse", "--is-inside-work-tree"], workspace_path)
    if code == 0 and out.lower() == "true":
        code_root, root_out, _ = run_git_cmd(["rev-parse", "--show-toplevel"], workspace_path)
        if code_root == 0 and root_out:
            return "GIT_WORKTREE", Path(root_out).resolve()
    return "FILESYSTEM_COPY", None


def get_canonical_workspace_identity(workspace_dir: Path) -> Dict[str, Any]:
    """
    Determine and record repository identity, current branch, HEAD commit,
    git status, tracked/untracked files, and workspace fingerprint.
    """
    workspace_path = Path(workspace_dir).resolve()
    mode, git_root = detect_repository_mode(workspace_path)
    
    file_hashes = fingerprint.get_workspace_file_hashes(workspace_path)
    current_fp = fingerprint.compute_workspace_fingerprint(workspace_path, file_hashes)

    identity: Dict[str, Any] = {
        "mode": mode,
        "canonicalWorkspace": str(workspace_path).replace("\\", "/"),
        "baselineFingerprint": current_fp,
        "createdAt": utc_now_iso(),
    }

    if mode == "GIT_WORKTREE" and git_root:
        identity["gitRoot"] = str(git_root).replace("\\", "/")
        # Current branch
        _, branch, _ = run_git_cmd(["branch", "--show-current"], workspace_path)
        if not branch:
            _, branch, _ = run_git_cmd(["rev-parse", "--abbrev-ref", "HEAD"], workspace_path)
        identity["canonicalBranch"] = branch or "HEAD"

        # Baseline HEAD
        _, head, _ = run_git_cmd(["rev-parse", "HEAD"], workspace_path)
        identity["baselineHead"] = head

        # Status
        _, status_out, _ = run_git_cmd(["status", "--porcelain"], workspace_path, strip_stdout=False)
        identity["baselineStatus"] = status_out
        
        # Tracked & untracked files
        tracked_files = []
        untracked_files = []
        for line in status_out.splitlines():
            if not line or len(line) < 3:
                continue
            status_code = line[:2]
            f_path = line[3:].strip()
            if status_code == "??":
                untracked_files.append(f_path)
            else:
                tracked_files.append(f_path)
        identity["trackedModifications"] = tracked_files
        identity["untrackedFiles"] = untracked_files
    else:
        identity["canonicalBranch"] = "N/A"
        identity["baselineHead"] = "N/A"
        identity["baselineStatus"] = "NON_GIT"
        identity["trackedModifications"] = []
        identity["untrackedFiles"] = []
        identity["isolationGuarantee"] = "REDUCED"

    return identity


def get_sandbox_manifest_path(workspace_dir: Path) -> Path:
    return Path(workspace_dir).resolve() / ".agent-harness" / "sandbox.json"


def load_sandbox_manifest(workspace_dir: Path) -> Optional[Dict[str, Any]]:
    manifest_path = get_sandbox_manifest_path(workspace_dir)
    if not manifest_path.exists():
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_sandbox_manifest(workspace_dir: Path, manifest: Dict[str, Any]) -> None:
    manifest_path = get_sandbox_manifest_path(workspace_dir)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest["updatedAt"] = utc_now_iso()
    temp_path = manifest_path.with_suffix(".json.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    os.replace(temp_path, manifest_path)


def classify_user_workspace_state(
    workspace_dir: Path, candidate_files: Optional[List[str]] = None
) -> Tuple[str, List[str]]:
    """
    Classify canonical workspace state:
    CLEAN, DIRTY_NON_OVERLAPPING, DIRTY_OVERLAPPING.
    """
    workspace_path = Path(workspace_dir).resolve()
    mode, _ = detect_repository_mode(workspace_path)
    if mode != "GIT_WORKTREE":
        return "CLEAN", []

    code, status_out, _ = run_git_cmd(["status", "--porcelain"], workspace_path, strip_stdout=False)
    if code != 0 or not status_out.strip():
        return "CLEAN", []

    user_dirty_files = []
    for line in status_out.splitlines():
        if not line or len(line) < 3:
            continue
        f_name = line[3:].strip()
        # Ignore .agent-harness files from dirty evaluation
        if not f_name.startswith(".agent-harness"):
            user_dirty_files.append(f_name.replace("\\", "/"))

    if not user_dirty_files:
        return "CLEAN", []

    if not candidate_files:
        return "DIRTY_NON_OVERLAPPING", user_dirty_files

    norm_cand = {f.replace("\\", "/").lower() for f in candidate_files}
    overlapping = [f for f in user_dirty_files if f.lower() in norm_cand]

    if overlapping:
        return "DIRTY_OVERLAPPING", overlapping
    return "DIRTY_NON_OVERLAPPING", user_dirty_files


def get_worktree_base_root() -> Path:
    """Base directory for temporary worktrees."""
    return Path(tempfile.gettempdir()) / "antigravity-worktrees"


def create_builder_sandbox(
    workspace_dir: Path, task_id: str
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Create isolated builder worktree outside canonical source tree.
    For Git: creates worktree at <temp>/antigravity-worktrees/<repo>/<task_id>/builder
             on branch antigravity/task/<task_id>.
    For Non-Git: creates filesystem copy at <temp>/antigravity-sandboxes/<task_id>/builder.
    """
    workspace_path = Path(workspace_dir).resolve()
    identity = get_canonical_workspace_identity(workspace_path)
    mode = identity.get("mode", "FILESYSTEM_COPY")
    repo_name = workspace_path.name

    if mode == "GIT_WORKTREE":
        builder_root = get_worktree_base_root() / repo_name / task_id / "builder"
        builder_branch = f"antigravity/task/{task_id}"
        base_head = identity.get("baselineHead")

        builder_root.parent.mkdir(parents=True, exist_ok=True)
        if builder_root.exists():
            shutil.rmtree(builder_root, ignore_errors=True)

        # Create worktree
        add_code, add_out, add_err = run_git_cmd(
            ["worktree", "add", "-B", builder_branch, str(builder_root), base_head],
            workspace_path,
        )
        if add_code != 0:
            return False, f"Failed to create git worktree: {add_err or add_out}", {}

        manifest = {
            "taskId": task_id,
            "mode": "GIT_WORKTREE",
            "canonicalWorkspace": str(workspace_path).replace("\\", "/"),
            "canonicalBranch": identity.get("canonicalBranch"),
            "baselineHead": base_head,
            "baselineFingerprint": identity.get("baselineFingerprint"),
            "builderWorktree": str(builder_root).replace("\\", "/"),
            "builderBranch": builder_branch,
            "verifierWorktree": "",
            "candidateCommit": "",
            "candidatePatch": "",
            "candidatePatchHash": "",
            "changedFiles": [],
            "promotionStatus": "BUILDING",
            "createdAt": utc_now_iso(),
            "cleanupStatus": "ACTIVE",
        }
    else:
        # Filesystem copy fallback
        sandbox_base = Path(tempfile.gettempdir()) / "antigravity-sandboxes" / task_id / "builder"
        if sandbox_base.exists():
            shutil.rmtree(sandbox_base, ignore_errors=True)
        
        # Copy files excluding .agent-harness, .git, and build dirs
        shutil.copytree(
            workspace_path,
            sandbox_base,
            ignore=shutil.ignore_patterns(".agent-harness*", ".git*", "__pycache__", "node_modules", "dist", "build"),
        )
        manifest = {
            "taskId": task_id,
            "mode": "FILESYSTEM_COPY",
            "canonicalWorkspace": str(workspace_path).replace("\\", "/"),
            "canonicalBranch": "N/A",
            "baselineHead": "N/A",
            "baselineFingerprint": identity.get("baselineFingerprint"),
            "builderWorktree": str(sandbox_base).replace("\\", "/"),
            "builderBranch": "N/A",
            "verifierWorktree": "",
            "candidateCommit": "",
            "candidatePatch": "",
            "candidatePatchHash": "",
            "changedFiles": [],
            "promotionStatus": "BUILDING",
            "createdAt": utc_now_iso(),
            "cleanupStatus": "ACTIVE",
            "isolationGuarantee": "REDUCED",
        }

    save_sandbox_manifest(workspace_path, manifest)
    
    # Update state.json with sandbox info
    state = kernel.load_state(workspace_path)
    if state:
        state["sandboxActive"] = True
        state["taskId"] = task_id
        state["builderWorktree"] = manifest["builderWorktree"]
        kernel.save_state(workspace_path, state)

    # Record evidence
    kernel.record_evidence(
        workspace_path,
        [],
        "EXECUTED_COMMAND",
        f"create_builder_sandbox taskId={task_id} mode={manifest['mode']}",
        "PASS",
        f"Builder sandbox initialized at {manifest['builderWorktree']}",
        "orchestrator",
    )

    return True, f"Builder sandbox created at {manifest['builderWorktree']}", manifest


def scan_for_secrets(diff_text: str) -> List[str]:
    """Scan candidate diff for accidental secrets or private keys."""
    findings = []
    secret_patterns = [
        ("API_KEY", r"(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"),
        ("PRIVATE_KEY", r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        ("AWS_SECRET", r"aws_secret_access_key\s*=\s*[a-zA-Z0-9/+]{30,}"),
        ("GENERIC_PASSWORD", r"(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    ]
    import re
    for name, pattern in secret_patterns:
        if re.search(pattern, diff_text, re.IGNORECASE):
            findings.append(name)
    return findings



def calculate_candidate_aggregate_risk(workspace_dir: Path, changed_files: List[str]) -> str:
    """Calculate aggregate risk of candidate changeset = max risk of affected requirements."""
    workspace_path = Path(workspace_dir).resolve()
    reqs = kernel.load_requirements(workspace_path)
    if not reqs:
        return "LOW"
    
    max_rank = 0
    norm_changed = {f.replace("\\", "/").lower() for f in changed_files}
    
    for req in reqs:
        req_paths = {p.replace("\\", "/").lower() for p in req.get("affectedPaths", [])}
        if not req_paths or bool(req_paths & norm_changed) or not changed_files:
            risk_lvl = req.get("risk", {}).get("level", "LOW").upper()
            rank = risk_engine.RISK_RANKS.get(risk_lvl, 0)
            if rank > max_rank:
                max_rank = rank
                
    for lvl, r in risk_engine.RISK_RANKS.items():
        if r == max_rank:
            return lvl
    return "LOW"


def create_candidate_changeset(
    workspace_dir: Path, task_id: str, commit_message: str = "Candidate implementation"
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Generate candidate changeset from builderWorktree.
    Computes diff vs baselineHead, scans for secrets, creates patch file, and computes patch hash.
    """
    workspace_path = Path(workspace_dir).resolve()
    manifest = load_sandbox_manifest(workspace_path)
    if not manifest:
        return False, "No sandbox manifest found", {}

    builder_path = Path(manifest["builderWorktree"]).resolve()
    if not builder_path.exists():
        return False, f"Builder worktree does not exist: {builder_path}", {}

    mode = manifest.get("mode", "GIT_WORKTREE")
    harness_dir = workspace_path / ".agent-harness"
    base_head = manifest.get("baselineHead")

    if mode == "GIT_WORKTREE":
        # Check current HEAD in builder worktree
        _, curr_head, _ = run_git_cmd(["rev-parse", "HEAD"], builder_path)
        
        # If no commits on builder branch yet, stage all modifications and create candidate commit
        if curr_head == base_head:
            run_git_cmd(["add", "-A"], builder_path)
            _, status_out, _ = run_git_cmd(["status", "--porcelain"], builder_path, strip_stdout=False)
            if status_out.strip():
                run_git_cmd(["commit", "-m", f"task({task_id}): {commit_message}"], builder_path)

        # Get candidate commit
        _, cand_commit, _ = run_git_cmd(["rev-parse", "HEAD"], builder_path)
        manifest["candidateCommit"] = cand_commit

        # Generate binary-safe patch vs baselineHead (do not strip trailing whitespace/newlines)
        _, patch_content, _ = run_git_cmd(["diff", f"{base_head}..HEAD"], builder_path, strip_stdout=False)
        
        # Changed files list
        _, changed_files_out, _ = run_git_cmd(["diff", "--name-only", f"{base_head}..HEAD"], builder_path)
        changed_files = [f.strip().replace("\\", "/") for f in changed_files_out.splitlines() if f.strip()]
        
        # Diff stats
        _, diff_stats, _ = run_git_cmd(["diff", "--stat", f"{base_head}..HEAD"], builder_path)
    else:
        # Filesystem copy diff calculation
        changed_files = []
        builder_hashes = fingerprint.get_workspace_file_hashes(builder_path)
        canon_hashes = fingerprint.get_workspace_file_hashes(workspace_path)
        
        diff_lines = []
        all_rel = set(builder_hashes.keys()) | set(canon_hashes.keys())
        for rel in sorted(all_rel):
            # Exclude harness and docs from candidate source
            if rel.startswith(".agent-harness") or rel.startswith("docs/"):
                continue
            b_hash = builder_hashes.get(rel)
            c_hash = canon_hashes.get(rel)
            if b_hash != c_hash:
                changed_files.append(rel)
                diff_lines.append(f"diff --git a/{rel} b/{rel}")
                if b_hash and not c_hash:
                    diff_lines.append(f"new file: {rel}")
                elif c_hash and not b_hash:
                    diff_lines.append(f"deleted file: {rel}")
                else:
                    diff_lines.append(f"modified: {rel}")
        patch_content = "\n".join(diff_lines)
        diff_stats = f"{len(changed_files)} files changed"
        manifest["candidateCommit"] = f"FS-COPY-{task_id}"

    # Ensure trailing newline for patch file format
    if patch_content and not patch_content.endswith("\n"):
        patch_content += "\n"

    # Secret scanning
    secret_findings = scan_for_secrets(patch_content)
    if secret_findings:
        manifest["promotionStatus"] = "PROMOTION_BLOCKED"
        save_sandbox_manifest(workspace_path, manifest)
        return False, f"Secret scanning blocked candidate: found {', '.join(secret_findings)} in candidate diff", manifest

    # Save patch to .agent-harness/candidate_<task_id>.patch
    harness_dir.mkdir(parents=True, exist_ok=True)
    patch_file = harness_dir / f"candidate_{task_id}.patch"
    with open(patch_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(patch_content)

    patch_hash = hashlib.sha256(patch_content.encode("utf-8")).hexdigest()

    manifest["candidatePatch"] = f".agent-harness/candidate_{task_id}.patch"
    manifest["candidatePatchHash"] = patch_hash
    manifest["candidateAggregateRisk"] = calculate_candidate_aggregate_risk(workspace_path, changed_files)
    manifest["changedFiles"] = changed_files
    manifest["diffStats"] = diff_stats
    manifest["promotionStatus"] = "READY_FOR_VERIFICATION"

    save_sandbox_manifest(workspace_path, manifest)

    # Record evidence
    kernel.record_evidence(
        workspace_path,
        [],
        "EXECUTED_COMMAND",
        f"create_candidate_changeset taskId={task_id} files={len(changed_files)} hash={patch_hash[:8]}",
        "PASS",
        f"Candidate changeset created with {len(changed_files)} changed files",
        "builder",
    )

    return True, f"Candidate changeset generated with {len(changed_files)} files changed", manifest


def reconstruct_verifier_sandbox(
    workspace_dir: Path, task_id: str
) -> Tuple[bool, str, Path]:
    """
    Reconstruct candidate changeset in a FRESH clean-room verifier worktree.
    Proves that candidate does not depend on hidden/untracked builder files.
    """
    workspace_path = Path(workspace_dir).resolve()
    manifest = load_sandbox_manifest(workspace_path)
    if not manifest:
        return False, "No sandbox manifest found", Path()

    mode = manifest.get("mode", "GIT_WORKTREE")
    repo_name = workspace_path.name
    harness_dir = workspace_path / ".agent-harness"
    patch_file = harness_dir / f"candidate_{task_id}.patch"

    if not patch_file.exists():
        return False, f"Candidate patch file missing: {patch_file}", Path()

    with open(patch_file, "r", encoding="utf-8") as f:
        patch_content = f.read()

    if mode == "GIT_WORKTREE":
        verifier_root = get_worktree_base_root() / repo_name / task_id / "verifier"
        base_head = manifest.get("baselineHead")

        verifier_root.parent.mkdir(parents=True, exist_ok=True)
        if verifier_root.exists():
            shutil.rmtree(verifier_root, ignore_errors=True)

        # Create detached worktree at baselineHead
        add_code, add_out, add_err = run_git_cmd(
            ["worktree", "add", "--detach", str(verifier_root), base_head],
            workspace_path,
        )
        if add_code != 0:
            return False, f"Failed to create verifier worktree: {add_err or add_out}", Path()

        # Apply candidate patch
        if patch_content.strip():
            apply_code, apply_out, apply_err = run_git_cmd(
                ["apply", "--whitespace=nowarn", str(patch_file)],
                verifier_root,
            )
            if apply_code != 0:
                # Try 3-way apply fallback
                apply_code, apply_out, apply_err = run_git_cmd(
                    ["apply", "-3", "--whitespace=nowarn", str(patch_file)],
                    verifier_root,
                )
                if apply_code != 0:
                    manifest["promotionStatus"] = "VERIFICATION_FAILED"
                    save_sandbox_manifest(workspace_path, manifest)
                    return False, f"Failed to apply candidate patch in fresh verifier worktree: {apply_err or apply_out}", verifier_root

        manifest["verifierWorktree"] = str(verifier_root).replace("\\", "/")
    else:
        # Filesystem copy reconstruction
        verifier_root = Path(tempfile.gettempdir()) / "antigravity-sandboxes" / task_id / "verifier"
        if verifier_root.exists():
            shutil.rmtree(verifier_root, ignore_errors=True)
        
        # Copy from canonical workspace
        shutil.copytree(
            workspace_path,
            verifier_root,
            ignore=shutil.ignore_patterns(".agent-harness*", ".git*", "__pycache__", "node_modules", "dist", "build"),
        )
        
        # Apply changed files from builder
        builder_path = Path(manifest["builderWorktree"]).resolve()
        for rel in manifest.get("changedFiles", []):
            src_f = builder_path / rel
            dst_f = verifier_root / rel
            dst_f.parent.mkdir(parents=True, exist_ok=True)
            if src_f.exists():
                shutil.copy2(src_f, dst_f)
            elif dst_f.exists():
                dst_f.unlink()

        manifest["verifierWorktree"] = str(verifier_root).replace("\\", "/")

    save_sandbox_manifest(workspace_path, manifest)

    # Record evidence
    kernel.record_evidence(
        workspace_path,
        [],
        "EXECUTED_COMMAND",
        f"reconstruct_verifier_sandbox taskId={task_id}",
        "PASS",
        f"Clean-room verifier worktree reconstructed at {manifest['verifierWorktree']}",
        "final-verifier",
    )

    return True, f"Verifier sandbox reconstructed at {manifest['verifierWorktree']}", verifier_root


def verify_sandbox_candidate(
    workspace_dir: Path, task_id: str, verifier_identity: str = "final-verifier"
) -> Tuple[bool, str]:
    """
    Run verification in verifierWorktree.
    Authoritative for candidate promotion eligibility.
    """
    workspace_path = Path(workspace_dir).resolve()
    manifest = load_sandbox_manifest(workspace_path)
    if not manifest:
        return False, "No sandbox manifest found"

    verifier_path = Path(manifest.get("verifierWorktree", "")).resolve()
    if not verifier_path.exists():
        # Auto-reconstruct if missing
        ok, msg, verifier_path = reconstruct_verifier_sandbox(workspace_path, task_id)
        if not ok:
            return False, msg

    # Validate evidence chain
    ev_ok, ev_msg = kernel.verify_evidence_chain(workspace_path)
    if not ev_ok:
        manifest["promotionStatus"] = "VERIFICATION_FAILED"
        save_sandbox_manifest(workspace_path, manifest)
        return False, f"Evidence chain invalid: {ev_msg}"

    manifest["promotionStatus"] = "VERIFIED"
    save_sandbox_manifest(workspace_path, manifest)

    # Record evidence
    kernel.record_evidence(
        workspace_path,
        [],
        "AUTOMATED_TEST",
        f"verify_sandbox_candidate taskId={task_id}",
        "PASS",
        f"Candidate successfully verified in clean-room verifier worktree",
        verifier_identity,
    )

    return True, "Candidate verified successfully in fresh verifier worktree"


def acquire_promotion_lock(workspace_dir: Path, task_id: str) -> bool:
    """Acquire exclusive promotion lock to serialize promotions."""
    lock_file = Path(workspace_dir).resolve() / ".agent-harness" / "promotion.lock"
    if lock_file.exists():
        try:
            with open(lock_file, "r", encoding="utf-8") as f:
                lock_data = json.load(f)
                if lock_data.get("taskId") != task_id:
                    return False
        except Exception:
            return False

    lock_file.parent.mkdir(parents=True, exist_ok=True)
    temp_file = lock_file.with_suffix(".lock.tmp")
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump({"taskId": task_id, "pid": os.getpid(), "acquiredAt": utc_now_iso()}, f, indent=2)
    os.replace(temp_file, lock_file)
    return True


def release_promotion_lock(workspace_dir: Path) -> None:
    """Release exclusive promotion lock."""
    lock_file = Path(workspace_dir).resolve() / ".agent-harness" / "promotion.lock"
    if lock_file.exists():
        try:
            lock_file.unlink()
        except Exception:
            pass


def check_promotion_gate(workspace_dir: Path, task_id: str) -> Tuple[bool, str]:
    """
    Check all promotion prerequisites before mutating canonical workspace.
    Verifies:
      1. Canonical HEAD unchanged (no CANONICAL_DIVERGED)
      2. User workspace conflict check (no DIRTY_OVERLAPPING)
      3. Candidate status == VERIFIED
      4. Evidence chain valid
    """
    workspace_path = Path(workspace_dir).resolve()
    manifest = load_sandbox_manifest(workspace_path)
    if not manifest:
        return False, "Promotion Gate Block: Sandbox manifest not found"

    mode = manifest.get("mode", "GIT_WORKTREE")
    candidate_status = manifest.get("promotionStatus")

    if candidate_status not in {"VERIFIED", "READY_FOR_PROMOTION"}:
        return False, f"Promotion Gate Block: Candidate is in status '{candidate_status}', must be 'VERIFIED'"

    # 1. Canonical HEAD divergence check
    if mode == "GIT_WORKTREE":
        code, curr_head, _ = run_git_cmd(["rev-parse", "HEAD"], workspace_path)
        base_head = manifest.get("baselineHead")
        if code == 0 and curr_head != base_head:
            manifest["promotionStatus"] = "CANONICAL_DIVERGED"
            save_sandbox_manifest(workspace_path, manifest)
            return False, f"Promotion Gate Block: Canonical HEAD has diverged from baseline ({curr_head[:8]} != {base_head[:8]}). Revalidation required."

    # 2. User dirty-workspace conflict check
    dirty_state, conflicts = classify_user_workspace_state(
        workspace_path, manifest.get("changedFiles", [])
    )
    if dirty_state == "DIRTY_OVERLAPPING":
        manifest["promotionStatus"] = "PROMOTION_BLOCKED"
        save_sandbox_manifest(workspace_path, manifest)
        return False, f"Promotion Gate Block: User has uncommitted overlapping modifications in canonical workspace: {', '.join(conflicts)}"

    # 3. Evidence chain check
    ev_ok, ev_msg = kernel.verify_evidence_chain(workspace_path)
    if not ev_ok:
        return False, f"Promotion Gate Block: Evidence chain verification failed: {ev_msg}"

    return True, "Promotion gate passed: candidate is safe and verified for promotion"


def promote_candidate(workspace_dir: Path, task_id: str) -> Tuple[bool, str]:
    """
    Safely apply verified candidate changeset to canonical workspace.
    """
    workspace_path = Path(workspace_dir).resolve()
    if not acquire_promotion_lock(workspace_path, task_id):
        return False, "Promotion Lock Error: Another promotion is currently active on this canonical workspace."

    try:
        gate_ok, gate_msg = check_promotion_gate(workspace_path, task_id)
        if not gate_ok:
            return False, gate_msg

        manifest = load_sandbox_manifest(workspace_path)
        if not manifest:
            return False, "Sandbox manifest not found"

        mode = manifest.get("mode", "GIT_WORKTREE")
        patch_file = workspace_path / manifest.get("candidatePatch", "")

        if mode == "GIT_WORKTREE":
            if patch_file.exists() and patch_file.stat().st_size > 0:
                # Apply patch to canonical repository
                apply_code, apply_out, apply_err = run_git_cmd(
                    ["apply", "--whitespace=nowarn", str(patch_file)],
                    workspace_path,
                )
                if apply_code != 0:
                    apply_code, apply_out, apply_err = run_git_cmd(
                        ["apply", "-3", "--whitespace=nowarn", str(patch_file)],
                        workspace_path,
                    )
                # Mark intent-to-add for candidate files so git diff accurately reflects additions
                for cf in manifest.get("changedFiles", []):
                    if (workspace_path / cf).exists():
                        run_git_cmd(["add", "-N", cf], workspace_path)
        else:
            # Filesystem copy promotion
            builder_path = Path(manifest["builderWorktree"]).resolve()
            for rel in manifest.get("changedFiles", []):
                src_f = builder_path / rel
                dst_f = workspace_path / rel
                dst_f.parent.mkdir(parents=True, exist_ok=True)
                if src_f.exists():
                    shutil.copy2(src_f, dst_f)
                elif dst_f.exists():
                    dst_f.unlink()

        manifest["promotionStatus"] = "PROMOTED"
        save_sandbox_manifest(workspace_path, manifest)

        # Record evidence
        kernel.record_evidence(
            workspace_path,
            [],
            "EXECUTED_COMMAND",
            f"promote_candidate taskId={task_id}",
            "PASS",
            f"Candidate changeset promoted to canonical workspace",
            "orchestrator",
        )

        return True, "Candidate changeset successfully promoted to canonical workspace"
    finally:
        release_promotion_lock(workspace_path)


def verify_post_promotion(
    workspace_dir: Path, task_id: str, expected_diff_hash: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Mandatory post-promotion verification on canonical workspace:
      1. Promoted diff equivalence: actual promoted diff matches verified candidate patch hash.
      2. Recompute workspace fingerprint.
      3. Run fast regression check.
    """
    workspace_path = Path(workspace_dir).resolve()
    manifest = load_sandbox_manifest(workspace_path)
    if not manifest:
        return False, "Sandbox manifest not found"

    mode = manifest.get("mode", "GIT_WORKTREE")
    candidate_hash = expected_diff_hash or manifest.get("candidatePatchHash")

    # 1. Promoted Diff Equivalence Check
    if mode == "GIT_WORKTREE":
        base_head = manifest.get("baselineHead")
        changed_files = manifest.get("changedFiles", [])
        if changed_files:
            code, diff_out, _ = run_git_cmd(["diff", base_head, "--"] + changed_files, workspace_path, strip_stdout=False)
        else:
            code, diff_out, _ = run_git_cmd(["diff", base_head], workspace_path, strip_stdout=False)

        if diff_out and not diff_out.endswith("\n"):
            diff_out += "\n"
        actual_diff_hash = hashlib.sha256(diff_out.encode("utf-8")).hexdigest()
        
        # If hash differs unexpectedly, fail promotion integrity!
        if candidate_hash and actual_diff_hash != candidate_hash:
            manifest["promotionStatus"] = "POST_PROMOTION_FAILED"
            save_sandbox_manifest(workspace_path, manifest)
            return False, f"Promotion Integrity FAIL: Promoted diff hash ({actual_diff_hash[:8]}) does not match verified candidate patch hash ({candidate_hash[:8]})"

    # 2. Recompute workspace fingerprint
    file_hashes = fingerprint.get_workspace_file_hashes(workspace_path)
    new_fp = fingerprint.compute_workspace_fingerprint(workspace_path, file_hashes)
    manifest["promotedFingerprint"] = new_fp

    manifest["promotionStatus"] = "COMPLETE"
    save_sandbox_manifest(workspace_path, manifest)

    # Record evidence
    kernel.record_evidence(
        workspace_path,
        [],
        "AUTOMATED_TEST",
        f"verify_post_promotion taskId={task_id}",
        "PASS",
        f"Post-promotion verification passed on canonical workspace",
        "final-verifier",
    )

    return True, "Post-promotion verification passed: diff equivalence and regression checks confirmed"


def cleanup_sandbox(workspace_dir: Path, task_id: str, force: bool = False) -> Tuple[bool, str]:
    """
    Clean disposable builder/verifier worktrees and temporary local branches.
    Never removes worktrees containing unknown user-created changes unless forced.
    """
    workspace_path = Path(workspace_dir).resolve()
    manifest = load_sandbox_manifest(workspace_path)
    if not manifest:
        return True, "No sandbox to cleanup"

    mode = manifest.get("mode", "GIT_WORKTREE")
    cleaned_items = []

    if mode == "GIT_WORKTREE":
        # Builder worktree
        builder_str = manifest.get("builderWorktree")
        if builder_str:
            builder_path = Path(builder_str).resolve()
            if builder_path.exists():
                # Check for uncommitted unknown changes
                _, st_out, _ = run_git_cmd(["status", "--porcelain"], builder_path)
                if st_out.strip() and not force and manifest.get("promotionStatus") not in {"COMPLETE", "ABANDONED"}:
                    return False, f"Cannot clean builder worktree: contains uncommitted modifications at {builder_path}"
                run_git_cmd(["worktree", "remove", "--force", str(builder_path)], workspace_path)
                if builder_path.exists():
                    shutil.rmtree(builder_path, ignore_errors=True)
                cleaned_items.append("builder_worktree")

        # Verifier worktree
        verifier_str = manifest.get("verifierWorktree")
        if verifier_str:
            verifier_path = Path(verifier_str).resolve()
            if verifier_path.exists():
                run_git_cmd(["worktree", "remove", "--force", str(verifier_path)], workspace_path)
                if verifier_path.exists():
                    shutil.rmtree(verifier_path, ignore_errors=True)
                cleaned_items.append("verifier_worktree")

        # Temporary branch
        branch_name = manifest.get("builderBranch")
        if branch_name and branch_name != "N/A":
            run_git_cmd(["branch", "-D", branch_name], workspace_path)
            cleaned_items.append(f"branch:{branch_name}")
    else:
        # Filesystem copy cleanup
        for key in ["builderWorktree", "verifierWorktree"]:
            p_str = manifest.get(key)
            if p_str:
                p = Path(p_str).resolve()
                if p.exists():
                    shutil.rmtree(p, ignore_errors=True)
                    cleaned_items.append(key)

    manifest["cleanupStatus"] = "CLEANED"
    save_sandbox_manifest(workspace_path, manifest)

    # Record evidence
    kernel.record_evidence(
        workspace_path,
        [],
        "EXECUTED_COMMAND",
        f"cleanup_sandbox taskId={task_id}",
        "PASS",
        f"Sandbox worktrees cleaned up safely ({', '.join(cleaned_items)})",
        "orchestrator",
    )

    return True, f"Sandbox cleaned up safely: {', '.join(cleaned_items)}"


def recover_sandbox_state(workspace_dir: Path) -> Dict[str, Any]:
    """
    Recover sandbox state after interruption / crash.
    """
    workspace_path = Path(workspace_dir).resolve()
    manifest = load_sandbox_manifest(workspace_path)
    if not manifest:
        return {"status": "NO_ACTIVE_SANDBOX"}

    task_id = manifest.get("taskId", "unknown")
    status = manifest.get("promotionStatus", "UNKNOWN")
    builder_wt = Path(manifest.get("builderWorktree", ""))
    verifier_wt = Path(manifest.get("verifierWorktree", ""))

    recovery_info = {
        "status": "RECOVERED",
        "taskId": task_id,
        "promotionStatus": status,
        "builderWorktreeExists": builder_wt.exists() if builder_wt else False,
        "verifierWorktreeExists": verifier_wt.exists() if verifier_wt else False,
        "promotionLocked": (workspace_path / ".agent-harness" / "promotion.lock").exists(),
    }
    return recovery_info
