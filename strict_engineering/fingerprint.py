"""
Strict Engineering Kernel V4.1 - Fingerprint Module
Computes deterministic SHA-256 fingerprints of workspace source files and lockfiles,
tracks dependency impacts, detects additions/deletions/renames, and invalidates stale verifications.
"""

import os
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

# Directories ignored during workspace fingerprinting to prevent false positives
DEFAULT_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "dist",
    "build",
    "out",
    "target",
    "bin",
    "obj",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    ".idea",
    ".vscode",
    ".gemini",
    ".agent-harness",
    "docs",
    "tmp",
    "temp",
}

# File extensions ignored during fingerprinting
DEFAULT_IGNORED_EXTS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".class",
    ".dll",
    ".exe",
    ".obj",
    ".o",
    ".a",
    ".lib",
    ".so",
    ".dylib",
    ".log",
    ".tmp",
    ".bak",
    ".swp",
    ".swo",
    ".DS_Store",
}

# Filenames ignored during fingerprinting
DEFAULT_IGNORED_FILES = {
    "thumbs.db",
    "desktop.ini",
    ".ds_store",
}

# Important lockfiles and dependency manifests that ARE tracked
TRACKED_DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
}


def normalize_rel_path(path: str) -> str:
    """Normalize path to forward-slash relative path."""
    return str(Path(path)).replace("\\", "/").lstrip("/")


def hash_file(filepath: Path) -> str:
    """Compute SHA-256 hash of a single file."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return ""


def get_workspace_file_hashes(
    workspace_dir: Path,
    ignored_dirs: Optional[Set[str]] = None,
    ignored_exts: Optional[Set[str]] = None,
    ignored_files: Optional[Set[str]] = None,
) -> Dict[str, str]:
    """
    Traverse workspace and return a dictionary mapping normalized
    relative file paths to their SHA-256 hashes.
    Properly includes lockfiles and source files while ignoring docs/ and artifacts.
    """
    if ignored_dirs is None:
        ignored_dirs = DEFAULT_IGNORED_DIRS
    if ignored_exts is None:
        ignored_exts = DEFAULT_IGNORED_EXTS
    if ignored_files is None:
        ignored_files = DEFAULT_IGNORED_FILES

    file_hashes: Dict[str, str] = {}
    workspace_path = Path(workspace_dir).resolve()

    if not workspace_path.exists():
        return file_hashes

    for root, dirs, files in os.walk(workspace_path):
        # Prune ignored directories
        dirs[:] = [
            d for d in dirs
            if d not in ignored_dirs and not d.startswith(".agent-")
        ]

        rel_root = Path(root).relative_to(workspace_path)

        for filename in files:
            file_lower = filename.lower()
            if file_lower in ignored_files:
                continue

            ext = os.path.splitext(filename)[1].lower()
            if ext in ignored_exts:
                continue

            file_path = Path(root) / filename
            rel_file_path = rel_root / filename
            norm_rel_path = normalize_rel_path(str(rel_file_path))

            # Skip if within docs or .agent-harness
            if norm_rel_path.startswith("docs/") or norm_rel_path.startswith(".agent-harness/"):
                continue

            h = hash_file(file_path)
            if h:
                file_hashes[norm_rel_path] = h

    return file_hashes


def compute_workspace_fingerprint(
    workspace_dir: Path,
    file_hashes: Optional[Dict[str, str]] = None,
) -> str:
    """
    Compute a single deterministic SHA-256 hash representing the entire
    workspace source and dependency state.
    """
    if file_hashes is None:
        file_hashes = get_workspace_file_hashes(workspace_dir)

    hasher = hashlib.sha256()
    # Sort keys for deterministic hashing
    for rel_path in sorted(file_hashes.keys()):
        hasher.update(rel_path.encode("utf-8"))
        hasher.update(b":")
        hasher.update(file_hashes[rel_path].encode("utf-8"))
        hasher.update(b"\n")

    return hasher.hexdigest()


def compute_path_subset_fingerprint(
    file_hashes: Dict[str, str],
    affected_paths: List[str],
) -> str:
    """
    Compute a fingerprint for a specific subset of affected paths.
    """
    hasher = hashlib.sha256()
    norm_affected = {normalize_rel_path(p) for p in affected_paths}

    matching_files = []
    for rel_path, fhash in file_hashes.items():
        for aff in norm_affected:
            if rel_path == aff or rel_path.startswith(aff.rstrip("/") + "/"):
                matching_files.append((rel_path, fhash))
                break

    matching_files.sort(key=lambda x: x[0])
    for rel_path, fhash in matching_files:
        hasher.update(rel_path.encode("utf-8"))
        hasher.update(b":")
        hasher.update(fhash.encode("utf-8"))
        hasher.update(b"\n")

    return hasher.hexdigest()


def compare_workspace_hashes(
    old_hashes: Dict[str, str],
    new_hashes: Dict[str, str],
) -> Dict[str, Any]:
    """
    Detailed delta comparison between two sets of workspace file hashes.
    Tracks additions, deletions, modifications, and renames.
    """
    old_keys = set(old_hashes.keys())
    new_keys = set(new_hashes.keys())

    added = sorted(list(new_keys - old_keys))
    deleted = sorted(list(old_keys - new_keys))
    common = old_keys & new_keys

    modified = [k for k in sorted(list(common)) if old_hashes[k] != new_hashes[k]]

    # Detect renames (deleted file has same hash as added file)
    renamed: List[Tuple[str, str]] = []
    unpaired_deleted = list(deleted)
    unpaired_added = list(added)

    for d in list(unpaired_deleted):
        d_hash = old_hashes[d]
        for a in list(unpaired_added):
            if new_hashes[a] == d_hash:
                renamed.append((d, a))
                unpaired_deleted.remove(d)
                unpaired_added.remove(a)
                break

    return {
        "changed": len(added) > 0 or len(deleted) > 0 or len(modified) > 0,
        "added": unpaired_added,
        "deleted": unpaired_deleted,
        "modified": modified,
        "renamed": renamed,
    }


def find_stale_requirements(
    workspace_dir: Path,
    requirements: List[Dict],
    dependency_map: Dict[str, List[str]],
    current_file_hashes: Optional[Dict[str, str]] = None,
) -> List[str]:
    """
    Compare current source file hashes against last verified fingerprints.
    Returns requirement IDs that should be transitioned to STALE.
    """
    if current_file_hashes is None:
        current_file_hashes = get_workspace_file_hashes(workspace_dir)

    current_workspace_fp = compute_workspace_fingerprint(workspace_dir, current_file_hashes)
    stale_req_ids = []

    for req in requirements:
        req_id = req.get("id")
        if not req_id:
            continue

        status = req.get("status")
        if status != "PASS":
            continue

        last_fp = req.get("lastVerifiedFingerprint")
        if not last_fp:
            # If a requirement claims PASS without a recorded fingerprint, it is unverified / stale
            stale_req_ids.append(req_id)
            continue

        # Check if requirement has specific affected paths in dependency-map or requirement entry
        affected = req.get("affectedPaths") or dependency_map.get(req_id) or []
        if affected:
            current_subset_fp = compute_path_subset_fingerprint(current_file_hashes, affected)
            recorded_subset_fp = req.get("lastVerifiedSubsetFingerprint")
            if recorded_subset_fp:
                if current_subset_fp != recorded_subset_fp:
                    stale_req_ids.append(req_id)
            else:
                # If no subset fingerprint recorded, check if subset matches current or workspace changed
                if current_workspace_fp != last_fp:
                    stale_req_ids.append(req_id)
        else:
            # Full workspace dependency
            if current_workspace_fp != last_fp:
                stale_req_ids.append(req_id)

    return stale_req_ids
