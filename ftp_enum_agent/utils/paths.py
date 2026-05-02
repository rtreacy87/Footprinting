from pathlib import Path


def safe_local_path(base: Path, remote_path: str) -> Path:
    """Convert a remote absolute path to a safe local path under base."""
    clean = remote_path.lstrip("/")
    local = base / clean
    # Prevent path traversal
    try:
        local.resolve().relative_to(base.resolve())
    except ValueError:
        local = base / Path(remote_path).name
    return local
