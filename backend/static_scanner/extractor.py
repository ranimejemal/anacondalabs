"""
AegisLab - static_scanner/extractor.py
=========================================
Safely extracts an uploaded zip into an isolated temp directory.

SAFETY:
  - Rejects path-traversal entries ("zip slip") — every extracted path is
    verified to remain inside the target directory before it's written.
  - Rejects oversized archives (uncompressed size cap) to prevent zip bombs.
  - Skips noisy/irrelevant directories (node_modules, .git, build artifacts,
    binaries) so the scan stays fast and signal stays high.
  - Never executes, imports, or evaluates anything from the archive — every
    file is opened as plain text for pattern matching only.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # 200MB cap — generous for source code, blocks zip bombs
MAX_FILE_COUNT = 20000
MAX_SINGLE_FILE_BYTES = 3 * 1024 * 1024  # skip anything bigger than 3MB (unlikely to be source)

SKIP_DIR_NAMES = {
    "node_modules", ".git", "dist", "build", "out", "coverage",
    "__pycache__", ".venv", "venv", ".next", ".turbo", "vendor",
    "target", ".idea", ".vscode",
}

# File extensions worth reading for source/config analysis
TEXT_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".json", ".yml", ".yaml", ".env", ".example",
    ".md", ".txt", ".toml", ".ini", ".cfg",
}
# Files with no extension that are still worth reading
TEXT_FILENAMES = {".env", "Dockerfile", "Procfile", ".env.local", ".env.production"}


class ZipRejectedError(Exception):
    pass


def safe_extract(zip_path: str, dest_dir: str) -> list[Path]:
    """
    Extracts `zip_path` into `dest_dir`, enforcing the safety limits above.
    Returns the list of extracted file paths worth scanning (already
    filtered to skip noisy directories and binary-ish files).
    """
    dest = Path(dest_dir).resolve()

    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        raise ZipRejectedError("This doesn't look like a valid zip file.")

    infos = zf.infolist()
    if len(infos) > MAX_FILE_COUNT:
        raise ZipRejectedError(f"Archive has too many entries (> {MAX_FILE_COUNT}); refusing to extract.")

    total_uncompressed = sum(i.file_size for i in infos)
    if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
        raise ZipRejectedError("Archive is too large when uncompressed; refusing to extract (possible zip bomb).")

    extracted: list[Path] = []

    for info in infos:
        if info.is_dir():
            continue

        # --- zip-slip protection: resolve and verify containment ---
        target_path = (dest / info.filename).resolve()
        if dest not in target_path.parents and target_path != dest:
            continue  # silently skip — this entry tries to escape the extraction dir

        # --- skip noisy directories anywhere in the path ---
        parts = set(Path(info.filename).parts)
        if parts & SKIP_DIR_NAMES:
            continue

        # --- skip oversized individual files ---
        if info.file_size > MAX_SINGLE_FILE_BYTES:
            continue

        # --- only extract text-ish files we'll actually analyze ---
        suffix = Path(info.filename).suffix.lower()
        name = Path(info.filename).name
        if suffix not in TEXT_EXTENSIONS and name not in TEXT_FILENAMES:
            continue

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target_path, "wb") as dst:
            dst.write(src.read())
        extracted.append(target_path)

    zf.close()
    return extracted
