"""AegisLab static source-code (SAST) scanner package."""

from .runner import scan_zip
from .extractor import ZipRejectedError

__all__ = ["scan_zip", "ZipRejectedError"]
