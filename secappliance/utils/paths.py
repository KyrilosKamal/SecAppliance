"""Locate bundled package data in a source checkout, an installed wheel, or a PyInstaller bundle."""
import sys
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent.parent


def package_path(relative_path: str = "") -> Path:
    """Absolute path to a file shipped inside the ``secappliance`` package."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "secappliance" / relative_path
    return _PACKAGE_DIR / relative_path
