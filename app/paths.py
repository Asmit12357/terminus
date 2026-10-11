"""Filesystem locations.

Two kinds of paths exist and are never mixed:

* **Bundled resources** ship inside the installed package (sample inventory,
  recorded demo fixtures, the config template). They are read-only.
* **User data** (database, scan history, cached responses, ``config.env``)
  lives in one per-user directory, the *Terminus home*, which is never the
  installation directory or the current working directory:

  =========  ==================================================
  Windows    ``%LOCALAPPDATA%\\Terminus``
  Linux      ``$XDG_DATA_HOME/terminus`` (``~/.local/share/terminus``)
  macOS      ``~/Library/Application Support/Terminus``
  =========  ==================================================

  ``TERMINUS_HOME`` (or ``terminus --home DIR``) overrides the location.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
BUNDLED_DATA_DIR = PACKAGE_DIR / "data"
FIXTURES_DIR = BUNDLED_DATA_DIR / "fixtures"
SAMPLE_INVENTORY_JSON = BUNDLED_DATA_DIR / "sample_inventory.json"
SAMPLE_INVENTORY_CSV = BUNDLED_DATA_DIR / "sample_inventory.csv"
CONFIG_TEMPLATE = BUNDLED_DATA_DIR / "config.env.example"

HOME_ENV_VAR = "TERMINUS_HOME"
CONFIG_FILE_NAME = "config.env"
DB_FILE_NAME = "terminus.db"


def default_home() -> Path:
    """Platform data directory, ignoring any override."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "Terminus"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Terminus"
    xdg = os.environ.get("XDG_DATA_HOME")
    # The XDG spec says relative values must be ignored.
    root = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / ".local" / "share"
    return root / "terminus"


def resolve_home() -> Path:
    """The Terminus home: ``TERMINUS_HOME`` when set, otherwise the platform default."""
    override = os.environ.get(HOME_ENV_VAR, "").strip()
    return Path(override).expanduser().resolve() if override else default_home()


def config_file(home: Path) -> Path:
    return home / CONFIG_FILE_NAME


def ensure_dir(path: Path) -> Path:
    """Create a private directory (0700 on POSIX) if it does not exist."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path
