"""Profile-scoped settings for the Iroh interconnect plugin.

Simple JSON file (0600) in the state dir. Currently controls whether
incoming file transfers are auto-fetched or surface as a normal message.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

SETTINGS_FILENAME = "settings.json"

_DEFAULTS: Dict[str, Any] = {
    # Receiving files is a local write side effect; require explicit opt-in.
    "auto_fetch": os.environ.get("HERMES_IROH_DEFAULT_AUTO_FETCH", "false").strip().lower()
    in {"1", "true", "yes", "on"},
}


def _state_dir() -> Path:
    override = os.environ.get("HERMES_IROH_STATE_DIR")
    if override:
        return Path(override)
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home()) / "iroh-interconnect"
    except Exception:
        return Path.home() / ".hermes" / "iroh-interconnect"


class Settings:
    """Durable, profile-scoped settings with 0600 permissions."""

    def __init__(self, data_dir: os.PathLike | str):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / SETTINGS_FILENAME
        self._ensure_file()

    def _ensure_file(self) -> None:
        if not self.path.exists():
            self._write(dict(_DEFAULTS))
        else:
            self._repair_permissions()

    def _repair_permissions(self) -> None:
        try:
            mode = self.path.stat().st_mode & 0o777
            if mode != 0o600:
                os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _read(self) -> Dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return dict(_DEFAULTS)

    def _write(self, data: Dict[str, Any]) -> None:
        fd, tmp_name = None, None
        import tempfile

        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix="settings", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
        except Exception:
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            raise

    def get(self, key: str, default: Any = None) -> Any:
        return self._read().get(key, _DEFAULTS.get(key, default))

    def set(self, key: str, value: Any) -> None:
        data = self._read()
        data[key] = value
        self._write(data)

    def all(self) -> Dict[str, Any]:
        merged = dict(_DEFAULTS)
        merged.update(self._read())
        return merged


def auto_fetch_enabled() -> bool:
    """Check if auto-fetch is enabled (default false)."""
    return bool(Settings(_state_dir()).get("auto_fetch", False))
