import json
from pathlib import Path

_BUILTIN_DIR = Path(__file__).parent / "builtin"
_CUSTOM_DIR = Path(__file__).parent / "custom"


def _load(path: Path):
    from rqsession._rust_core import load_profile
    return load_profile(str(path))


def _load_builtin(filename: str):
    return _load(_BUILTIN_DIR / filename)


def list_builtin() -> list[str]:
    return [p.stem for p in _BUILTIN_DIR.glob("*.json")]


def list_custom() -> list[str]:
    return [p.stem for p in _CUSTOM_DIR.glob("*.json")]


def load_custom(name: str):
    """Load a profile from profiles/custom/<name>.json"""
    path = _CUSTOM_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Custom profile not found: {path}")
    return _load(path)


# ── Built-in profile singletons (lazy-loaded) ────────────────────────────────

_cache: dict = {}


def _get(name: str):
    if name not in _cache:
        path = _BUILTIN_DIR / f"{name}.json"
        if not path.exists():
            raise FileNotFoundError(f"Built-in profile not found: {name}")
        _cache[name] = _load(path)
    return _cache[name]


class _ProfileProxy:
    """Lazily loads a built-in profile on first access."""
    def __init__(self, name: str):
        self._name = name

    def __getattr__(self, item):
        return getattr(_get(self._name), item)

    def _inner(self):
        return _get(self._name)


Chrome120 = _ProfileProxy("chrome120_windows")
Chrome119 = _ProfileProxy("chrome119_windows")
Edge142   = _ProfileProxy("edge142_windows")
Firefox133 = _ProfileProxy("firefox133_windows")
Safari17  = _ProfileProxy("safari17_macos")
