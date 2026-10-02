"""Configuration: defaults, config.json, environment overrides."""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

DEFAULTS = {
    "host": "127.0.0.1",
    "port": 9877,
    "ce_agent_port": 9878,
    "ce_dir": r"C:\Program Files\Cheat Engine 7.4",
    "ce_exe_64": r"C:\Program Files\Cheat Engine 7.4\cheatengine-x86_64.exe",
    "ce_exe_64_avx": r"C:\Program Files\Cheat Engine 7.4\cheatengine-x86_64-SSE4-AVX2.exe",
    "ce_exe_32": r"C:\Program Files\Cheat Engine 7.4\cheatengine-i386.exe",
    "ce_agent_file": os.path.join(HERE, "ce_agent", "ce_bridge_agent.lua"),
    "ce_autorun_dir": r"C:\Program Files\Cheat Engine 7.4\autorun",
    "auto_launch_ce": False,
    "read_only_default": True,
    "log_file": os.path.join(ROOT, "bridge.log"),
    "log_level": "INFO",
    "max_request_seconds": 120,
}

ENV_PREFIX = "CEBRIDGE_"

KNOWN_CE_EXES = (
    r"C:\Program Files\Cheat Engine 7.4\cheatengine-x86_64.exe",
    r"C:\Program Files\Cheat Engine 7.4\cheatengine-x86_64-SSE4-AVX2.exe",
    r"C:\Program Files\Cheat Engine 7.4\cheatengine-i386.exe",
    r"C:\Program Files\Cheat Engine 7.4\Cheat Engine.exe",
)


class Config:
    def __init__(self, path=None, overrides=None):
        self.path = os.path.abspath(path or os.path.join(ROOT, "config.json"))
        self.data = dict(DEFAULTS)
        self.load()
        for key, value in (overrides or {}).items():
            if value is not None:
                self.data[key] = value
        for key in list(self.data):
            env = os.getenv(ENV_PREFIX + key.upper())
            if env:
                self.data[key] = _coerce(self.data[key], env)

    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                self.data.update(json.load(handle))
        except Exception as error:
            print(f"[config] ignoring {self.path}: {error}")

    def save(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2)
            handle.write("\n")

    def get(self, key, default=None):
        return self.data.get(key, default)

    def __getitem__(self, key):
        return self.data[key]

    def ce_exe_for(self, arch="x64", prefer_avx=False):
        if arch == "x86":
            candidates = [self.data["ce_exe_32"]]
        elif prefer_avx:
            candidates = [self.data["ce_exe_64_avx"], self.data["ce_exe_64"]]
        else:
            candidates = [self.data["ce_exe_64"]]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        for candidate in KNOWN_CE_EXES:
            if os.path.exists(candidate):
                return candidate
        return None

    def to_dict(self):
        return dict(self.data)


def _coerce(original, text):
    if isinstance(original, bool):
        return text.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(original, int):
        try:
            return int(text)
        except ValueError:
            return original
    if isinstance(original, float):
        try:
            return float(text)
        except ValueError:
            return original
    return text
