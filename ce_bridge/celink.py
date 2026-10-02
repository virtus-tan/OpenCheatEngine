"""The link to Cheat Engine.

Cheat Engine's Lua has no socket library, so the transport is a spool of files
in %TEMP%\\ce_bridge_spool that a CE timer and this module both poll:

    hello.txt   written once by the agent: what that CE build supports
    status.txt  rewritten by the agent every tick: which process is attached
    cmd.txt     written here: one command, id=N plus key=value lines
    res.txt     written by the agent: the reply to that command

The human picks the process and attaches inside CE. This module only reports
the PID they attached to, and mirrors findings back into the address list.
"""

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time

from .core.winapi import ProcessHandle

SPOOL_NAME = "ce_bridge_spool"
TICK_SECONDS = 0.3
CALL_TIMEOUT = 20.0
STATUS_MAX_AGE = 5.0


def spool_dir():
    """Where the bridge and the agent exchange files.

    CEBRIDGE_SPOOL overrides it, which is how two bridges, or two test suites,
    stay out of each other's way. The Lua agent reads the same variable.
    """
    override = os.environ.get("CEBRIDGE_SPOOL")
    if override:
        return os.path.abspath(override)
    return os.path.join(tempfile.gettempdir(), SPOOL_NAME)


def _copy_tree(source, target):
    """Copy a directory, skipping anything that cannot be read.

    Cheat Engine holds its .dat files open, and shutil.copytree aborts the whole
    copy on the first entry it cannot open. The agent only needs autorun and the
    helper DLLs, so a few skipped data files do not matter.
    """
    copied = 0
    skipped = 0
    for root, _dirs, files in os.walk(source):
        relative = os.path.relpath(root, source)
        destination_root = target if relative == "." else os.path.join(target, relative)
        os.makedirs(destination_root, exist_ok=True)
        for name in files:
            try:
                shutil.copy2(os.path.join(root, name), os.path.join(destination_root, name))
                copied += 1
            except Exception:
                skipped += 1
    return copied, skipped


class CELink:
    def __init__(self, log, autorun_dir=None, agent_file=None):
        self.log = log
        self.autorun_dir = autorun_dir
        self.agent_file = agent_file
        self.dir = spool_dir()
        self.cmd_path = os.path.join(self.dir, "cmd.txt")
        self.res_path = os.path.join(self.dir, "res.txt")
        self.status_path = os.path.join(self.dir, "status.txt")
        self.hello_path = os.path.join(self.dir, "hello.txt")
        self.lock = threading.RLock()
        self._counter = 0
        self._process = None
        self._stop = threading.Event()
        self._thread = None
        self.state = {
            "agent_seen": False,
            "agent_version": None,
            "ce_version": None,
            "capabilities": [],
            "address_list_supported": False,
            "attached_pid": None,
            "attached_name": None,
            "arch": None,
            "address_list_count": 0,
            "last_error": None,
        }
        self.on_attach = None
        self.on_detach = None

    def ensure_dir(self):
        os.makedirs(self.dir, exist_ok=True)
        return self.dir

    def start(self):
        self.ensure_dir()
        # hello.txt too: it survives Cheat Engine closing, and a stale one must
        # not be mistaken for a running agent.
        for stale in (self.cmd_path, self.res_path, self.status_path, self.hello_path):
            try:
                os.remove(stale)
            except OSError:
                pass
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)

    def _poll_loop(self):
        while not self._stop.is_set():
            try:
                self._read_status()
            except Exception as error:
                self.log.debug("status poll failed: %s", error)
            self._stop.wait(TICK_SECONDS)

    def _read_json_file(self, path):
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("json="):
                        raw = bytes.fromhex(line[5:].strip()).decode("utf-8", "replace")
                        return json.loads(raw)
        except Exception:
            return None
        return None

    @staticmethod
    def _normalise_pid(value):
        """Cheat Engine reports -1 when nothing is attached, which is truthy."""
        try:
            pid = int(value)
        except (TypeError, ValueError):
            return None
        return pid if pid > 0 else None

    def _read_status(self):
        if not os.path.exists(self.status_path):
            return None
        if time.time() - os.path.getmtime(self.status_path) > STATUS_MAX_AGE:
            self.state["agent_seen"] = False
            return None
        report = self._read_json_file(self.status_path)
        if not report:
            return None
        previous = self.state.get("attached_pid")
        current = self._normalise_pid(report.get("pid"))
        self.state.update({
            "agent_seen": True,
            "ce_version": report.get("ce_version") or self.state.get("ce_version"),
            "attached_pid": current,
            "attached_name": report.get("name") if current else None,
            "arch": report.get("arch") if current else None,
            "address_list_count": report.get("address_list_count") or 0,
        })
        if current and current != previous:
            self.log.info("Cheat Engine attached to pid %s (%s)", current, report.get("name"))
            if self.on_attach:
                self.on_attach(current, report.get("name"))
        elif (not current) and previous:
            self.log.info("Cheat Engine detached")
            if self.on_detach:
                self.on_detach()
        return report

    def describe_process(self, pid, reported_name=None):
        """Name and architecture for a pid, preferring what Cheat Engine said.

        Cheat Engine 7.4's Lua exposes neither getProcessName nor targetIs64bit,
        so its report usually carries a pid and nothing else. Windows knows both
        regardless, which is why the bridge asks it rather than treating the
        missing fields as a failure.
        """
        info = {"name": reported_name, "arch": None}
        try:
            handle = ProcessHandle(int(pid), writable=False)
        except Exception:
            return info
        try:
            info["arch"] = "x64" if handle.is_64bit else "x86"
            if not info["name"]:
                info["name"] = handle.base_name()
        except Exception:
            pass
        finally:
            handle.close()
        return info



    def hello(self, refresh=False):
        """Read what the agent supports.

        Deliberately does not set agent_seen: hello.txt only records that the
        agent ran once, and it stays on disk after Cheat Engine closes. Only
        status.txt, which is rewritten on every tick, proves it is alive now.
        """
        if not refresh and self.state.get("capabilities"):
            return {"capabilities": self.state["capabilities"]}
        report = self._read_json_file(self.hello_path)
        if not report:
            return None
        self.state.update({
            "agent_version": report.get("version"),
            "capabilities": report.get("functions") or [],
            "address_list_supported": bool(report.get("addresslist")),
            "ce_version": report.get("ce_version") or self.state.get("ce_version"),
        })
        return {
            "version": report.get("version"),
            "ce_version": report.get("ce_version"),
            "functions": report.get("functions") or [],
            "type_constants": report.get("type_constants") or [],
            "addresslist": report.get("addresslist"),
        }


    def call(self, command, timeout=CALL_TIMEOUT, **params):
        """Send one command and wait for the agent's reply."""
        if not self.state.get("agent_seen"):
            return {
                "ok": False,
                "error": "the Cheat Engine agent is not connected. Start Cheat "
                         "Engine, and if it is running install the agent first "
                         "with ce_ce_install (once, as administrator).",
            }
        with self.lock:
            self.ensure_dir()
            self._counter += 1
            request_id = self._counter
            try:
                os.remove(self.res_path)
            except OSError:
                pass
            lines = [f"id={request_id}", f"command={command}"]
            for key, value in params.items():
                if value is None:
                    continue
                if key == "script":
                    lines.append("script=" + str(value).replace("\r\n", "\n"))
                else:
                    text = str(value)
                    lines.append(f"{key}=" + text.replace("\r", " ").replace("\n", " "))
            payload = ("\n".join(lines) + "\n").encode("utf-8")
            temp = self.cmd_path + ".tmp"
            with open(temp, "wb") as handle:
                handle.write(payload)
            try:
                os.replace(temp, self.cmd_path)
            except OSError as error:
                return {"ok": False, "error": f"could not queue the command: {error}"}

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._stop.is_set():
                return {"ok": False, "error": "bridge is shutting down"}
            reply = self._read_fields(self.res_path)
            if reply and str(reply.get("id")) == str(request_id):
                try:
                    os.remove(self.res_path)
                except OSError:
                    pass
                if reply.get("ok") != "1":
                    return {"ok": False, "error": reply.get("error") or "agent reported a failure"}
                raw = reply.get("json")
                if not raw:
                    self._read_status()
                    return {"ok": True, "result": {}}
                try:
                    result = json.loads(bytes.fromhex(raw).decode("utf-8"))
                except Exception as error:
                    return {"ok": False, "error": f"could not decode the agent reply: {error}"}
                # The agent has just done something, which is the moment an
                # attach or a detach is most likely to have happened. Reading
                # status now means the bridge notices immediately instead of
                # waiting for the next background poll.
                self._read_status()
                return {"ok": True, "result": result}
            time.sleep(0.05)
        return {
            "ok": False,
            "error": f"Cheat Engine did not answer {command!r} within {timeout}s. "
                     "Is the agent installed and Cheat Engine running?",
        }

    def _read_fields(self, path):
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read()
        except OSError:
            return None
        fields = {}
        for line in content.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value
        return fields

    def status(self):
        self._read_status()
        self.hello()
        with self.lock:
            state = dict(self.state)
        pid = state.get("attached_pid")
        if pid and not (state.get("attached_name") and state.get("arch")):
            described = self.describe_process(pid, state.get("attached_name"))
            with self.lock:
                self.state["attached_name"] = described["name"]
                self.state["arch"] = described["arch"]
            state["attached_name"] = described["name"]
            state["arch"] = described["arch"]
        state.update({
            "spool": self.dir,
            "cmd_path": self.cmd_path,
            "agent_installed": self.agent_installed(),
            "ce_pid": self._process.pid if self._process else None,
            "ce_running": self._process.poll() is None if self._process else bool(self.find_ce()),
        })
        if not state["agent_seen"]:
            state["hint"] = (
                "The agent is not reporting. Install it with ce_ce_install (run once "
                "as administrator), then restart Cheat Engine."
            )
        return state

    def agent_installed(self):
        if not self.autorun_dir:
            return False
        return os.path.exists(os.path.join(self.autorun_dir, "ce_bridge_agent.lua"))

    def install_agent(self, source=None):
        """Copy the Lua agent into CE's autorun folder.

        Tries the real install folder first. If that is not writable, which it
        is not without elevation, it falls back to a user-writable copy of
        Cheat Engine: the autorun folder is resolved relative to the executable,
        so a copy picks up its own agent with no administrator rights at all.
        """
        source = source or self.agent_file
        if not source or not os.path.exists(source):
            return {"ok": False, "error": f"agent source not found: {source}"}
        if not self.autorun_dir or not os.path.isdir(self.autorun_dir):
            return {"ok": False, "error": f"Cheat Engine autorun folder not found: {self.autorun_dir}"}
        destination = os.path.join(self.autorun_dir, "ce_bridge_agent.lua")
        try:
            with open(source, "r", encoding="utf-8") as handle:
                content = handle.read()
            with open(destination, "w", encoding="utf-8") as handle:
                handle.write(content)
            return {"ok": True, "where": "install", "destination": destination,
                    "note": "restart Cheat Engine for the agent to load"}
        except PermissionError:
            return self.install_agent_local(source, content)
        except Exception as error:
            return {"ok": False, "error": str(error)}

    def install_agent_local(self, source, content=None):
        """Copy the whole Cheat Engine folder somewhere writable and add the agent.

        Roughly 75 MB, done once. Cheat Engine resolves autorun, languages and
        its helper DLLs relative to its own executable, so the copy behaves
        identically and needs no elevation.

        Cheat Engine keeps .dat files open while it runs, so the copy tolerates
        entries it cannot read rather than failing outright.
        """
        if not self.autorun_dir:
            return {"ok": False, "error": "no Cheat Engine folder configured"}
        origin = os.path.dirname(self.autorun_dir.rstrip("\\/"))
        if not os.path.isdir(origin):
            return {"ok": False, "error": f"Cheat Engine folder not found: {origin}"}
        target = os.path.join(
            os.environ.get("LOCALAPPDATA", tempfile.gettempdir()),
            "CEBridge", "Cheat Engine",
        )
        available = {
            entry.lower()
            for entry in os.listdir(origin)
            if entry.lower().startswith("cheatengine") and entry.lower().endswith(".exe")
        }
        exe_name = next(
            (name for name in ("cheatengine-x86_64.exe", "cheatengine-x86_64-SSE4-AVX2.exe",
                               "cheatengine-i386.exe", "Cheat Engine.exe")
             if name.lower() in available),
            "cheatengine-x86_64.exe",
        )
        try:
            if not os.path.isdir(target):
                print(f"copying Cheat Engine to {target}, this happens once and takes a moment")
                copied, skipped = _copy_tree(origin, target)
                print(f"copied {copied} file(s), skipped {skipped}")
            autorun = os.path.join(target, "autorun")
            os.makedirs(autorun, exist_ok=True)
            if content is None:
                with open(source, "r", encoding="utf-8") as handle:
                    content = handle.read()
            destination = os.path.join(autorun, "ce_bridge_agent.lua")
            with open(destination, "w", encoding="utf-8") as handle:
                handle.write(content)
        except Exception as error:
            return {
                "ok": False,
                "error": f"the local copy failed: {error}",
                "source": source,
                "destination": os.path.join(self.autorun_dir, "ce_bridge_agent.lua"),
            }
        if not os.path.exists(os.path.join(target, exe_name)):
            return {
                "ok": False,
                "error": f"the copy is missing {exe_name}; remove {target} and try again",
            }
        return {
            "ok": True,
            "where": "local-copy",
            "ce_dir": target,
            "exe": os.path.join(target, exe_name),
            "destination": destination,
            "note": (
                "Cheat Engine was copied to a writable folder so the agent can load "
                "without administrator rights. The bridge will now launch that copy. "
                "Restart Cheat Engine for the agent to load."
            ),
        }


    def find_ce(self):
        try:
            import psutil
            for process in psutil.process_iter(["name"]):
                name = (process.info.get("name") or "").lower()
                if name.startswith("cheatengine") or name == "cheat engine.exe":
                    return process.pid
        except Exception:
            pass
        return None

    def launch(self, exe_path, arch="x64", prefer_avx=False):
        """Start Cheat Engine. The human attaches to the game inside it.

        Cheat Engine's manifest asks for administrator rights, and CreateProcess
        cannot satisfy that: it fails with ERROR_ELEVATION_REQUIRED. ShellExecute
        is what raises the UAC prompt, so the user accepts it once per launch.
        """
        existing = self.find_ce()
        if existing:
            return {
                "ok": True,
                "pid": existing,
                "already_running": True,
                "next": "Cheat Engine is already running. Attach to the game in it.",
            }
        if not exe_path or not os.path.exists(exe_path):
            return {"ok": False, "error": f"Cheat Engine executable not found: {exe_path}"}
        try:
            import ctypes
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "open", exe_path, None,
                os.path.dirname(exe_path), 1,
            )
        except Exception as error:
            return {"ok": False, "error": f"could not start Cheat Engine: {error}"}
        if result <= 32:
            return {
                "ok": False,
                "error": f"ShellExecute failed with code {result}. "
                         "Start Cheat Engine yourself and the bridge will find it.",
            }
        pid = self.find_ce()
        self.log.info("Cheat Engine started (pid %s)", pid)
        return {
            "ok": True,
            "pid": pid,
            "path": exe_path,
            "arch_hint": arch,
            "avx": prefer_avx,
            "uac": "Cheat Engine asks for administrator rights. Accept the prompt.",
            "next": "Open the game, then attach to it in Cheat Engine. The bridge "
                    "picks the target up automatically within a second.",
        }

    def mirror(self, items):
        """Push addresses into CE's address list so findings are visible in the GUI."""
        added = []
        failed = []
        for item in items:
            reply = self.call(
                "add_address",
                address=item.get("address"),
                name=item.get("name") or "",
                type=item.get("type") or "f32",
                comment=item.get("comment") or "",
                value=item.get("value"),
            )
            if not reply.get("ok"):
                # The agent is gone or wedged; do not spend the timeout on
                # every remaining row.
                failed.append({"item": item, "error": reply.get("error")})
                break
            added.append(reply.get("result") or {})
        return {
            "added": len(added),
            "failed": len(failed),
            "entries": added,
            "errors": failed,
            "address_list_count": self.state.get("address_list_count"),
        }
