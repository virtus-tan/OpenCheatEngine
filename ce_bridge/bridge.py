"""Bridge state and the tool surface the opencode tools call.

One Bridge object owns the target session and the Cheat Engine link, and
exposes every operation as a plain method taking keyword arguments. server.py
turns HTTP into these calls; nothing else touches bpy-style global state.
"""

import os
import threading
import time
import traceback
from datetime import datetime, timezone

from . import config as config_module
from .celink import CELink
from .core import managed as managed_core
from .session import BridgeError, NoTarget, ReadOnly, Target, list_processes

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Logger:
    def __init__(self, path, level="INFO"):
        self.path = path
        self.level = level
        self.levels = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
        self.threshold = self.levels.get(level.upper(), 20)
        self.lock = threading.Lock()
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def _write(self, level, message, args):
        if self.levels.get(level, 20) < self.threshold:
            return
        try:
            text = message % args if args else str(message)
        except Exception:
            text = f"{message} {args}"
        line = f"{now()} {level:<5} {text}"
        with self.lock:
            print(line, flush=True)
            if self.path:
                try:
                    with open(self.path, "a", encoding="utf-8") as handle:
                        handle.write(line + "\n")
                except OSError:
                    pass

    def debug(self, message, *args):
        self._write("DEBUG", message, args)

    def info(self, message, *args):
        self._write("INFO", message, args)

    def warn(self, message, *args):
        self._write("WARN", message, args)

    def error(self, message, *args):
        self._write("ERROR", message, args)


class Bridge:
    def __init__(self, config=None):
        self.config = config or config_module.Config()
        self.log = Logger(self.config.get("log_file"), self.config.get("log_level"))
        self.started_at = now()
        self.lock = threading.RLock()
        self.target = None
        self.history = []
        self.ce = CELink(
            self.log,
            autorun_dir=self.config.get("ce_autorun_dir"),
            agent_file=self.config.get("ce_agent_file"),
        )
        self.ce.on_attach = self._on_ce_attach
        self.ce.on_detach = self._on_ce_detach

    def start(self):
        self.ce.start()
        self.log.info("bridge ready on %s:%s", self.config.get("host"), self.config.get("port"))
        return self

    def stop(self):
        with self.lock:
            if self.target:
                self.target.close()
                self.target = None
        self.ce.stop()
        self.log.info("bridge stopped")

    def _on_ce_attach(self, pid, name):
        with self.lock:
            if self.target and self.target.pid == pid:
                return
            if self.target:
                self.log.info("closing previous target pid %s", self.target.pid)
                self.target.close()
                self.target = None
            try:
                self.target = Target(pid, writable=not self.config.get("read_only_default"),
                                     source="cheat-engine")
            except Exception as error:
                self.log.error("could not attach to pid %s: %s", pid, error)
                self.history.append({"at": now(), "event": "attach_failed", "pid": pid,
                                     "error": str(error)})
                return
            self.history.append({"at": now(), "event": "attached", "pid": pid, "name": name,
                                 "source": "cheat-engine"})
        self.log.info("target acquired: %s pid %s (%s)", name, pid,
                      "x64" if self.target.proc.is_64bit else "x86")

    def _on_ce_detach(self):
        with self.lock:
            if self.target:
                self.log.info("target released (Cheat Engine detached)")
                self.history.append({"at": now(), "event": "detached", "pid": self.target.pid})
                self.target.close()
                self.target = None

    def require_target(self):
        with self.lock:
            if self.target is None:
                raise NoTarget()
            if not self.target.proc.alive():
                pid = self.target.pid
                self.target.close()
                self.target = None
                raise BridgeError(
                    f"the target process (pid {pid}) has exited. Reattach in Cheat Engine."
                )
            return self.target

    def status(self):
        with self.lock:
            payload = {
                "bridge": {
                    "started_at": self.started_at,
                    "uptime_seconds": round(time.time() - _epoch(self.started_at), 1),
                    "host": self.config.get("host"),
                    "port": self.config.get("port"),
                },
                "cheat_engine": self.ce.status(),
                "target": self.target.status() if self.target else None,
                "events": self.history[-20:],
            }
        if self.target is None:
            payload["next_step"] = (
                "Start the game, attach to it in Cheat Engine, and the target "
                "appears here automatically. Use ce_ce_launch to open Cheat Engine "
                "first if it is not running."
            )
        return payload

    def ping(self):
        return {"pong": True, "at": now()}

    def processes(self, filter="", include_system=False):
        return list_processes(filter, include_system)

    def attach(self, pid, writable=False):
        with self.lock:
            if self.target:
                self.target.close()
                self.target = None
            self.target = Target(int(pid), writable=bool(writable), source="api")
            self.history.append({"at": now(), "event": "attached", "pid": int(pid),
                                 "source": "api"})
        return self.target.status()

    def attach_by_name(self, name, writable=False):
        matches = [item for item in list_processes(name)["processes"]
                   if name.lower() in (item["name"] or "").lower()]
        if not matches:
            raise BridgeError(
                f"no running process matches {name!r}. Use processes to see what is running."
            )
        if len(matches) > 1:
            raise BridgeError(
                f"{len(matches)} processes match {name!r}: "
                + ", ".join(f"{item['name']} pid {item['pid']}" for item in matches[:8])
                + ". Attach by pid."
            )
        return self.attach(matches[0]["pid"], writable)

    def detach(self):
        with self.lock:
            pid = self.target.pid if self.target else None
            if self.target:
                self.target.close()
                self.target = None
            self.history.append({"at": now(), "event": "detached", "pid": pid})
        return {"detached": pid is not None, "pid": pid}

    def unlock(self, writable=True):
        return self.require_target().unlock(bool(writable))

    def call(self, tool, params):
        handler = getattr(self, f"tool_{tool}", None)
        if handler is None:
            raise BridgeError(
                f"unknown tool {tool!r}. Available: {', '.join(sorted(TOOLS))}"
            )
        return handler(**(params or {}))

    def tool_status(self):
        return self.status()

    def tool_ping(self):
        return self.ping()

    def tool_processes(self, filter="", include_system=False):
        return self.processes(filter, include_system)

    def tool_attach(self, pid=None, name=None, writable=False):
        if pid is not None:
            return self.attach(pid, writable)
        if name:
            return self.attach_by_name(name, writable)
        target = self.require_target()
        return target.status()

    def tool_detach(self):
        return self.detach()

    def tool_unlock(self, writable=True):
        return self.unlock(writable)

    def tool_read(self, address=None, module=None, offset=None, type="u32", count=1):
        target = self.require_target()
        if address is None and module:
            address = self._module_offset(target, module, offset or 0)
        if address is None:
            raise BridgeError("address is required (or pass module plus offset)")
        return target.read(address, type, count)

    def tool_read_bytes(self, address, size=64, dump=True):
        return self.require_target().read_bytes(address, int(size), dump)

    def tool_write(self, address, value, type="u32", note=None):
        return self.require_target().write(address, value, type, note)

    def tool_write_bytes(self, address, data, note=None):
        return self.require_target().write_bytes(address, data, note)

    def tool_query(self, address):
        return self.require_target().query(address)

    def tool_modules(self, filter=""):
        return self.require_target().modules(filter)

    def tool_memory_map(self, writable_only=False, executable_only=False, committed_only=True):
        return self.require_target().memory_map(writable_only, executable_only, committed_only)

    def tool_disasm(self, address, count=16, module=None, follow_thunk=True):
        return self.require_target().disasm(address, int(count), module, follow_thunk)

    def tool_assemble(self, asm, address=0):
        return self.require_target().assemble(asm, address)

    def tool_assemble_write(self, asm, address, note=None):
        return self.require_target().assemble_write(asm, address, note)

    def tool_scan_start(self, type="u32", scan_type="unknown_initial", value=None,
                        alignment=1, module=None, region_type=None, writable_only=True,
                        executable_only=False, start=None, end=None,
                        max_results=4_000_000, struct=None, values=None, tolerance=0.0):
        return self.require_target().scan_start(
            value_type=type, scan_type=scan_type, value=value, alignment=int(alignment),
            module=module, region_type=region_type, writable_only=writable_only,
            executable_only=executable_only, start=start or 0, end=end or 0,
            max_results=int(max_results), struct=struct, values=values, tolerance=tolerance,
        )

    def tool_scan_next(self, scan_type, value=None, tolerance=0.0):
        return self.require_target().scan_next(scan_type, value, tolerance)

    def tool_scan_results(self, offset=0, limit=500, group=False, values=True):
        return self.require_target().scan_results(int(offset), int(limit), group, values)
    def tool_scan_reset(self):
        return self.require_target().scan_reset()

    def tool_aob(self, pattern, module=None, max_hits=256, require_unique=False):
        return self.require_target().aob(pattern, module, int(max_hits), require_unique)

    def tool_xrefs(self, address, code_only=True, max_hits=256):
        return self.require_target().xrefs(address, code_only, int(max_hits))

    def tool_pointer_chains(self, address, depth=6, max_results=32, module=None,
                            writable_only=True):
        return self.require_target().pointer_chains(
            address, int(depth), int(max_results), module, writable_only
        )

    def tool_resolve_chain(self, chain, final_offset=0):
        return self.require_target().resolve_chain(chain, final_offset)

    def tool_freeze(self, address, value=None, type="f32", interval=0.1):
        target = self.require_target()
        if value is None:
            return target.freeze_status()
        return target.freeze(address, value, type, interval)

    def tool_unfreeze(self, address=None):
        target = self.require_target()
        return target.unfreeze_all() if address is None else target.unfreeze(address)

    def tool_freeze_status(self):
        return self.require_target().freeze_status()

    def tool_watch(self, address, type="f32", interval=0.25, duration=0):
        return self.require_target().watch(address, type, float(interval), float(duration))

    def tool_unwatch(self, address):
        return self.require_target().unwatch(address)

    def tool_watch_history(self, address):
        return {"address": address, "history": self.require_target().watch_list(address)}

    def tool_undo(self, id=None, all=False):
        return self.require_target().undo(id, bool(all))

    def tool_journal(self, limit=100, include_undone=True):
        return self.require_target().journal_list(int(limit), include_undone)

    def tool_inject(self, path, call_entry=False, entry_name="DllMain"):
        return self.require_target().inject(path, call_entry, entry_name)

    def tool_exec_shellcode(self, code, timeout=20000):
        return self.require_target().exec_shellcode(code, int(timeout))

    def tool_remote_call(self, module, export, args=None, timeout=15000):
        return {
            "result": hex(self.require_target().remote_call(
                module, export, args or [], int(timeout))),
            "module": module,
            "export": export,
        }

    def tool_patch(self, address, expected=None, replacement="", note=None):
        return self.require_target().patch(address, expected, replacement, note)

    def tool_hook(self, address, replacement, note=None):
        return self.require_target().hook(address, replacement, note)

    def tool_unhook(self, address):
        return self.require_target().unhook(address)

    def tool_hook_list(self):
        return self.require_target().hook_list()

    def tool_runtime(self, refresh=False):
        return self.require_target().managed_runtime(bool(refresh)).status()

    def tool_runtime_exports(self, pattern="", limit=200):
        runtime = self.require_target().managed_runtime()
        return runtime.list_exports(pattern, int(limit))

    def tool_managed_assemblies(self):
        return self.require_target().managed_runtime().assemblies()

    def tool_managed_types(self, assembly, filter="", limit=20000):
        return self.require_target().managed_runtime().types(assembly, filter, int(limit))

    def tool_managed_fields(self, assembly, type):
        return self.require_target().managed_runtime().fields(assembly, type)

    def tool_managed_methods(self, assembly, type):
        return self.require_target().managed_runtime().methods(assembly, type)

    def tool_managed_static(self, assembly, type, field, value_type="f32", size=None):
        return self.require_target().managed_runtime().static_value(
            assembly, type, field, value_type, size
        )

    def tool_managed_call(self, assembly, type, method, argc=0, timeout=20000):
        return self.require_target().managed_runtime().call_method(
            assembly, type, method, int(argc), int(timeout)
        )

    def tool_managed_metadata(self, path=None, filter="", limit=400):
        if not path:
            path = self._find_managed_assembly()
        return managed_core.read_metadata(path, filter, int(limit))

    def _find_managed_assembly(self):
        with self.lock:
            if not self.target:
                raise NoTarget()
            try:
                exe = self.target.proc.image_path()
            except Exception as error:
                raise BridgeError(f"cannot resolve the target path: {error}")
        candidates = []
        root = os.path.dirname(exe)
        parent = os.path.dirname(root)
        for managed_dir in (
            os.path.join(root, "Managed"),
            os.path.join(parent, "Managed"),
            os.path.join(root, "..", "Managed"),
        ):
            normalized = os.path.normpath(managed_dir)
            if not os.path.isdir(normalized):
                continue
            for name in sorted(os.listdir(normalized)):
                if name.lower().endswith(".dll") and name.lower() != "mscorlib.dll":
                    candidates.append(os.path.join(normalized, name))
            if candidates:
                return candidates[0]
        raise BridgeError(
            "no Managed folder found next to the target. Pass an explicit path, "
            "for example the game's *_Data/Managed/Assembly-CSharp.dll."
        )

    def _ce_call(self, command, timeout=60.0, **params):
        """Call the CE agent, turning a failed reply into a bridge error.

        Without this the agent's failure would arrive as ok:true with
        ok:false buried inside the result, which reads like success.
        """
        reply = self.ce.call(command, timeout=timeout, **params)
        if not reply.get("ok"):
            raise BridgeError(reply.get("error") or f"Cheat Engine failed {command!r}")
        return reply.get("result") or {}

    def tool_ce_launch(self, arch="x64", avx=False):
        exe = self.config.ce_exe_for(arch, bool(avx))
        if not exe:
            return {"ok": False, "error": "no Cheat Engine executable found; set ce_exe_64 "
                                          "in config.json"}
        return self.ce.launch(exe, arch, bool(avx))

    def tool_ce_status(self, refresh=False):
        self.ce.hello(bool(refresh))
        return self.ce.status()

    def tool_ce_install(self):
        result = self.ce.install_agent()
        if result.get("ok") and result.get("where") == "local-copy":
            target = result["ce_dir"]
            self.config.data["ce_dir"] = target
            self.config.data["ce_autorun_dir"] = os.path.join(target, "autorun")
            for key, candidate in (
                ("ce_exe_64", "cheatengine-x86_64.exe"),
                ("ce_exe_64_avx", "cheatengine-x86_64-SSE4-AVX2.exe"),
                ("ce_exe_32", "cheatengine-i386.exe"),
            ):
                path = os.path.join(target, candidate)
                if os.path.exists(path):
                    self.config.data[key] = path
            self.config.save()
            result["config_updated"] = self.config.path
        return result

    def tool_ce_mirror(self, items):
        if not self.ce.state.get("agent_seen"):
            raise BridgeError(
                "the Cheat Engine agent is not connected. Start Cheat Engine; if it "
                "is already running, install the agent with ce_ce_install (once, as "
                "administrator) and restart it."
            )
        return self.ce.mirror(items)

    def tool_ce_register_symbol(self, name, address):
        return self._ce_call("register_symbol", name=name, address=address)

    def tool_ce_resolve(self, expression):
        return self._ce_call("resolve", expression=expression)

    def tool_ce_disassemble(self, address, count=12):
        return self._ce_call("disassemble", address=address, count=int(count))

    def tool_ce_autoassemble(self, script):
        return self._ce_call("autoassemble", script=script)

    def tool_ce_message(self, text):
        return self._ce_call("show_message", text=text)

    def tool_ce_addresses(self):
        return self._ce_call("list_addresses")

    def _module_offset(self, target, module, offset):
        info = target.proc.module(module)
        if not info:
            raise BridgeError(f"module {module!r} is not loaded")
        if isinstance(offset, str):
            offset = int(offset, 0)
        return info.base + int(offset or 0)

    def execute(self, tool, params):
        """Run a tool, turning any failure into a readable message."""
        started = time.time()
        try:
            result = self.call(tool, params)
            return {"ok": True, "tool": tool, "result": result,
                    "elapsed_ms": round((time.time() - started) * 1000, 1)}
        except NoTarget as error:
            return {"ok": False, "tool": tool, "error": str(error), "kind": "no_target",
                    "elapsed_ms": round((time.time() - started) * 1000, 1)}
        except BridgeError as error:
            return {"ok": False, "tool": tool, "error": str(error), "kind": "error",
                    "elapsed_ms": round((time.time() - started) * 1000, 1)}
        except PermissionError as error:
            return {"ok": False, "tool": tool, "error": str(error), "kind": "read_only",
                    "elapsed_ms": round((time.time() - started) * 1000, 1)}
        except Exception as error:
            self.log.error("%s failed: %s", tool, error)
            self.log.debug("%s", traceback.format_exc())
            return {"ok": False, "tool": tool, "error": f"{type(error).__name__}: {error}",
                    "kind": "error", "traceback": traceback.format_exc()[-2000:],
                    "elapsed_ms": round((time.time() - started) * 1000, 1)}


TOOLS = (
    "status", "ping", "processes", "attach", "detach", "unlock",
    "read", "read_bytes", "write", "write_bytes", "query", "modules", "memory_map",
    "disasm", "assemble", "assemble_write",
    "scan_start", "scan_next", "scan_results", "scan_reset",
    "aob", "xrefs", "pointer_chains", "resolve_chain",
    "freeze", "unfreeze", "freeze_status", "watch", "unwatch", "watch_history",
    "undo", "journal", "inject", "exec_shellcode", "remote_call", "patch", "hook",
    "unhook", "hook_list",
    "runtime", "runtime_exports", "managed_assemblies", "managed_types", "managed_fields",
    "managed_methods", "managed_static", "managed_call", "managed_metadata",
    "ce_launch", "ce_status", "ce_install", "ce_mirror", "ce_register_symbol",
    "ce_resolve", "ce_disassemble", "ce_autoassemble", "ce_message", "ce_addresses",
)


def _epoch(stamp):
    try:
        return datetime.fromisoformat(stamp).timestamp()
    except Exception:
        return time.time()
