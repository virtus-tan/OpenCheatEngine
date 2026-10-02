"""Target session: the state machine the whole bridge shares.

The human picks the process in Cheat Engine; this object only ever adopts a PID
it was handed. It opens read-only, records every write for undo, and refuses
anything that needs a target while none is attached.
"""

import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone

import psutil

from .core import disasm, inject, managed, scanner, signature, valuetypes as vt
from .core.winapi import ProcessHandle, Win32Error, hexdump, parse_address, parse_bytes

MAX_JOURNAL = 2000
WATCH_HISTORY = 512


class BridgeError(RuntimeError):
    pass


class NoTarget(BridgeError):
    def __init__(self):
        super().__init__(
            "no target attached. Attach the game in Cheat Engine, then the "
            "bridge picks the PID up automatically (or call ce_attach with a pid)."
        )


class ReadOnly(PermissionError):
    def __init__(self):
        super().__init__(
            "the target is read-only. Call ce_unlock(writable=true) to allow "
            "writes; every write is journaled and can be undone."
        )


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def list_processes(filter_text="", include_system=False):
    """Running processes, with the window title when there is one."""
    out = []
    for process in psutil.process_iter(["pid", "name", "exe", "username", "create_time"]):
        try:
            info = process.info
            name = info.get("name") or ""
            if not include_system and not info.get("exe"):
                continue
            title = _window_title(process.pid)
            if filter_text:
                needle = filter_text.lower()
                if needle not in name.lower() and needle not in (title or "").lower() \
                        and needle not in str(info.get("exe") or "").lower():
                    continue
            out.append({
                "pid": process.pid,
                "name": name,
                "exe": info.get("exe"),
                "title": title,
                "user": info.get("username"),
                "started": (datetime.fromtimestamp(info["create_time"], timezone.utc)
                            .isoformat(timespec="seconds") if info.get("create_time") else None),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    out.sort(key=lambda item: (item["name"] or "").lower())
    return {"count": len(out), "processes": out}


def _window_title(pid):
    """Main window title for a pid, via EnumWindows."""
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        found = {}

        callback_type = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
        )

        def callback(hwnd, _lparam):
            owner = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value != pid:
                return True
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            if buffer.value:
                found.setdefault("title", buffer.value)
                found.setdefault("hwnd", hex(hwnd))
            return not found.get("title")

        user32.EnumWindows(callback_type(callback), 0)
        return found.get("title")
    except Exception:
        return None


class WriteRecord:
    __slots__ = ("id", "timestamp", "address", "size", "before", "after", "kind", "note", "undone")

    def __init__(self, address, before, after, kind="write", note=None):
        self.id = uuid.uuid4().hex[:12]
        self.timestamp = _now()
        self.address = address
        self.size = len(before)
        self.before = before
        self.after = after
        self.kind = kind
        self.note = note
        self.undone = False

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "address": hex(self.address),
            "size": self.size,
            "before": self.before.hex(),
            "after": self.after.hex(),
            "kind": self.kind,
            "note": self.note,
            "undone": self.undone,
        }


class Target:
    """An attached process, plus everything the tools do to it."""

    def __init__(self, pid, writable=False, source="manual"):
        self.pid = int(pid)
        self.source = source
        self.attached_at = _now()
        self.proc = ProcessHandle(self.pid, writable)
        self.writable = self.proc.writable
        self.journal = deque(maxlen=MAX_JOURNAL)
        self.scan_session = None
        self.frozen = {}
        self.hooks = []
        self._managed = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._freezer = None
        self._watchers = {}

    def close(self):
        self._stop.set()
        self.unfreeze_all()
        for key in list(self._watchers):
            state, _history = self._watchers.pop(key)
            state["stop"].set()
            thread = state.get("thread")
            if thread and thread.is_alive():
                thread.join(timeout=0.5)
        try:
            self.proc.close()
        except Exception:
            pass

    def _reopen(self, writable):
        """Swap in a new handle, since VM_WRITE is fixed at OpenProcess time."""
        old = self.proc
        fresh = ProcessHandle(self.pid, writable)
        self.proc = fresh
        self.writable = fresh.writable
        if self.scan_session:
            self.scan_session.proc = fresh
        if self._managed:
            self._managed.proc = fresh
        threading.Thread(target=old.close, daemon=True).start()

    def unlock(self, writable=True):
        with self._lock:
            if writable and not self.writable:
                self._reopen(True)
            elif not writable and self.writable:
                self._reopen(False)
            return self.status()

    def require_writable(self):
        if not self.writable:
            raise ReadOnly()
        return True

    def managed_runtime(self, refresh=False):
        with self._lock:
            if self._managed is None or refresh:
                self._managed = managed.ManagedRuntime(self.proc).detect()
            return self._managed

    def status(self):
        try:
            alive = self.proc.alive()
        except Exception:
            alive = False
        path = None
        try:
            path = self.proc.image_path()
        except Exception:
            pass
        return {
            "attached": True,
            "alive": alive,
            "pid": self.pid,
            "name": self.proc.base_name(),
            "path": path,
            "arch": "x64" if self.proc.is_64bit else "x86",
            "pointer_size": self.proc.ptr_size,
            "writable": self.writable,
            "source": self.source,
            "attached_at": self.attached_at,
            "journal_entries": len(self.journal),
            "frozen": len(self.frozen),
            "hooks": len(self.hooks),
            "active_scan": self.scan_session.summary() if self.scan_session else None,
        }

    def _record(self, address, before, after, kind, note=None):
        entry = WriteRecord(address, before, after, kind, note)
        self.journal.append(entry)
        return entry

    def read(self, address, value_type="u32", count=1):
        address = parse_address(address)
        value = vt.read(self.proc, address, value_type, count)
        try:
            region = self.query(address)
        except Exception:
            region = None
        return {
            "address": hex(address),
            "type": vt.normalise(value_type),
            "count": count,
            "value": value,
            "region": region,
        }


    def write(self, address, value, value_type="u32", note=None):
        self.require_writable()
        address = parse_address(address)
        normalised = vt.normalise(value_type)
        size = vt.size_of(normalised, self.proc.ptr_size)
        if size == 0:
            raise BridgeError(f"type {normalised} has no fixed size; use write_bytes")
        before = self.proc.read_exact(address, size)
        result = vt.write(self.proc, address, normalised, value)
        entry = self._record(address, before, parse_bytes(result["raw"]), "write", note)
        result["value"] = value
        result["undo_id"] = entry.id
        result["before"] = before.hex()
        return result

    def write_bytes(self, address, data, note=None):
        self.require_writable()
        address = parse_address(address)
        payload = parse_bytes(data)
        before = self.proc.read_exact(address, len(payload))
        self.proc.write(address, payload)
        entry = self._record(address, before, payload, "write_bytes", note)
        return {
            "address": hex(address),
            "bytes": len(payload),
            "value": payload.hex(),
            "before": before.hex(),
            "undo_id": entry.id,
        }

    def read_bytes(self, address, size, hexdump_output=True):
        address = parse_address(address)
        raw = self.proc.read_exact(address, size)
        return {
            "address": hex(address),
            "size": size,
            "hex": raw.hex(),
            "dump": hexdump(raw, address) if hexdump_output else None,
        }

    def query(self, address):
        address = parse_address(address)
        owner = self.proc.module_containing(address)
        region = self.proc.region_at(address)
        region["module"] = owner.name if owner else None
        region["module_offset"] = hex(address - owner.base) if owner else None
        return region

    def modules(self, filter_text=""):
        modules = [module.to_dict() for module in self.proc.modules(refresh=True)]
        if filter_text:
            needle = filter_text.lower()
            modules = [item for item in modules if needle in item["name"].lower()]
        return {"count": len(modules), "modules": modules}

    def memory_map(self, writable_only=False, executable_only=False, committed_only=True):
        regions = self.proc.memory_map()
        if committed_only:
            regions = [item for item in regions if item["state"] == "COMMIT"]
        if writable_only:
            regions = [item for item in regions if item["writable"]]
        if executable_only:
            regions = [item for item in regions if item["executable"]]
        total = sum(item["size"] for item in regions)
        return {
            "count": len(regions),
            "total_bytes": total,
            "total_mb": round(total / (1024 * 1024), 2),
            "regions": regions,
        }

    def disasm(self, address, count=16, module=None, follow_thunk=True):
        if module:
            info = self.proc.module(module)
            if not info:
                raise BridgeError(f"module {module!r} is not loaded")
            start = info.base + int(address, 0) if isinstance(address, str) else address
        else:
            start = parse_address(address)
        hops = []
        if follow_thunk:
            start, hops = disasm.resolve_thunk(self.proc, start)
        instructions = disasm.disassemble_at(self.proc, start, count)
        owner = self.proc.module_containing(start)
        return {
            "address": hex(start),
            "requested": hex(parse_address(address)),
            "thunk_hops": hops,
            "module": owner.name if owner else None,
            "module_offset": hex(start - owner.base) if owner else None,
            "count": len(instructions),
            "text": disasm.format_block(instructions),
            "instructions": instructions,
        }

    def assemble(self, text, address=0):
        """Assemble to bytes without touching the target, so it works read-only."""
        target_address = parse_address(address) if address else 0
        payload, count = disasm.assemble(text, target_address, self.proc.is_64bit)
        return {
            "asm": text,
            "address": hex(target_address),
            "bytes": payload.hex(),
            "count": count,
        }

    def assemble_write(self, text, address, note=None):
        self.require_writable()
        address = parse_address(address)
        payload, _count = disasm.assemble(text, address, self.proc.is_64bit)
        before = self.proc.read_exact(address, len(payload))
        self.proc.write(address, payload)
        entry = self._record(address, before, payload, "assemble", note)
        return {
            "address": hex(address),
            "bytes": payload.hex(),
            "before": before.hex(),
            "undo_id": entry.id,
        }

    def scan_start(self, value_type="u32", scan_type="unknown_initial", value=None,
                   alignment=1, module=None, region_type=None, writable_only=True,
                   executable_only=False, start=0, end=0, max_results=scanner.MAX_RESULTS,
                   struct=None, values=None, tolerance=0.0):
        options = scanner.ScanOptions(
            value_type=vt.normalise(value_type) if value_type != "array" else "array",
            alignment=alignment,
            writable_only=writable_only,
            executable_only=executable_only,
            module=module,
            region_type=region_type,
            start=parse_address(start) if start else 0,
            end=parse_address(end) if end else 0,
            max_results=max_results,
        )
        if struct:
            options.struct = vt.parse_struct(struct)
        if values:
            options.values = values
        session = scanner.ScanSession(self.proc, options)
        count = session.start(scan_type, value, tolerance)
        self.scan_session = session
        return {"results": count, **session.summary()}

    def scan_next(self, scan_type, value=None, tolerance=0.0):
        if not self.scan_session:
            raise scanner.NoScanSession("no active scan; call scan_start first")
        count = self.scan_session.next(scan_type, value, tolerance)
        return {"results": count, **self.scan_session.summary()}

    def scan_results(self, offset=0, limit=scanner.RESULT_PAGE, group=False, with_values=True):
        if not self.scan_session:
            raise scanner.NoScanSession("no active scan; call scan_start first")
        return self.scan_session.results(offset, limit, group, with_values)

    def scan_reset(self):
        self.scan_session = None
        return {"active_scan": None}

    def aob(self, pattern, module=None, max_hits=256, require_unique=False):
        return signature.aob(self.proc, pattern, module, max_hits, require_unique)

    def xrefs(self, address, code_only=True, max_hits=256):
        return signature.xrefs_to(self.proc, parse_address(address), code_only, True, max_hits)

    def pointer_chains(self, address, depth=signature.MAX_CHAIN_DEPTH, max_results=32,
                      module=None, writable_only=True):
        return signature.find_pointer_chains(
            self.proc, parse_address(address), depth, max_results, writable_only, module
        )

    def resolve_chain(self, chain, final_offset=0):
        return signature.resolve_chain(
            self.proc, [parse_address(item) for item in chain], parse_address(final_offset)
        )

    def freeze(self, address, value, value_type="f32", interval=0.1):
        self.require_writable()
        address = parse_address(address)
        normalised = vt.normalise(value_type)
        self.frozen[address] = {
            "address": hex(address),
            "value": value,
            "type": normalised,
            "interval": max(float(interval), 0.01),
            "writes": 0,
        }
        self._ensure_freezer()
        return self.freeze_status()

    def unfreeze(self, address):
        key = parse_address(address)
        removed = self.frozen.pop(key, None)
        return {"removed": removed, **self.freeze_status()}

    def unfreeze_all(self):
        count = len(self.frozen)
        self.frozen.clear()
        return {"removed": count, **self.freeze_status()}

    def freeze_status(self):
        return {
            "frozen": list(self.frozen.values()),
            "count": len(self.frozen),
        }

    def _ensure_freezer(self):
        if self._freezer and self._freezer.is_alive():
            return
        self._stop.clear()

        def loop():
            while not self._stop.is_set() and self.frozen:
                time.sleep(0.02)
                for address, entry in list(self.frozen.items()):
                    try:
                        vt.write(self.proc, address, entry["type"], entry["value"])
                        entry["writes"] += 1
                    except Exception:
                        self.frozen.pop(address, None)
            self._stop.set()

        self._freezer = threading.Thread(target=loop, daemon=True)
        self._freezer.start()

    def watch(self, address, value_type="f32", interval=0.25, duration=0):
        """Sample a value over time and keep a change timeline.

        Non-invasive, so it is safe against a live game. Pair it with xrefs to
        find the code that writes the value.
        """
        address = parse_address(address)
        key = f"{address:x}"
        if key in self._watchers:
            existing = self._watchers[key]
            return {"already_watching": hex(address), "history": list(existing[1])[-32:]}
        normalised = vt.normalise(value_type)
        history = deque(maxlen=WATCH_HISTORY)
        stop = threading.Event()
        state = {"stop": stop, "started": _now(), "type": normalised}
        self._watchers[key] = (state, history)

        def loop():
            deadline = time.time() + duration if duration else None
            while not stop.is_set() and self.proc.alive():
                try:
                    history.append({"t": round(time.time(), 3),
                                    "value": vt.read(self.proc, address, normalised)})
                except Exception:
                    break
                if deadline and time.time() > deadline:
                    break
                time.sleep(max(float(interval), 0.02))

        thread = threading.Thread(target=loop, daemon=True)
        state["thread"] = thread
        thread.start()
        return {"watching": hex(address), "type": normalised, "interval": interval}

    def unwatch(self, address):
        key = f"{parse_address(address):x}"
        entry = self._watchers.pop(key, None)
        if not entry:
            return {"watching": None}
        entry[0]["stop"].set()
        return {"stopped": hex(address), "history": list(entry[1])}

    def watch_list(self, address):
        entry = self._watchers.get(f"{parse_address(address):x}")
        return list(entry[1]) if entry else []

    def undo(self, undo_id=None, all_entries=False):
        self.require_writable()
        results = []
        if all_entries:
            targets = [item for item in self.journal if not item.undone]
        else:
            targets = [item for item in self.journal
                       if item.id == undo_id and not item.undone]
            if not targets and undo_id:
                raise BridgeError(f"no undoable write with id {undo_id!r}")
        for item in reversed(targets):
            self.proc.write(item.address, item.before)
            item.undone = True
            results.append({"id": item.id, "address": hex(item.address),
                            "restored": item.before.hex()})
        return {"undone": len(results), "entries": results}

    def journal_list(self, limit=100, include_undone=True):
        items = [item.to_dict() for item in self.journal]
        if not include_undone:
            items = [item for item in items if not item["undone"]]
        items.reverse()
        return {"count": len(items), "entries": items[:limit]}

    def inject(self, path, call_entry=False, entry_name="DllMain"):
        self.require_writable()
        return inject.inject_dll(self.proc, path, call_entry, entry_name)

    def exec_shellcode(self, code, timeout=20000):
        self.require_writable()
        return inject.exec_shellcode(self.proc, code, timeout)

    def remote_call(self, module, export, args=(), timeout=15000):
        """Call an exported function inside the target and return its result.

        The cheapest end to end proof that the call stub is correct: call
        GetCurrentProcessId and check the answer is the target's own pid.
        """
        self.require_writable()
        return inject.remote_call(self.proc, module, export, list(args), timeout)

    def patch(self, address, expected, replacement, note=None):
        self.require_writable()
        address = parse_address(address)
        result = inject.patch(self.proc, address, expected, replacement)
        before = parse_bytes(result["before"])
        after = parse_bytes(result["after"])
        entry = self._record(address, before, after, "patch", note)
        result["undo_id"] = entry.id
        return result

    def hook(self, address, replacement_address, note=None):
        self.require_writable()
        entry = inject.hook(self.proc, address, replacement_address)
        self.hooks.append(entry)
        return entry

    def unhook(self, address):
        self.require_writable()
        key = parse_address(address)
        for index, entry in enumerate(self.hooks):
            if parse_address(entry["address"]) == key:
                self.hooks.pop(index)
                return inject.unhook(self.proc, entry)
        raise BridgeError(f"no hook recorded at {hex(key)}")

    def hook_list(self):
        return {"hooks": list(self.hooks), "count": len(self.hooks)}
