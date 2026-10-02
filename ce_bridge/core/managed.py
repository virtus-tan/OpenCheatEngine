"""Managed runtime support: metadata from disk, and live Mono/IL2CPP calls.

Two independent halves, because either alone is not enough:

- metadata comes from the managed assembly on disk, so it works even when the
  target is packed, stripped, or the runtime exports are missing. This is how
  you get exact type, field and method names.
- values and offsets come from calling the live runtime, which is the only way
  to see what the game actually loaded.

Unsupported combinations report themselves instead of returning a guess.
"""

import os
import re

from . import pe

try:
    import dnfile
    HAVE_DNFILE = True
except ImportError:
    HAVE_DNFILE = False

MONO_MARKERS = ("mono_domain_get", "mono_image_get_name", "mono_assembly_get_image")
IL2CPP_MARKERS = ("il2cpp_domain_get", "il2cpp_image_get_name", "il2cpp_assembly_get_image")

CAPABILITIES = {
    "mono": ["assemblies", "types", "fields", "methods", "call_method", "metadata"],
    "il2cpp": [
        "assemblies", "types", "fields", "methods", "call_method",
        "field_offset", "static_value", "metadata",
    ],
    "native": ["metadata"],
}

MAX_TYPES = 20000
MAX_FIELDS = 400
MAX_METHODS = 400


class ManagedError(RuntimeError):
    pass


class ManagedRuntime:
    """Detects the managed runtime and exposes its entry points."""

    def __init__(self, proc):
        self.proc = proc
        self.kind = "native"
        self.module = None
        self.exports = {}
        self._export_source = None

    def detect(self):
        candidates = []
        for module in self.proc.modules():
            path = module.path
            if not path or not os.path.exists(path):
                continue
            if "GameAssembly" in module.name or "il2cpp" in module.name.lower():
                candidates.append(module)
        for module in self.proc.modules():
            if module in candidates:
                continue
            if module.name.lower().startswith("mono-") or "monosgen" in module.name.lower():
                candidates.insert(0, module)
        if not candidates:
            main = self.proc.modules()
            if main:
                candidates.append(main[0])

        for module in candidates:
            try:
                table = pe.cached_exports(module.path)
            except Exception:
                continue
            if not table:
                continue
            if any(marker in table for marker in IL2CPP_MARKERS):
                self.kind = "il2cpp"
                self.module = module
                self.exports = table
                self._export_source = "exports"
                return self
            if any(marker in table for marker in MONO_MARKERS):
                self.kind = "mono"
                self.module = module
                self.exports = table
                self._export_source = "exports"
                return self

        for module in self.proc.modules():
            name = module.name.lower()
            if "gameassembly" in name:
                self.kind = "il2cpp"
                self.module = module
                self.exports = {}
                self._export_source = "name"
                return self
            if name.startswith("mono-") or "monosgen" in name:
                self.kind = "mono"
                self.module = module
                self.exports = {}
                self._export_source = "name"
                return self
        return self

    def status(self):
        return {
            "kind": self.kind,
            "module": self.module.name if self.module else None,
            "module_path": self.module.path if self.module else None,
            "module_base": hex(self.module.base) if self.module else None,
            "export_source": self._export_source,
            "capabilities": CAPABILITIES.get(self.kind, []),
            "has_file_metadata": self._find_managed_dir() is not None,
            "note": (
                "No managed runtime found. If this is a Unity Mono build the "
                "mono exports may be static inside the exe; check the loaded "
                "modules for mono-2.0-bdwgc.dll."
            ) if self.kind == "native" else None,
        }

    def _find_managed_dir(self):
        try:
            exe = self.proc.image_path()
        except Exception:
            return None
        root = os.path.dirname(exe)
        for relative in ("Managed", os.path.join(os.path.dirname(root), "Managed")):
            candidate = os.path.join(root, relative)
            if os.path.isdir(candidate):
                return candidate
        return None

    def require(self, kind):
        if self.kind != kind:
            raise ManagedError(
                f"this target is {self.kind}, not {kind}; "
                f"available: {', '.join(CAPABILITIES.get(self.kind, [])) or 'nothing'}"
            )
        if self.kind != "native" and not self.exports:
            raise ManagedError(
                f"no {kind} exports were found in {self.module.name if self.module else 'the target'}. "
                "The runtime may be present with a static (non-exported) build."
            )

    def addr(self, name):
        """Resolve an export name to a target address, with common fallbacks."""
        rva = self.exports.get(name)
        if rva is None:
            lowered = name.lower()
            for candidate, value in self.exports.items():
                if candidate.lower() == lowered:
                    rva = value
                    break
        if rva is None:
            for candidate, value in self.exports.items():
                if lowered in candidate.lower():
                    rva = value
                    break
        if rva is None:
            raise ManagedError(
                f"export {name} not found"
                + (f" in {self.module.name}" if self.module else "")
                + ". Use list_exports to see what this build exposes."
            )
        return self.module.base + rva

    def call(self, name, args=(), timeout=15000):
        return self.proc.remote_call_n(self.addr(name), list(args), timeout=timeout)

    def list_exports(self, pattern="", limit=200):
        table = self.exports
        if pattern:
            lowered = pattern.lower()
            table = {name: rva for name, rva in table.items() if lowered in name.lower()}
        items = sorted(table.items())[:limit]
        base = self.module.base if self.module else 0
        return {
            "count": len(table),
            "exports": [
                {"name": name, "rva": hex(rva), "address": hex(base + rva)}
                for name, rva in items
            ],
        }

    def scratch(self, size):
        address = self.proc.alloc(size)
        self.proc.write(address, b"\x00" * size)
        return address

    def cstr(self, address, limit=512):
        return self.proc.read_cstr(address, limit)

    def assemblies(self, limit=512):
        self.require("mono" if self.kind == "mono" else "il2cpp")
        mono = self.kind == "mono"
        if mono:
            domain = self.call("mono_domain_get")
            count_at = self.scratch(4)
            array = self.call("mono_domain_get_assemblies", [domain, count_at])
        else:
            domain = self.call("il2cpp_domain_get")
            count_at = self.scratch(8)
            array = self.call("il2cpp_domain_get_assemblies", [domain, count_at])

        if not array:
            raise ManagedError(
                "the runtime returned no assembly list. The game may still be "
                "loading, or the runtime may not be initialised yet."
            )
        count = int.from_bytes(self.proc.read(count_at, 4 if mono else 8), "little")
        count = min(count, limit)
        out = []
        for index in range(count):
            entry = self.proc.read_exact(array + index * self.proc.ptr_size, self.proc.ptr_size)
            assembly = int.from_bytes(entry, "little")
            if not assembly:
                continue
            try:
                if mono:
                    size_at = self.scratch(4)
                    image = self.call("mono_assembly_get_image", [assembly, size_at])
                else:
                    image = self.call("il2cpp_assembly_get_image", [assembly])
                name_address = self.call("mono_image_get_name" if mono else "il2cpp_image_get_name",
                                         [image])
                out.append({
                    "name": self.cstr(name_address) if name_address else "?",
                    "assembly": hex(assembly),
                    "image": hex(image),
                })
            except Exception as error:
                out.append({"name": f"<entry {index}: {error}>", "assembly": hex(assembly)})
        return {"count": len(out), "assemblies": out}

    def find_image(self, assembly_name):
        wanted = assembly_name.lower()
        for entry in self.assemblies()["assemblies"]:
            if entry["name"].lower() == wanted:
                return int(entry["image"], 16)
            if os.path.splitext(entry["name"].lower())[0] == os.path.splitext(wanted)[0]:
                return int(entry["image"], 16)
        available = ", ".join(entry["name"] for entry in self.assemblies()["assemblies"][:20])
        raise ManagedError(f"assembly {assembly_name!r} is not loaded. Loaded: {available}")

    def types(self, assembly, name_filter="", limit=MAX_TYPES):
        self.require("mono" if self.kind == "mono" else "il2cpp")
        image = self.find_image(assembly) if isinstance(assembly, str) else int(assembly)
        namer = "mono_class_get_next" if self.kind == "mono" else "il2cpp_class_get_next"
        namefn = "mono_class_get_name" if self.kind == "mono" else "il2cpp_class_get_name"
        nsfnexpr = ("mono_class_get_namespace" if self.kind == "mono"
                    else "il2cpp_class_get_namespace")
        pattern = re.compile(name_filter, re.IGNORECASE) if name_filter else None

        out = []
        handle = 0
        while len(out) < limit:
            handle = self.call(namer, [handle])
            if not handle:
                break
            try:
                name_ptr = self.call(namefn, [handle])
                name = self.cstr(name_ptr) if name_ptr else "?"
                if pattern and not pattern.search(name):
                    continue
                namespace_ptr = self.call(nsfnexpr, [handle])
                namespace = self.cstr(namespace_ptr) if namespace_ptr else ""
                out.append({
                    "name": name,
                    "namespace": namespace,
                    "full_name": f"{namespace}.{name}" if namespace else name,
                    "class": hex(handle),
                })
            except Exception:
                continue
        return {"assembly": assembly, "count": len(out), "types": out}

    def _class_handle(self, assembly, type_name):
        image = self.find_image(assembly)
        namespace, _, bare = type_name.rpartition(".")
        entry = ("mono_class_from_name" if self.kind == "mono"
                 else "il2cpp_class_from_name")
        with self.proc.with_strings([namespace, bare]) as pointers:
            return self.call(entry, [image, pointers[0], pointers[1]])


    def fields(self, assembly, type_name, limit=MAX_FIELDS):
        handle = self._class_handle(assembly, type_name)
        if not handle:
            available = [item["full_name"] for item in self.types(assembly, type_name)["types"]]
            raise ManagedError(
                f"type {type_name!r} not found in {assembly}"
                + (f". Similar: {', '.join(available[:10])}" if available else "")
            )
        mono = self.kind == "mono"
        iter_at = self.scratch(self.proc.ptr_size)
        self.proc.write(iter_at, b"\x00" * self.proc.ptr_size)
        namefn = "mono_field_get_name" if mono else "il2cpp_field_get_name"
        flagsfn = "mono_field_get_flags" if mono else "il2cpp_field_get_flags"

        out = []
        while len(out) < limit:
            field = self.call("mono_class_get_fields" if mono else "il2cpp_class_get_fields",
                              [handle, iter_at])
            if not field:
                break
            name_ptr = self.call(namefn, [field])
            try:
                flags = self.call(flagsfn, [field])
            except Exception:
                flags = 0
            static = bool(flags & (0x0010 if mono else 0x0010))
            entry = {
                "name": self.cstr(name_ptr) if name_ptr else "?",
                "field": hex(field),
                "static": static,
                "flags": hex(flags),
            }
            if not mono and not static:
                try:
                    offset = self.call("il2cpp_field_get_offset", [field])
                    entry["offset"] = hex(offset)
                except Exception:
                    pass
            out.append(entry)
        return {"type": type_name, "count": len(out), "fields": out}

    def methods(self, assembly, type_name, limit=MAX_METHODS):
        handle = self._class_handle(assembly, type_name)
        if not handle:
            raise ManagedError(f"type {type_name!r} not found in {assembly}")
        mono = self.kind == "mono"
        iter_at = self.scratch(self.proc.ptr_size)
        self.proc.write(iter_at, b"\x00" * self.proc.ptr_size)
        namefn = "mono_method_get_name" if mono else "il2cpp_method_get_name"
        out = []
        while len(out) < limit:
            method = self.call("mono_class_get_methods" if mono else "il2cpp_class_get_methods",
                               [handle, iter_at])
            if not method:
                break
            name_ptr = self.call(namefn, [method])
            entry = {"name": self.cstr(name_ptr) if name_ptr else "?", "method": hex(method)}
            try:
                count = self.call("mono_method_get_param_count" if mono
                                  else "il2cpp_method_get_param_count", [method])
                entry["parameters"] = count
            except Exception:
                pass
            out.append(entry)
        return {"type": type_name, "count": len(out), "methods": out}

    def static_value(self, assembly, type_name, field_name, value_type="f32", size=None):
        if self.kind != "il2cpp":
            raise ManagedError(
                f"reading a live static value needs il2cpp_field_static_get_value, "
                f"which this {self.kind} build does not expose. Use metadata "
                "(read_metadata) for names and offsets instead."
            )
        handle = self._class_handle(assembly, type_name)
        if not handle:
            raise ManagedError(f"type {type_name!r} not found in {assembly}")
        with self.proc.with_strings([field_name]) as pointers:
            field = self.call("il2cpp_class_get_field_from_name", [handle, pointers[0]])
        if not field:
            raise ManagedError(f"field {field_name!r} not found on {type_name}")
        width = size or 8
        buffer = self.scratch(width)
        self.call("il2cpp_field_static_get_value", [field, buffer])
        raw = self.proc.read_exact(buffer, width)
        from . import valuetypes as vt
        return {
            "assembly": assembly, "type": type_name, "field": field_name,
            "raw": raw.hex(),
            "value": vt._decode(value_type, raw[:vt.size_of(value_type, self.proc.ptr_size)] or raw),
            "value_type": value_type,
        }

    def call_method(self, assembly, type_name, method_name, arg_count=0, timeout=20000):
        if self.kind not in ("mono", "il2cpp"):
            raise ManagedError("method invocation needs a managed runtime")
        handle = self._class_handle(assembly, type_name)
        if not handle:
            raise ManagedError(f"type {type_name!r} not found in {assembly}")
        mono = self.kind == "mono"
        with self.proc.with_strings([method_name]) as pointers:
            method = self.call("mono_class_get_method_from_name" if mono
                               else "il2cpp_class_get_method_from_name", [
                handle, pointers[0], int(arg_count)
            ])
        if not method:
            raise ManagedError(f"method {method_name!r} not found on {type_name}")
        params = self.scratch(self.proc.ptr_size)
        self.proc.write(params, b"\x00" * self.proc.ptr_size)
        exception = self.scratch(self.proc.ptr_size)
        self.proc.write(exception, b"\x00" * self.proc.ptr_size)
        invoke = "mono_runtime_invoke" if mono else "il2cpp_runtime_invoke"
        result = self.call(invoke, [method, 0, params, exception], timeout=timeout)
        raised = int.from_bytes(self.proc.read(exception, self.proc.ptr_size), "little")
        return {
            "assembly": assembly, "type": type_name, "method": method_name,
            "result": hex(result),
            "exception": hex(raised) if raised else None,
        }


def _owned_rows(row, attr, pool, typedef_rows, index):
    """The rows a typedef owns for one of its list columns.

    dnfile 0.16 and earlier expose FieldList/MethodList as an MDTableIndex
    holding the row index into a flat table, so a type's members run from its
    own index to the next type's. dnfile 0.18+ resolves the list into actual
    row objects instead, so the two shapes have to be told apart.
    """
    value = getattr(row, attr, None)
    if value is None:
        return []
    if isinstance(value, list):
        return [item.row for item in value if getattr(item, "row", None) is not None]
    start = int(value.row_index) - 1
    end = len(pool)
    if index + 1 < len(typedef_rows):
        nxt = getattr(typedef_rows[index + 1], attr, None)
        if nxt is not None:
            end = int(nxt.row_index) - 1
    return pool[start:end]


def read_metadata(path, type_filter="", limit=400):
    """List types, fields and methods straight from the assembly on disk.

    Needs no target access, so it works on any Unity game the moment you point
    it at <Game>_Data/Managed/Assembly-CSharp.dll.
    """
    if not HAVE_DNFILE:
        raise ManagedError(
            "dnfile is not installed; run: pip install dnfile. It is what turns "
            "Assembly-CSharp.dll into a readable list of classes and fields."
        )
    if not os.path.exists(path):
        raise ManagedError(f"assembly not found: {path}")
    try:
        module = dnfile.dnPE(path)
    except Exception as error:
        raise ManagedError(f"cannot read {os.path.basename(path)}: {error}")

    tables = getattr(module, "net", None)
    if tables is None or getattr(tables, "mdtables", None) is None:
        raise ManagedError(
            f"{os.path.basename(path)} is not a .NET assembly, so it has no managed "
            "types. Point this at a managed DLL such as Assembly-CSharp.dll, or use "
            "runtime_metadata to read the live runtime instead."
        )
    tables = tables.mdtables
    if not getattr(tables, "TypeDef", None):
        raise ManagedError(
            f"{os.path.basename(path)} has no TypeDef table. If it is an IL2CPP "
            "game the managed code is compiled into GameAssembly.dll, so use "
            "runtime_metadata on the loaded assemblies instead."
        )
    typedef_rows = list(getattr(tables.TypeDef, "rows", []) or [])
    field_rows = list(getattr(tables.Field, "rows", []) or [])
    method_rows = list(getattr(tables.MethodDef, "rows", []) or [])

    pattern = re.compile(type_filter, re.IGNORECASE) if type_filter else None

    out = []
    for index, row in enumerate(typedef_rows):
        name = str(row.TypeName or "")
        namespace = str(row.TypeNamespace or "")
        full = f"{namespace}.{name}" if namespace else name
        if pattern and not pattern.search(full):
            continue
        fields = _owned_rows(row, "FieldList", field_rows, typedef_rows, index)
        methods = _owned_rows(row, "MethodList", method_rows, typedef_rows, index)
        out.append({
            "full_name": full,
            "namespace": namespace,
            "name": name,
            "fields": [str(item.Name or "") for item in fields],
            "methods": [str(item.Name or "") for item in methods],
        })
        if len(out) >= limit:
            break
    return {
        "path": path,
        "assembly": os.path.basename(path),
        "types": len(typedef_rows),
        "filtered": len(out),
        "truncated": len(out) >= limit,
        "result": out,
    }
