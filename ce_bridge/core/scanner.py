"""The scan engine: a stateful narrowing search over the target's memory.

A session keeps, for every candidate, both its address and the bytes it held
when it was found. That is what makes changed/unchanged/increased/decreased
possible without re-reading the whole address space each pass.
"""

import re
from array import array

from . import valuetypes as vt

SCAN_TYPES = (
    "exact",
    "unknown_initial",
    "unknown_previous",
    "changed",
    "unchanged",
    "increased",
    "decreased",
    "fuzzy",
)

CHUNK = 1 << 20
MAX_RESULTS = 4_000_000
RESULT_PAGE = 500


class ScanError(RuntimeError):
    pass


class NoScanSession(ScanError):
    pass


class ScanOptions:
    __slots__ = (
        "value_type", "alignment", "writable_only", "executable_only",
        "module", "region_type", "skip_unnamed_modules", "skip_noaccess",
        "start", "end", "max_results", "struct", "values", "value_bytes", "element_size",
    )

    def __init__(self, **kwargs):
        self.value_type = "u32"
        self.alignment = 1
        self.writable_only = True
        self.executable_only = False
        self.module = None
        self.region_type = None
        self.skip_unnamed_modules = True
        self.skip_noaccess = True
        self.start = 0
        self.end = 0
        self.max_results = MAX_RESULTS
        self.struct = None
        self.values = None
        self.value_bytes = b""
        self.element_size = 0
        for key, value in kwargs.items():
            if key not in self.__slots__:
                raise ScanError(f"unknown scan option {key!r}")
            setattr(self, key, value)

    def to_dict(self):
        return {
            "value_type": self.value_type,
            "alignment": self.alignment,
            "writable_only": self.writable_only,
            "executable_only": self.executable_only,
            "module": self.module,
            "region_type": self.region_type,
            "start": hex(self.start),
            "end": hex(self.end) if self.end else None,
            "max_results": self.max_results,
        }


class ScanSession:
    """One narrowing search. Start it, then narrow it with next()."""

    def __init__(self, proc, options):
        self.proc = proc
        self.options = options
        self.value_type = options.value_type
        self.value_size = len(options.value_bytes) or vt.size_of(options.value_type, proc.ptr_size)
        self.element_size = options.element_size or self.value_size
        self.count = 0
        self.scanned_bytes = 0
        self.regions_scanned = 0
        self.truncated = False
        self.pass_number = 0
        self.history = []
        self.addresses = array("Q")
        self.original = bytearray()

    def _region_allowed(self, region):
        options = self.options
        if region["state"] != "COMMIT":
            return False
        if options.skip_noaccess and region["protect"] == "---":
            return False
        if options.writable_only and not region["writable"]:
            return False
        if options.executable_only and not region["executable"]:
            return False
        if options.region_type and region["type"] != options.region_type:
            return False
        return True

    def _module_bounds(self):
        if not self.options.module:
            return None
        module = self.proc.module(self.options.module)
        if not module:
            raise ScanError(
                f"module {self.options.module!r} is not loaded; "
                f"loaded modules: {', '.join(m.name for m in self.proc.modules()[:20])}"
            )
        return module.base, module.base + (module.size or 0)

    def start(self, scan_type="unknown_initial", value=None, tolerance=0.0):
        """First pass. Returns the hit count."""
        if scan_type not in SCAN_TYPES:
            raise ScanError(f"unknown scan type {scan_type!r}; expected one of {', '.join(SCAN_TYPES)}")
        self.pass_number = 1
        self._prepare(value, scan_type)
        self.addresses = array("Q")
        self.original = bytearray()

        module_bounds = self._module_bounds()
        limit = self.options.end or (1 << 47 if self.proc.is_64bit else 1 << 31)
        target = self.options.value_bytes
        align = max(1, self.options.alignment)

        for region in self.proc.memory_map(self.options.start, 0):
            if region["base"] == limit:
                break
            if not self._region_allowed(region):
                continue
            base = int(region["base"], 16)
            size = region["size"]
            if module_bounds:
                low, high = module_bounds
                if base + size <= low or base >= high:
                    continue
                start = max(base, low)
                end = min(base + size, high)
                base, size = start, end - start
            if not size:
                continue
            if scan_type == "unknown_initial":
                self._collect_all(base, size, align, module_bounds)
            else:
                self._collect_exact(base, size, align, target, module_bounds)
            self.regions_scanned += 1
            self.scanned_bytes += size
            if self.count >= self.options.max_results:
                self.truncated = True
                break

        if not self.addresses:
            raise ScanError(
                "no matches. Widen the region filter: try writable_only=false, "
                "executable_only=true, or a specific module name."
            )
        self.history.append({
            "pass": self.pass_number,
            "scan_type": scan_type,
            "value": self._display(value) if value is not None else None,
            "results": self.count,
        })
        return self.count

    def _prepare(self, value, scan_type="exact"):
        options = self.options
        if options.value_type == "array":
            if not options.struct or not options.values:
                raise ScanError("array scans need both a struct spec and a list of values")
            options.value_bytes = b"".join(
                vt._encode(field["type"], options.values[field["name"]], self.proc.ptr_size)
                for field in options.struct
            )
            options.element_size = len(options.value_bytes)
            return
        if scan_type == "unknown_initial":
            options.value_bytes = b""
            return
        if value is None:
            raise ScanError(
                f"scan type {scan_type!r} needs a value for {options.value_type}"
            )
        if options.value_type == "bytes":
            from .winapi import parse_bytes
            options.value_bytes = parse_bytes(value)
            return
        options.value_bytes = vt._encode(options.value_type, value, self.proc.ptr_size)

    def _collect_all(self, base, size, align, module_bounds):
        step = self.element_size
        limit = self.options.max_results
        origin = module_bounds[0] if module_bounds else base
        for offset in range(0, max(size - step + 1, 0), align):
            if (offset + base - origin) % align:
                continue
            if self.count >= limit:
                self.truncated = True
                return
            self.addresses.append(base + offset)
            self.original += b"\x00" * step
            self.count += 1

    def _collect_exact(self, base, size, align, target, module_bounds):
        origin = module_bounds[0] if module_bounds else base
        limit = self.options.max_results
        overlap = len(target) - 1
        cursor = 0
        while cursor < size:
            window = self.proc.read(base + cursor, min(CHUNK, size - cursor) + overlap, partial=True)
            if not window:
                break
            position = window.find(target)
            while position != -1:
                if position < size and (position - origin) % align == 0:
                    if self.count >= limit:
                        self.truncated = True
                        return
                    self.addresses.append(base + cursor + position)
                    self.original += target
                    self.count += 1
                position = window.find(target, position + 1)
            if len(window) <= overlap:
                break
            cursor += CHUNK

    def next(self, scan_type, value=None, tolerance=0.0):
        """Narrow the current result set. Returns the new hit count."""
        if not self.addresses:
            raise NoScanSession("no active scan; call scan start first")
        if scan_type == "unknown_previous":
            return self.count
        if scan_type not in SCAN_TYPES:
            raise ScanError(f"unknown scan type {scan_type!r}; expected one of {', '.join(SCAN_TYPES)}")

        self.pass_number += 1
        if scan_type in ("exact", "fuzzy"):
            self._prepare(value, scan_type)
        target = self.options.value_bytes
        step = self.element_size
        source = bytes(self.original)

        keep_addresses = array("Q")
        keep_original = bytearray()
        count = 0

        for index, address in enumerate(self.addresses):
            current = self.proc.read(address, step, partial=True)
            if not current:
                continue
            previous = source[index * step:(index + 1) * step]
            if scan_type == "exact":
                matched = current == target
            elif scan_type == "unknown_initial":
                matched = True
            elif scan_type == "changed":
                matched = current != previous
            elif scan_type == "unchanged":
                matched = current == previous
            else:
                matched = self._compare(scan_type, current, previous, target, tolerance)
            if matched:
                keep_addresses.append(address)
                # The new baseline is what this pass saw, not what the previous
                # pass saw. Storing the old value here would make every later
                # comparison run against the wrong snapshot.
                keep_original += current.ljust(step, b"\x00")
                count += 1
                if count >= self.options.max_results:
                    self.truncated = True
                    break

        self.addresses = keep_addresses
        self.original = keep_original
        self.count = count
        self.history.append({
            "pass": self.pass_number,
            "scan_type": scan_type,
            "value": self._display(value) if value is not None else None,
            "results": self.count,
        })
        if not self.count:
            raise ScanError(
                f"scan narrowed to zero results (pass {self.pass_number}: {scan_type}). "
                "Start over with a wider region filter or a different first value."
            )
        return self.count

    def _compare(self, scan_type, current, previous, target, tolerance):
        if self.value_type == "bytes" or self.options.value_type == "array":
            if scan_type == "increased":
                return current > previous
            if scan_type == "decreased":
                return current < previous
            if scan_type == "fuzzy":
                return _bytes_fuzzy(current, previous, tolerance)
            return current != previous
        current_value = vt._decode(self.value_type, current)
        previous_value = vt._decode(self.value_type, previous)
        if scan_type == "increased":
            return current_value > previous_value
        if scan_type == "decreased":
            return current_value < previous_value
        if scan_type == "fuzzy":
            return vt.almost_equal(current_value, previous_value, relative=tolerance or 0.001)
        return current_value != previous_value

    def _display(self, value):
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).hex()
        return value

    def value_at(self, address, value_type=None):
        return vt.read(self.proc, address, value_type or self.value_type)

    def results(self, offset=0, limit=RESULT_PAGE, group=False, with_values=True):
        total = self.count
        offset = max(0, int(offset))
        limit = max(1, min(int(limit), RESULT_PAGE * 20))
        page = []
        step = self.element_size
        for index in range(offset, min(offset + limit, total)):
            address = self.addresses[index]
            entry = {"address": hex(address), "address_dec": address}
            if with_values:
                try:
                    entry["value"] = self.value_at(address)
                except Exception:
                    entry["value"] = None
            page.append(entry)

        payload = {
            "total": total,
            "offset": offset,
            "returned": len(page),
            "truncated": self.truncated,
            "pass": self.pass_number,
            "history": self.history,
            "results": page,
        }
        if group:
            buckets = {}
            for index in range(total):
                address = self.addresses[index]
                try:
                    value = self.value_at(address)
                except Exception:
                    value = None
                buckets.setdefault(repr(value), []).append(hex(address))
            ordered = sorted(
                buckets.items(), key=lambda item: len(item[1]), reverse=True
            )
            payload["groups"] = [
                {"value": value, "count": len(addresses), "addresses": addresses[:64]}
                for value, addresses in ordered[:64]
            ]
        return payload

    def summary(self):
        return {
            "value_type": self.value_type,
            "value_size": self.value_size,
            "results": self.count,
            "pass": self.pass_number,
            "scanned_bytes": self.scanned_bytes,
            "regions_scanned": self.regions_scanned,
            "truncated": self.truncated,
            "history": self.history,
        }


def _bytes_fuzzy(current, previous, tolerance):
    if tolerance <= 0:
        tolerance = 0.001
    for left, right in zip(current, previous):
        if right:
            if abs(left - right) > max(1, abs(right) * tolerance):
                return False
        elif left:
            return False
    return True


ADDRESS_RANGE = re.compile(r"^(0x[0-9a-fA-F]+|\d+)\s*-\s*(0x[0-9a-fA-F]+|\d+)$")


def parse_range(text):
    if not text:
        return None
    match = ADDRESS_RANGE.match(text.strip())
    if not match:
        raise ScanError(f"cannot parse address range {text!r}")
    return int(match.group(1), 0), int(match.group(2), 0)
