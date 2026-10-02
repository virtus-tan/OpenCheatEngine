"""Value typing for read, write and scan operations."""

import math
import struct

FORMATS = {
    "i8": ("<b", 1),
    "u8": ("<B", 1),
    "bool": ("<B", 1),
    "i16": ("<h", 2),
    "u16": ("<H", 2),
    "i32": ("<i", 4),
    "u32": ("<I", 4),
    "f32": ("<f", 4),
    "i64": ("<q", 8),
    "u64": ("<Q", 8),
    "f64": ("<d", 8),
}

ALIASES = {
    "byte": "u8",
    "sbyte": "i8",
    "int": "i32",
    "int32": "i32",
    "uint": "u32",
    "uint32": "u32",
    "int64": "i64",
    "uint64": "u64",
    "float": "f32",
    "double": "f64",
    "short": "i16",
    "ushort": "u16",
    "word": "u16",
    "dword": "u32",
    "qword": "u64",
    "single": "f32",
    "half": "f32",
}

BYTE_TYPES = {"i8", "u8", "bool"}
FLOAT_TYPES = {"f32", "f64"}


class TypeError_(ValueError):
    pass


def normalise(name):
    key = (name or "").strip().lower()
    key = ALIASES.get(key, key)
    if key in FORMATS:
        return key
    if key in ("ptr", "pointer", "address"):
        return "ptr"
    if key in ("bytes", "hex", "raw"):
        return "bytes"
    if key in ("string", "str", "text"):
        return "string"
    if key in ("array", "bytes_array", "struct"):
        return key
    raise TypeError_(f"unknown value type {name!r}; known: {', '.join(sorted(known_types()))}")


def known_types():
    return set(FORMATS) | {"ptr", "bytes", "string", "array", "struct"}


def size_of(value_type, ptr_size=8):
    value_type = normalise(value_type)
    if value_type in FORMATS:
        return FORMATS[value_type][1]
    if value_type == "ptr":
        return ptr_size
    return 0


def _decode(value_type, raw):
    value_type = normalise(value_type)
    if value_type == "bool":
        return bool(raw[0])
    if value_type == "ptr":
        return int.from_bytes(raw, "little")
    if value_type == "bytes":
        return raw
    if value_type == "string":
        return raw.split(b"\x00")[0].decode("utf-8", "replace")
    fmt, _size = FORMATS[value_type]
    return struct.unpack(fmt, raw)[0]


def _to_int(value):
    """Coerce a number the way a person would write it.

    Values arrive from tool arguments as strings, and "0xAABBCCDD" or
    "0b1010" have to work, so a base-prefixed string is read with base 0 and
    anything else as decimal.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not value.is_integer():
            raise TypeError_(f"{value} is not a whole number")
        return int(value)
    if isinstance(value, str):
        text = value.strip().replace("_", "").replace(" ", "")
        if not text:
            raise TypeError_("empty value")
        try:
            return int(text, 0) if text[:2].lower() in ("0x", "0b", "0o") else int(text, 10)
        except ValueError:
            raise TypeError_(f"{value!r} is not a number") from None
    raise TypeError_(f"cannot read {type(value).__name__} as a number")


def _to_float(value):
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        try:
            return float(text)
        except ValueError:
            return float(_to_int(text))
    raise TypeError_(f"cannot read {type(value).__name__} as a number")


def _encode(value_type, value, ptr_size=8):
    value_type = normalise(value_type)
    if value_type == "ptr":
        if isinstance(value, str):
            return int(value, 0) if value.strip()[:2].lower() == "0x" else int(value.strip(), 16)
        return int(value).to_bytes(ptr_size, "little")
    if value_type == "bytes":
        from .winapi import parse_bytes
        return parse_bytes(value)
    if value_type == "string":
        return value.encode("utf-8") + b"\x00" if isinstance(value, str) else bytes(value)
    fmt, _size = FORMATS[value_type]
    if value_type in FLOAT_TYPES:
        number = _to_float(value)
    elif value_type == "bool":
        number = 1 if value in (True, 1, "1", "true", "True") else 0
    else:
        number = _to_int(value)
        if value_type in ("u8", "u16", "u32", "u64") and number < 0:
            raise TypeError_(f"{number} does not fit in unsigned {value_type}")
        if value_type in ("i8", "i16", "i32", "i64"):
            size = FORMATS[value_type][1]
            if not -(1 << (size * 8 - 1)) <= number < (1 << (size * 8 - 1)):
                raise TypeError_(f"{number} does not fit in {value_type}")
    return struct.pack(fmt, number)



def read(proc, address, value_type="u32", count=1):
    """Read one or more values. Returns a single value or a list."""
    value_type = normalise(value_type)
    if value_type == "array":
        return read_array(proc, address, count)
    size = size_of(value_type, proc.ptr_size)
    if size == 0:
        raise TypeError_(f"type {value_type} has no fixed size")
    if count <= 1:
        return _decode(value_type, proc.read_exact(address, size))
    raw = proc.read_exact(address, size * count)
    return [_decode(value_type, raw[index * size:(index + 1) * size]) for index in range(count)]


def write(proc, address, value_type, value):
    raw = _encode(value_type, value, proc.ptr_size)
    written = proc.write(address, raw)
    return {"address": hex(address), "type": value_type, "bytes": written, "raw": raw.hex()}


def read_array(proc, address, count, element_size=1):
    raw = proc.read_exact(address, count * element_size)
    return [raw[index * element_size:(index + 1) * element_size].hex() for index in range(count)]


def read_struct(proc, address, fields):
    """fields: [{"name": str, "type": str}, ...] in declaration order."""
    out = {}
    cursor = address
    for field in fields:
        field_type = normalise(field["type"])
        size = size_of(field_type, proc.ptr_size)
        raw = proc.read_exact(cursor, size)
        out[field["name"]] = _decode(field_type, raw)
        cursor += size
    return {"address": hex(address), "size": cursor - address, "fields": out}


def write_struct(proc, address, fields, values):
    payload = b""
    resolved = []
    for field in fields:
        field_type = normalise(field["type"])
        raw = _encode(field_type, values[field["name"]], proc.ptr_size)
        resolved.append((field["name"], field_type, raw.hex()))
        payload += raw
    proc.write(address, payload)
    return {"address": hex(address), "bytes": len(payload), "fields": resolved}


def parse_struct(spec):
    """Accept a list of dicts, or a compact "int32 hp; float x; char name[16]".

    Type comes first and the name second, which is both C style and what
    Cheat Engine's array-of-structures scan uses. The array suffix is accepted
    on either the type (float[16] v) or the name (char name[16]).
    """
    if isinstance(spec, list):
        return [{"name": item["name"], "type": normalise(item["type"])} for item in spec]
    fields = []
    for chunk in spec.replace("\n", " ").split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.replace(",", " ").split()
        if len(parts) < 2:
            raise TypeError_(f"cannot parse struct member {chunk!r}; expected 'type name'")
        type_name, name = parts[0], parts[1]
        count = 1
        if "[" in type_name:
            type_name, _, rest = type_name.partition("[")
            count = int(rest.rstrip("] ") or 1)
        if "[" in name:
            name, _, rest = name.partition("[")
            count = int(rest.rstrip("] ") or 1)
        for index in range(count):
            fields.append({
                "name": name if count == 1 else f"{name}[{index}]",
                "type": normalise(type_name),
            })
    if not fields:
        raise TypeError_(f"no struct members found in {spec!r}")
    return fields


def almost_equal(left, right, relative=0.001, absolute=0.0001):
    if left == right:
        return True
    if math.isnan(left) and math.isnan(right):
        return True
    if math.isinf(left) or math.isinf(right):
        return False
    return abs(left - right) <= max(absolute, abs(right) * relative)
