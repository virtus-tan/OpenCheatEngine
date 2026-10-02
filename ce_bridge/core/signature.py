"""Signature scanning, cross-references and static pointer discovery."""

import struct
import time

from . import disasm

WILDCARDS = {"?", "??", "*", "x"}
CHUNK = 1 << 20
MAX_CHAIN_DEPTH = 6
MAX_CHAIN_NODES = 4000


class SignatureError(RuntimeError):
    pass


def parse_pattern(pattern):
    """Turn "48 8B ?? 05" into (bytes, mask).

    mask[i] is 0xFF for a known byte and 0x00 for a wildcard, so a match test
    is a single AND per position. Half-byte wildcards like "4?" are supported.
    """
    tokens = pattern.replace(",", " ").split()
    if not tokens:
        raise SignatureError("empty signature pattern")
    values = bytearray()
    mask = bytearray()
    for token in tokens:
        text = token.strip().lower()
        if text in WILDCARDS:
            values.append(0)
            mask.append(0)
            continue
        if len(text) == 1:
            text = "0" + text
        allowed = set("0123456789abcdef?")
        if len(text) != 2 or any(char not in allowed for char in text):
            raise SignatureError(
                f"bad pattern token {token!r}; use hex bytes, ?? for any byte, "
                "or A? / ?A for a half byte"
            )
        if text[0] == "?":
            values.append(int(text[1], 16))
            mask.append(0x0F)
        elif text[1] == "?":
            values.append(int(text[0], 16) << 4)
            mask.append(0xF0)
        else:
            values.append(int(text, 16))
            mask.append(0xFF)
    return bytes(values), bytes(mask)


def _match(data, offset, values, mask):
    for index in range(len(values)):
        if data[offset + index] & mask[index] != values[index] & mask[index]:
            return False
    return True


def aob_scan(proc, pattern, start=None, end=None, max_hits=256, region_filter=None,
             require_unique=False):
    """Scan for a byte pattern. Returns a list of hit addresses."""
    values, mask = parse_pattern(pattern)
    span = len(values)
    anchor = values[0] if mask[0] == 0xFF else None

    if start is None:
        regions = list(proc.iter_regions(
            committed_only=True, writable_only=False, executable_only=False
        ))
    else:
        stop = end or start + 0x100000
        regions = [{
            "base": hex(start), "size": stop - start, "state": "COMMIT",
            "protect": "RW-", "type": "PRIVATE", "writable": True, "executable": True,
        }]

    hits = []
    truncated = False
    for region in regions:
        if region_filter and not region_filter(region):
            continue
        base = int(region["base"], 16)
        size = region["size"]
        if size < span:
            continue
        cursor = 0
        while cursor < size:
            window = proc.read(base + cursor, min(CHUNK, size - cursor) + span - 1, partial=True)
            if len(window) < span:
                break
            if anchor is None:
                positions = range(0, len(window) - span + 1)
            else:
                positions = []
                found = window.find(bytes([anchor]))
                while found != -1:
                    positions.append(found)
                    found = window.find(bytes([anchor]), found + 1)
            for position in positions:
                if position + span > len(window):
                    continue
                if _match(window, position, values, mask):
                    hits.append(base + cursor + position)
                    if len(hits) >= max_hits:
                        truncated = True
                        break
            if truncated:
                break
            if len(window) <= span - 1:
                break
            cursor += CHUNK
        if truncated:
            break
    return hits, truncated


def aob(proc, pattern, module=None, max_hits=256, require_unique=False):
    """AOB scan, optionally restricted to one module's image."""
    if module:
        info = proc.module(module)
        if not info:
            raise SignatureError(f"module {module!r} is not loaded")
        bounds = (info.base, info.base + (info.size or 0))
    else:
        bounds = (None, None)

    def in_module(region):
        if bounds[0] is None:
            return True
        base = int(region["base"], 16)
        return base + region["size"] > bounds[0] and base < bounds[1]

    hits, truncated = aob_scan(
        proc, pattern, start=bounds[0], end=bounds[1], max_hits=max_hits, region_filter=in_module
    )
    out = []
    for address in hits:
        entry = {
            "address": hex(address),
            "module": module,
            "offset": hex(address - bounds[0]) if bounds[0] is not None else None,
        }
        try:
            instructions = disasm.disassemble_at(proc, address, 1)
            if instructions:
                entry["instruction"] = instructions[0]["text"]
                entry["bytes"] = instructions[0]["bytes"]
        except Exception:
            pass
        out.append(entry)
    if require_unique and len(out) != 1:
        raise SignatureError(
            f"signature {pattern!r} matched {len(out)} times"
            + ("" if not out else f" at {', '.join(item['address'] for item in out[:8])}")
            + ". Add more unique bytes."
        )
    return {"pattern": pattern, "count": len(out), "truncated": truncated, "hits": out}


def xrefs_to(proc, address, code_only=True, disassemble=True, max_hits=256):
    """Find instructions and pointer slots that reference an address.

    Two mechanisms: the address as a literal pointer, and RIP-relative
    displacements (x64 only), which is how 64-bit compilers reference data.
    """
    address = int(address)
    results = []
    truncated = False

    literal = address.to_bytes(proc.ptr_size, "little")
    for region in proc.iter_regions(committed_only=True):
        if code_only and not region["executable"]:
            continue
        base = int(region["base"], 16)
        size = region["size"]
        cursor = 0
        while cursor < size:
            window = proc.read(base + cursor, min(CHUNK, size - cursor) + proc.ptr_size - 1,
                               partial=True)
            if not window:
                break
            position = window.find(literal)
            while position != -1:
                results.append({
                    "address": hex(base + cursor + position),
                    "kind": "pointer",
                    "region": hex(base),
                })
                if len(results) >= max_hits:
                    truncated = True
                    break
                position = window.find(literal, position + 1)
            if truncated:
                break
            cursor += CHUNK
        if truncated:
            break

    if proc.is_64bit:
        for entry in _rip_relative(proc, address, max_hits - len(results)):
            results.append(entry)
            if len(results) >= max_hits:
                truncated = True
                break

    if disassemble:
        for entry in results:
            try:
                instructions = disasm.disassemble_at(proc, int(entry["address"], 16), 1)
                if instructions:
                    entry["instruction"] = instructions[0]["text"]
                    entry["instruction_bytes"] = instructions[0]["bytes"]
            except Exception:
                pass
    return {"target": hex(address), "count": len(results), "truncated": truncated,
            "xrefs": results}


def _rip_relative(proc, address, max_hits):
    """Scan executable regions for a 32-bit displacement resolving to address."""
    found = []
    for region in proc.iter_regions(committed_only=True, executable_only=True):
        base = int(region["base"], 16)
        size = region["size"]
        data = proc.read(base, size, partial=True)
        if not data:
            continue
        for offset in range(0, max(len(data) - 4, 0), 1):
            displacement = struct.unpack_from("<i", data, offset)[0]
            if base + offset + 4 + displacement == address:
                found.append({
                    "address": hex(base + offset),
                    "kind": "rip",
                    "region": hex(base),
                })
                if len(found) >= max_hits:
                    return found
    return found


def find_pointer_chains(proc, address, depth=MAX_CHAIN_DEPTH, max_results=32,
                        writable_only=True, module=None):
    """Look for a static pointer chain: module -> +off -> ptr -> ... -> target.

    Only committed regions are searched, and the walk is breadth-first with a
    node budget so a large process cannot stall the request.
    """
    target = int(address)
    ptr_size = proc.ptr_size
    level = [target]
    chain_by_target = {target: []}
    found = []
    budget = MAX_CHAIN_NODES

    if module:
        info = proc.module(module)
        if not info:
            raise SignatureError(f"module {module!r} is not loaded")
        seed_region = {
            "base": hex(info.base), "size": info.size or 0x1000000, "state": "COMMIT",
            "protect": "R--", "type": "IMAGE", "writable": True, "executable": False,
        }
        regions = [seed_region]
    else:
        regions = list(proc.iter_regions(committed_only=True, writable_only=writable_only))

    for level_index in range(1, depth + 1):
        next_level = []
        for pointer_target in level:
            wanted = pointer_target.to_bytes(ptr_size, "little")
            for region in regions:
                base = int(region["base"], 16)
                size = region["size"]
                if size < ptr_size or budget <= 0:
                    continue
                budget -= size // ptr_size
                data = proc.read(base, size, partial=True)
                if not data:
                    continue
                position = data.find(wanted)
                while position != -1:
                    candidate = base + position
                    if candidate not in chain_by_target:
                        chain = [candidate] + chain_by_target[pointer_target]
                        chain_by_target[candidate] = chain
                        next_level.append(candidate)
                        found.append({
                            "chain": " -> ".join(hex(item) for item in chain) + f" -> {hex(target)}",
                            "head": hex(candidate),
                            "depth": len(chain),
                            "offsets": [0] * len(chain),
                        })
                        if len(found) >= max_results:
                            return {
                                "target": hex(target), "count": len(found),
                                "truncated": True, "chains": found,
                            }
                    position = data.find(wanted, position + 1)
        if not next_level:
            break
        level = next_level
    return {"target": hex(target), "count": len(found), "truncated": False, "chains": found}


def resolve_chain(proc, chain, final_offset=0):
    """Walk a chain of pointer hops and report the final address and each step."""
    started = time.time()
    current = int(chain[0])
    steps = [{"step": 0, "address": hex(current), "value": hex(proc.pointer(current))}]
    for offset in chain[1:]:
        current = proc.pointer(current) + int(offset)
        steps.append({"step": len(steps), "address": hex(current), "offset": hex(int(offset))})
    final = proc.pointer(current) + int(final_offset)
    return {
        "final": hex(final),
        "steps": steps,
        "elapsed_ms": round((time.time() - started) * 1000, 2),
    }
