"""Disassembly and assembly, via capstone and keystone."""

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

try:
    from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, Ks
    HAVE_KEYSTONE = True
except ImportError:
    HAVE_KEYSTONE = False


class DisasmUnavailable(RuntimeError):
    pass


def require_capstone():
    if not HAVE_CAPSTONE:
        raise DisasmUnavailable("capstone is not installed; run: pip install capstone")


def require_keystone():
    if not HAVE_KEYSTONE:
        raise DisasmUnavailable("keystone-engine is not installed; run: pip install keystone-engine")


def capstone_mode(is_64bit):
    return CS_MODE_64 if is_64bit else CS_MODE_32


def keystone_mode(is_64bit):
    return KS_MODE_64 if is_64bit else KS_MODE_32


def disassemble(code, address, is_64bit, count=0):
    """Disassemble raw bytes at address. Returns a list of instruction dicts."""
    require_capstone()
    engine = Cs(CS_ARCH_X86, capstone_mode(is_64bit))
    engine.detail = False
    out = []
    for instruction in engine.disasm(bytes(code), address):
        out.append({
            "address": hex(instruction.address),
            "size": instruction.size,
            "bytes": bytes(instruction.bytes).hex(),
            "mnemonic": instruction.mnemonic,
            "op_str": instruction.op_str,
            "text": f"{instruction.mnemonic} {instruction.op_str}".strip(),
        })
        if count and len(out) >= count:
            break
    return out


def disassemble_at(proc, address, count=16, max_bytes=256):
    size = min(max(count, 1) * 15 + 16, max_bytes)
    raw = proc.read_exact(address, size)
    return disassemble(raw, address, proc.is_64bit, count)


def disassemble_range(proc, start, end):
    raw = proc.read_exact(start, max(end - start, 1))
    return disassemble(raw, start, proc.is_64bit, 0)


def assemble(text, address, is_64bit):
    """Assemble one or more instructions. Returns (bytes, instruction count)."""
    require_keystone()
    engine = Ks(KS_ARCH_X86, keystone_mode(is_64bit))
    encoding, count = engine.asm(text, addr=address, as_bytes=True)
    return bytes(encoding), count


def assemble_at(proc, text, address):
    """Assemble for the target's bitness and write the result. Returns bytes written."""
    payload, _count = assemble(text, address, proc.is_64bit)
    proc.write(address, payload)
    return payload.hex()


def format_block(instructions, show_bytes=True):
    lines = []
    for instruction in instructions:
        prefix = f"{instruction['bytes']:<24} " if show_bytes else ""
        lines.append(f"{instruction['address']}  {prefix}{instruction['text']}")
    return "\n".join(lines)


def resolve_thunk(proc, address, max_hops=4):
    """Follow E9/EB jump thunks to the real code.

    Linkers routinely leave a five byte jump at the address of a function whose
    body was placed elsewhere, so the interesting code is one hop away. Reading
    a disassembly always means following the jump first.
    """
    hops = []
    current = int(address)
    for _hop in range(max_hops):
        raw = proc.read_exact(current, 5)
        if raw[0] == 0xE9:
            displacement = int.from_bytes(raw[1:5], "little", signed=True)
        elif raw[0] == 0xEB:
            displacement = int.from_bytes(raw[1:2], "little", signed=True)
        else:
            break
        target = current + 5 + displacement
        if target == current or not target:
            break
        hops.append({"from": hex(current), "to": hex(target), "kind": "jmp" if raw[0] == 0xE9 else "jmp8"})
        current = target
        try:
            if not proc.query(current):
                break
        except Exception:
            break
    return current, hops
