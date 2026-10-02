"""Code injection, export resolution and simple trampoline hooks."""

import os
import struct

from . import disasm, pe
from .winapi import parse_bytes, parse_address

INJECT_DLL = "LoadLibraryA"
INJECT_ENTRY = "GetProcAddress"


class InjectError(RuntimeError):
    pass


MAX_FORWARD_HOPS = 8


def resolve_export(proc, module_name, export_name):
    """Address of an export inside the target, following export forwarders.

    The RVA comes from the DLL on disk and the base from the target's module
    list, which is what makes this work for a 32-bit target from a 64-bit
    bridge: kernel32.dll is mapped at the same base for every process of a
    given bitness, but its 32-bit base is not reachable from a 64-bit address
    space without going through the target's own module list.

    Windows 10 and 11 forward most of kernel32 to KernelBase, so the RVA in
    kernel32's own export table addresses a string rather than code. Those are
    followed to the real implementation, in whichever module actually provides
    it, because calling the forwarder string returns garbage silently.
    """
    chain = []
    current_module = module_name
    current_export = export_name
    for _hop in range(MAX_FORWARD_HOPS):
        module = proc.module(current_module)
        if not module:
            raise InjectError(
                f"module {current_module!r} is not loaded in the target"
                + (f" (needed for {current_export} via {' -> '.join(chain)})" if chain else "")
            )
        try:
            image = pe.load(module.path)
        except Exception as error:
            raise InjectError(f"cannot read {module.path}: {error}")
        rva = image.export_rva(current_export)
        if rva is None:
            guesses = list(pe.export_rvas(module.path, current_export[:4]))[:8]
            raise InjectError(
                f"{current_export} is not exported by {module.path}"
                + (f" (reached via {' -> '.join(chain)})" if chain else "")
                + (f". Similar: {', '.join(guesses)}" if guesses else "")
            )
        if not image.is_forwarder(rva):
            return module.base + rva
        forwarder = image.forwarder(rva)
        if not forwarder or "." not in forwarder:
            raise InjectError(
                f"{current_export} in {module.path} has an unreadable forwarder entry"
            )
        dll, _, exported = forwarder.partition(".")
        chain.append(f"{current_module}!{current_export}->{forwarder}")
        current_module, current_export = dll, exported
    raise InjectError(
        f"{export_name} is forwarded more than {MAX_FORWARD_HOPS} times: "
        + " -> ".join(chain)
    )


def remote_call(proc, module_name, export_name, args=(), timeout=15000):
    """Call module!export(args...) in the target and return the raw result."""
    return proc.remote_call_n(resolve_export(proc, module_name, export_name),
                              list(args), timeout=timeout)


def inject_dll(proc, path, call_entry=False, entry_name="DllMain"):
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise InjectError(f"DLL not found: {path}")
    loader = resolve_export(proc, "kernel32.dll", INJECT_DLL)
    path_address = proc.string_in_target(path)
    try:
        handle = proc.remote_call_n(loader, [path_address], timeout=30000)
    finally:
        try:
            proc.free(path_address)
        except Exception:
            pass
    if not handle:
        raise InjectError(
            f"LoadLibraryA returned NULL for {os.path.basename(path)}. "
            "The target is probably 64-bit and the DLL is 32-bit (or the "
            "reverse), or the DLL's dependencies are missing."
        )
    result = {
        "path": path,
        "module_handle": hex(handle),
        "base": hex(handle),
        "entry_called": False,
    }
    if call_entry:
        try:
            getter = resolve_export(proc, "kernel32.dll", INJECT_ENTRY)
            name_address = proc.string_in_target(entry_name)
            try:
                remote = proc.remote_call_n(getter, [handle, name_address], timeout=20000)
            finally:
                proc.free(name_address)
            if remote:
                proc.remote_call_n(remote, [handle, 1, 0], timeout=20000)
                result["entry_called"] = True
                result["entry"] = hex(remote)
        except InjectError as error:
            result["entry_error"] = str(error)
    return result


def exec_shellcode(proc, code, timeout=20000):
    raw = parse_bytes(code)
    result = proc.run_shellcode(raw, timeout=timeout)
    return {"bytes": len(raw), "thread_exit_code": result}


def patch(proc, address, expected, replacement, verify=True):
    """Overwrite bytes at address, optionally checking what is there first.

    expected accepts "90 90", "9090" or a list, and is what makes a patch safe
    to retry: if the module is a different build the bytes will not match and
    the patch is refused instead of corrupting something.
    """
    address = parse_address(address)
    replacement = parse_bytes(replacement)
    expected_raw = parse_bytes(expected) if expected else b""
    before = proc.read_exact(address, max(len(expected_raw), len(replacement)))
    if verify and expected_raw and before[:len(expected_raw)] != expected_raw:
        from .winapi import hexdump
        raise InjectError(
            f"patch refused at {hex(address)}: expected "
            f"{expected_raw.hex(' ')} but found {before[:len(expected_raw)].hex(' ')}. "
            "This usually means a different build or a patch already applied."
        )
    proc.write(address, replacement)
    owner = proc.module_containing(address)
    return {
        "address": hex(address),
        "before": before[:len(replacement)].hex(),
        "after": replacement.hex(),
        "module": owner.name if owner else None,
        "module_offset": hex(address - owner.base) if owner else None,
    }


def _overwrite_length(proc, address, is_64bit, needed):
    """Grow the overwrite window by whole instructions until it fits `needed`."""
    cursor = address
    consumed = 0
    while consumed < needed:
        instructions = disasm.disassemble_at(proc, cursor, 1)
        if not instructions:
            raise InjectError(
                f"cannot disassemble at {hex(cursor)}, so the hook window cannot "
                "be made instruction aligned there"
            )
        mnemonic = instructions[0]["mnemonic"]
        if mnemonic.startswith("j") or mnemonic in ("call", "loop", "jmp"):
            raise InjectError(
                f"the instruction at {hex(cursor)} ({instructions[0]['text']}) is a "
                "relative branch inside the hook window. Hooking here needs a full "
                "detour engine that relocates branches; hook the first instruction "
                "of the function instead."
            )
        consumed += instructions[0]["size"]
        cursor += instructions[0]["size"]
        if consumed > 32:
            raise InjectError("hook window grew past 32 bytes; pick a better entry point")
    return consumed


def hook(proc, address, replacement_address, trampoline=True):
    """Redirect execution at address to replacement_address.

    A plain jump with a relocation trampoline, which is enough for hooking a
    function you also want to be able to call through. It refuses to patch
    across a relative branch instead of producing a broken trampoline.
    """
    address = parse_address(address)
    replacement_address = parse_address(replacement_address)
    is_64bit = proc.is_64bit

    if is_64bit:
        jump = bytes([0x48, 0xB8]) + struct.pack("<Q", replacement_address) + bytes([0xFF, 0xE0])
    else:
        relative = replacement_address - (address + 5)
        if -0x80000000 <= relative < 0x80000000:
            jump = bytes([0xE9]) + struct.pack("<i", relative)
        else:
            jump = bytes([0xFF, 0x25]) + struct.pack("<I", replacement_address)

    window = _overwrite_length(proc, address, is_64bit, len(jump))
    original = proc.read_exact(address, window)
    entry = {
        "address": hex(address),
        "replacement": hex(replacement_address),
        "window": window,
        "original": original.hex(),
        "trampoline": None,
    }
    if trampoline:
        cave = proc.alloc(0x1000, executable=True)
        body = original + jump
        if is_64bit:
            back = address + window
            relative_back = back - (cave + window + len(jump))
            tail = bytes([0x48, 0xB8]) + struct.pack("<Q", back) + bytes([0xFF, 0xE0])
        else:
            tail = bytes([0xE9]) + struct.pack("<i", (address + window) - (cave + window + len(jump) + 5))
        proc.write(cave, body + tail)
        entry["trampoline"] = hex(cave)
    proc.write(address, jump + b"\x90" * (window - len(jump)))
    return entry


def unhook(proc, entry):
    address = parse_address(entry["address"])
    original = parse_bytes(entry["original"])
    proc.write(address, original)
    cave = entry.get("trampoline")
    if cave:
        try:
            proc.free(parse_address(cave))
        except Exception:
            pass
    return {"address": hex(address), "restored": original.hex()}
