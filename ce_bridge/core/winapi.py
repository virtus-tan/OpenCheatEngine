"""Raw Win32 bindings for cross-process memory access.

Everything here is ctypes against kernel32. The rest of the bridge is built on
top of this module and never touches ctypes directly.
"""

import ctypes
import os
import struct
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Windows 10 1607+ re-exports the psapi entry points from kernel32. Prefer those
# so a 64-bit bridge drives a 32-bit target through the same code path.
try:
    k32 = kernel32
    k32.K32EnumProcessModulesEx
    k32.K32GetModuleFileNameExW
except AttributeError:  # pragma: no cover
    k32 = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

MEMORY_PARTIAL_MACHINE = 0x08000000
MEM_RELEASE = 0x8000

LIST_MODULES_ALL = 0x03
LIST_MODULES_32BIT = 0x02
LIST_MODULES_64BIT = 0x01

STILL_ACTIVE = 259

PROTECT_NAMES = {
    PAGE_NOACCESS: "---",
    PAGE_READONLY: "R--",
    PAGE_READWRITE: "RW-",
    PAGE_WRITECOPY: "RWc",
    PAGE_EXECUTE: "--X",
    PAGE_EXECUTE_READ: "R-X",
    PAGE_EXECUTE_READWRITE: "RWX",
    PAGE_EXECUTE_WRITECOPY: "RWXc",
}
STATE_NAMES = {MEM_COMMIT: "COMMIT", MEM_RESERVE: "RESERVE", MEM_FREE: "FREE"}
TYPE_NAMES = {MEM_PRIVATE: "PRIVATE", MEM_MAPPED: "MAPPED", MEM_IMAGE: "IMAGE"}


class Win32Error(RuntimeError):
    def __init__(self, func, code=None):
        if code is None:
            code = ctypes.get_last_error()
        try:
            text = ctypes.FormatError(code)
        except Exception:
            text = "unknown error"
        super().__init__(f"{func} failed: {text} (0x{code:08X})")
        self.func = func
        self.code = code


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """The 64-bit layout, used for 32-bit targets as well.

    Windows 10 2004 added a WORD PartitionId between AllocationProtect and
    RegionSize, but the 2 bytes of padding that used to sit there absorb it, so
    RegionSize is at offset 24 on every Windows version that matters.
    """

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("_pad", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD,
]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualFreeEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD,
]
kernel32.VirtualFreeEx.restype = wintypes.BOOL
kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
    ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL
kernel32.FlushInstructionCache.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
]
kernel32.FlushInstructionCache.restype = wintypes.BOOL
kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.IsWow64Process.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
k32.K32EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
]
k32.K32EnumProcessModulesEx.restype = wintypes.BOOL
k32.K32GetModuleFileNameExW.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD,
]
k32.K32GetModuleFileNameExW.restype = wintypes.DWORD

ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]
ntdll.NtQueryInformationProcess.restype = wintypes.LONG

PROCESS_BASIC_INFORMATION = 0
PROCESS_WOW64_INFORMATION = 26
PEB_BASIC_ADDRESS = 8

# Offsets inside the 32-bit structures, which differ from the 64-bit ones.
PEB32_LDR = 0x0C
LDR32_IN_MEMORY_ORDER_LIST = 0x14
LDR32_ENTRY_DLL_BASE = 0x18
LDR32_ENTRY_SIZE_OF_IMAGE = 0x20
LDR32_ENTRY_FULL_DLL_NAME = 0x24
LDR32_ENTRY_BASE_DLL_NAME = 0x2C
LDR32_ENTRY_IN_MEMORY_ORDER_LINKS = 0x08
UNICODE32_BUFFER_OFFSET = 4

# Offsets inside the 64-bit structures.
PEB64_LDR = 0x18
LDR64_IN_MEMORY_ORDER_LIST = 0x20
LDR64_ENTRY_DLL_BASE = 0x30
LDR64_ENTRY_SIZE_OF_IMAGE = 0x40
LDR64_ENTRY_FULL_DLL_NAME = 0x48
LDR64_ENTRY_BASE_DLL_NAME = 0x58
LDR64_ENTRY_IN_MEMORY_ORDER_LINKS = 0x20

# Data block layout shared by both architectures, offsets from the block base.
BLK_FUNC = 0x00
BLK_ARGPTR = 0x04 + 0x04  # 8 on x64, handled per-arch below
DATA_OFFSET = 0x200
CODE_OFFSET = 0x000
BLOCK_SIZE = 0x1000


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def align_down(value, alignment):
    return value & ~(alignment - 1)


def parse_address(value):
    """Accept an int, "0x..." or a bare number string.

    A bare string is read as hex, because every address in this domain is hex and
    C's %p prints them without a 0x prefix. A leading sign still works.
    """
    if isinstance(value, bool):
        raise TypeError("bool is not an address")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().replace("_", "").replace(" ", "")
        if not text:
            raise ValueError("empty address")
        negative = text.startswith("-")
        if negative:
            text = text[1:]
        if text[:2].lower() == "0x":
            text = text[2:]
        if not text:
            raise ValueError(f"not an address: {value!r}")
        try:
            number = int(text, 16)
        except ValueError:
            raise ValueError(
                f"not an address: {value!r}. Addresses are hex, with or without 0x, "
                'for example 0x7ff6237f9000 or "7ff6237f9000".'
            ) from None
        return -number if negative else number
    raise TypeError(f"cannot parse an address from {type(value).__name__}")


def parse_bytes(value):
    """Accept a hex string, an iterable of ints, or bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, (list, tuple)):
        return bytes(int(item) & 0xFF for item in value)
    if isinstance(value, str):
        cleaned = value.replace(" ", "").replace(",", "").replace("\n", "").replace("_", "")
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if len(cleaned) % 2:
            cleaned = "0" + cleaned
        return bytes.fromhex(cleaned)
    raise TypeError(f"cannot parse bytes from {type(value).__name__}")


def hexdump(data, base=0, limit=None):
    out = []
    view = data if limit is None else data[:limit]
    for offset in range(0, len(view), 16):
        row = view[offset:offset + 16]
        hexpart = " ".join(f"{byte:02X}" for byte in row)
        text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in row)
        out.append(f"{base + offset:016X}  {hexpart:<47}  |{text}|")
    return "\n".join(out)


class ModuleInfo:
    __slots__ = ("name", "path", "base", "size", "bitness")

    def __init__(self, name, path, base, size, bitness):
        self.name = name
        self.path = path
        self.base = base
        self.size = size
        self.bitness = bitness

    def to_dict(self):
        return {
            "name": self.name,
            "path": self.path,
            "base": hex(self.base),
            "end": hex(self.base + self.size) if self.size else None,
            "size": self.size,
            "bitness": self.bitness,
        }


class ProcessHandle:
    """An open handle to a target process plus every memory primitive."""

    def __init__(self, pid, writable):
        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE
        if writable:
            access |= PROCESS_VM_OPERATION | PROCESS_VM_WRITE
        handle = kernel32.OpenProcess(access, False, pid)
        if not handle:
            raise Win32Error("OpenProcess", ctypes.get_last_error())
        self.pid = pid
        self.writable = writable
        self.handle = handle
        self.closed = False
        wow64 = wintypes.BOOL()
        if not kernel32.IsWow64Process(handle, ctypes.byref(wow64)):
            code = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            raise Win32Error("IsWow64Process", code)
        self.is_64bit = not bool(wow64.value)
        self.ptr_size = 8 if self.is_64bit else 4
        self._modules = None

    def require_injection(self, what="this operation"):
        """Refuse code injection into a WOW64 target.

        A 64-bit process cannot create a thread with a 32-bit entry point, so
        VirtualAllocEx plus CreateRemoteThread has nothing to run. Rather than
        return a zero that looks like a real answer, say so.
        """
        if not self.is_64bit:
            raise Win32Error(
                f"{what} needs code execution in the target, which is not possible "
                f"for a 32-bit process from a 64-bit one: Windows will not create a "
                f"32-bit thread in a WOW64 process. Reading, writing, scanning, "
                f"disassembly and signatures all work. For injection, run the bridge "
                f"from a 32-bit Python, or use Cheat Engine's 32-bit build against "
                f"this process.",
                5,
            )
        return True

    def close(self):
        if not self.closed and self.handle:
            kernel32.CloseHandle(self.handle)
        self.closed = True
        self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def alive(self):
        if self.closed or not self.handle:
            return False
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(self.handle, ctypes.byref(code)):
            return False
        return code.value == STILL_ACTIVE

    def image_path(self):
        size = wintypes.DWORD(1024)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(
            self.handle, 0, buffer, ctypes.byref(size)
        ):
            raise Win32Error("QueryFullProcessImageNameW", ctypes.get_last_error())
        return buffer.value

    def base_name(self):
        try:
            return os.path.basename(self.image_path())
        except Exception:
            return f"pid{self.pid}"

    def read(self, address, size, partial=False):
        """Read up to size bytes. Returns a short buffer rather than raising."""
        if size <= 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(got)
        )
        if got.value == 0 and not partial:
            raise Win32Error("ReadProcessMemory", ctypes.get_last_error() or 0xC0000005)
        return buffer.raw[: got.value]

    def read_exact(self, address, size):
        chunks = []
        got = 0
        while got < size:
            chunk = self.read(address + got, size - got, partial=True)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
        if got < size:
            raise Win32Error(
                f"ReadProcessMemory short at {hex(address)}",
                ctypes.get_last_error() or 0xC0000005,
            )
        return b"".join(chunks)

    def write(self, address, data):
        if self.closed:
            raise Win32Error("WriteProcessMemory", 6)
        if not self.writable:
            raise PermissionError("target is read-only; unlock it first")
        payload = bytes(data)
        if not payload:
            return 0
        buffer = ctypes.create_string_buffer(payload, len(payload))
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(
            self.handle, ctypes.c_void_p(address), buffer, len(payload),
            ctypes.byref(written),
        ):
            raise Win32Error("WriteProcessMemory", ctypes.get_last_error())
        if written.value != len(payload):
            raise Win32Error("WriteProcessMemory partial", ctypes.get_last_error())
        return written.value

    def query(self, address):
        mbi = MEMORY_BASIC_INFORMATION()
        result = kernel32.VirtualQueryEx(
            self.handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if not result:
            raise Win32Error("VirtualQueryEx", ctypes.get_last_error())
        return mbi

    def image_regions(self, module):
        """Region list for a module image, taken from its section table.

        VirtualQueryEx cannot see a WOW64 target's 32-bit view: the kernel owns
        a 64-bit map for such a process and the 32-bit addresses below 4GB read
        back as MEM_FREE. Reads and writes through ReadProcessMemory still work,
        so the image is described from the section table instead, which is
        where a game's own data lives anyway.
        """
        from .pe import load as pe_load

        try:
            image = pe_load(module.path)
        except Exception:
            return []
        regions = []
        for section in image.sections:
            span = max(section.virtual_size, section.raw_size)
            if not span:
                continue
            if section.executable:
                protect = "RWX" if section.writable else "R-X"
            else:
                protect = "RW-" if section.writable else "R--"
            regions.append({
                "base": hex(module.base + section.virtual_address),
                "allocation_base": hex(module.base),
                "size": span,
                "state": "COMMIT",
                "protect": protect,
                "type": "IMAGE",
                "writable": section.writable,
                "executable": section.executable,
                "section": section.name,
                "module": module.name,
                "raw": {
                    "base": module.base + section.virtual_address,
                    "size": span,
                    "state": MEM_COMMIT,
                    "protect": 0,
                    "type": MEM_IMAGE,
                },
            })
        return regions

    def module_regions(self):
        """Every module image described by its section table."""
        regions = []
        for module in self.modules():
            regions.extend(self.image_regions(module))
        return regions

    def _annotate_module(self, region):
        base = int(region["base"], 16)
        span = region["size"]
        if base < 0x10000 or not span:
            return region
        for module in self.modules():
            if not module.size:
                continue
            if module.base <= base and base + span <= module.base + module.size:
                region["module"] = module.name
                region["module_offset"] = hex(base - module.base)
                break
        return region

    def region_at(self, address):
        if not self.is_64bit:
            synthetic = self._wow64_region(address)
            if synthetic is not None:
                return synthetic
        mbi = self.query(address)
        base = int(mbi.BaseAddress or 0)
        allocation_base = int(mbi.AllocationBase or 0)
        return self._annotate_module({
            "base": hex(base),
            "allocation_base": hex(allocation_base) if allocation_base else None,
            "size": int(mbi.RegionSize or 0),
            "state": STATE_NAMES.get(mbi.State, hex(mbi.State)),
            "protect": PROTECT_NAMES.get(mbi.Protect & 0xFF, hex(mbi.Protect)),
            "type": TYPE_NAMES.get(mbi.Type, hex(mbi.Type)),
            "writable": bool(
                mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY
                               | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            ),
            "executable": bool(
                mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ
                               | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            ),
            "raw": {
                "base": base,
                "allocation_base": allocation_base,
                "size": int(mbi.RegionSize or 0),
                "state": int(mbi.State),
                "protect": int(mbi.Protect),
                "type": int(mbi.Type),
            },
        })


    def _wow64_region(self, address):
        """Describe a 32-bit target address from the section table, or None."""
        module = self.module_containing(address)
        if not module:
            return None
        for region in self.image_regions(module):
            start = int(region["base"], 16)
            if start <= address < start + region["size"]:
                return dict(region, base=hex(start), offset=hex(address - start))
        return None

    def memory_map(self, start=0, size=0):
        if not self.is_64bit:
            return self.module_regions()
        limit = start + size if size else (1 << 47)
        cursor = start
        regions = []
        while cursor < limit:
            try:
                mbi = self.query(cursor)
            except Win32Error:
                break
            base = int(mbi.BaseAddress or 0)
            span = int(mbi.RegionSize or 0)
            if base == 0 and span == 0:
                break
            regions.append(self.region_at(base))
            nxt = base + max(span, 0x1000)
            if nxt <= cursor:
                break
            cursor = nxt
        return regions

    def iter_regions(self, committed_only=True, writable_only=False, executable_only=False):
        for region in self.memory_map():
            if committed_only and region["state"] != "COMMIT":
                continue
            if writable_only and not region["writable"]:
                continue
            if executable_only and not region["executable"]:
                continue
            yield region

    def alloc(self, size, executable=False, protect=PAGE_READWRITE):
        if not self.writable:
            raise PermissionError("target is read-only; unlock it first")
        if executable:
            self.require_injection("allocating executable memory")
        address = kernel32.VirtualAllocEx(
            self.handle, None, max(size, 0x1000), MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE if executable else protect,
        )
        if not address:
            raise Win32Error("VirtualAllocEx", ctypes.get_last_error())
        return address

    def free(self, address, size=0):
        if not self.writable:
            raise PermissionError("target is read-only; unlock it first")
        if not kernel32.VirtualFreeEx(
            self.handle, ctypes.c_void_p(address), size, MEM_RELEASE
        ):
            raise Win32Error("VirtualFreeEx", ctypes.get_last_error())
        return True

    def protect(self, address, size, protect):
        if not self.writable:
            raise PermissionError("target is read-only; unlock it first")
        old = wintypes.DWORD()
        if not kernel32.VirtualProtectEx(
            self.handle, ctypes.c_void_p(address), size, protect, ctypes.byref(old)
        ):
            raise Win32Error("VirtualProtectEx", ctypes.get_last_error())
        return old.value

    def _peb_query(self, info_class, width):
        """NtQueryInformationProcess with an exactly sized buffer.

        These classes reject a buffer that is larger than the structure with
        STATUS_INFO_LENGTH_MISMATCH, so the length is not advisory: 48 bytes for
        ProcessBasicInformation and 8 for ProcessWow64Information.
        """
        buffer = (ctypes.c_ubyte * width)()
        returned = wintypes.ULONG(0)
        status = ntdll.NtQueryInformationProcess(
            self.handle, info_class, buffer, width, ctypes.byref(returned)
        )
        if (status & 0xFFFFFFFF) != 0:
            return None
        return int.from_bytes(bytes(buffer)[:width], "little") or None

    def peb32(self):
        """The 32-bit PEB of a WOW64 target, or None.

        ProcessBasicInformation on a WOW64 process describes the 32-bit guest,
        not the host that emulates it, and EnumProcessModulesEx from a 64-bit
        caller returns the WOW64 host's modules. ProcessWow64Information is the
        documented way to reach the real 32-bit PEB, and walking its loader
        list is the only way to get a 32-bit target's module list.
        """
        if self.is_64bit:
            return None
        return self._peb_query(PROCESS_WOW64_INFORMATION, 8)

    def _read_u32(self, address):
        return int.from_bytes(self.read_exact(address, 4), "little")

    def _read_u64(self, address):
        return int.from_bytes(self.read_exact(address, 8), "little")

    def _read_unicode32(self, address):
        # UNICODE_STRING32 is {USHORT Length; USHORT MaximumLength; ULONG Buffer},
        # so the length is two bytes. Reading four would fold MaximumLength in
        # and make every name look impossibly long.
        length = int.from_bytes(self.read_exact(address, 2), "little")
        buffer = self._read_u32(address + UNICODE32_BUFFER_OFFSET)
        if not buffer or length == 0 or length > 2048:
            return ""
        return self.read_exact(buffer, length).decode("utf-16-le", "replace")

    def _read_unicode64(self, address):
        length = int.from_bytes(self.read_exact(address, 2), "little")
        buffer = self._read_u64(address + 8)
        if not buffer or length == 0 or length > 2048:
            return ""
        return self.read_exact(buffer, length).decode("utf-16-le", "replace")

    def _walk_loader(self, ldr, is_32bit):
        """Walk InMemoryOrderModuleList and return the modules it holds."""
        if is_32bit:
            head = ldr + LDR32_IN_MEMORY_ORDER_LIST
            links = LDR32_ENTRY_IN_MEMORY_ORDER_LINKS
            base_at, size_at = LDR32_ENTRY_DLL_BASE, LDR32_ENTRY_SIZE_OF_IMAGE
            full_at, name_at = LDR32_ENTRY_FULL_DLL_NAME, LDR32_ENTRY_BASE_DLL_NAME
            read_ptr, read_text = self._read_u32, self._read_unicode32
            bitness = "32-bit"
        else:
            head = ldr + LDR64_IN_MEMORY_ORDER_LIST
            links = LDR64_ENTRY_IN_MEMORY_ORDER_LINKS
            base_at, size_at = LDR64_ENTRY_DLL_BASE, LDR64_ENTRY_SIZE_OF_IMAGE
            full_at, name_at = LDR64_ENTRY_FULL_DLL_NAME, LDR64_ENTRY_BASE_DLL_NAME
            read_ptr, read_text = self._read_u64, self._read_unicode64
            bitness = "64-bit"

        modules = []
        seen = set()
        try:
            link = read_ptr(head)
        except Exception:
            return modules
        for _step in range(2048):
            if not link or link == head or link in seen:
                break
            seen.add(link)
            entry = link - links
            try:
                base = read_ptr(entry + base_at)
                size = read_ptr(entry + size_at)
                name = read_text(entry + name_at)
                path = read_text(entry + full_at)
            except Exception:
                break
            if base and name:
                modules.append(ModuleInfo(name, path or name, base, size, bitness))
            try:
                link = read_ptr(link)
            except Exception:
                break
        return modules

    def modules_from_peb(self, is_32bit):
        peb = self.peb32() if is_32bit else self._peb_basic()
        if not peb:
            return []
        try:
            ldr = self._read_u32(peb + PEB32_LDR) if is_32bit else self._read_u64(peb + PEB64_LDR)
        except Exception:
            return []
        if not ldr:
            return []
        return self._walk_loader(ldr, is_32bit)

    def _peb_basic(self):
        buffer = (ctypes.c_ubyte * 48)()
        returned = wintypes.ULONG(0)
        status = ntdll.NtQueryInformationProcess(
            self.handle, PROCESS_BASIC_INFORMATION, buffer, 48, ctypes.byref(returned)
        )
        if (status & 0xFFFFFFFF) != 0:
            return None
        return int.from_bytes(bytes(buffer)[8:16], "little") or None

    def modules(self, refresh=False):
        if self._modules is not None and not refresh:
            return self._modules
        from .pe import size_of_image

        found = {}
        flags = [(LIST_MODULES_ALL, "64-bit")] if self.is_64bit else []

        if not self.is_64bit:
            # For a WOW64 target the loader list is the only source that works:
            # EnumProcessModulesEx hands back the emulating host's modules.
            for module in self.modules_from_peb(True):
                found[module.name.lower()] = module
            if not found:
                flags.append((LIST_MODULES_32BIT, "32-bit"))

        for flag, bitness in flags:
            capacity = 2048
            array = (ctypes.c_void_p * capacity)()
            needed = wintypes.DWORD(0)
            if not k32.K32EnumProcessModulesEx(
                self.handle, array, ctypes.sizeof(array), ctypes.byref(needed), flag
            ):
                continue
            count = min(needed.value // ctypes.sizeof(ctypes.c_void_p), capacity)
            for index in range(count):
                base = array[index]
                if not base:
                    continue
                buffer = ctypes.create_unicode_buffer(1024)
                if not k32.K32GetModuleFileNameExW(
                    self.handle, ctypes.c_void_p(base), buffer, 1024
                ):
                    continue
                path = buffer.value
                if not path:
                    continue
                name = os.path.basename(path)
                if name.lower() in found:
                    continue
                size = 0
                try:
                    mbi = self.query(base)
                    if int(mbi.AllocationBase or 0) == base:
                        size = int(mbi.RegionSize or 0)
                except Exception:
                    size = 0
                disk_size = size_of_image(path)
                if disk_size:
                    size = disk_size
                found[name.lower()] = ModuleInfo(name, path, base, size, bitness)
        self._modules = sorted(found.values(), key=lambda module: module.base)
        return self._modules

    def module(self, name):
        lowered = (name or "").lower()
        if not lowered:
            return None
        for module in self.modules():
            if module.name.lower() == lowered or module.path.lower() == lowered:
                return module
        stem = os.path.splitext(lowered)[0]
        for module in self.modules():
            if os.path.splitext(module.name.lower())[0] == stem:
                return module
        return None

    def module_by_base(self, address):
        for module in self.modules():
            if module.base == address:
                return module
        return None

    def module_containing(self, address):
        """The module whose image an address falls inside, if any."""
        address = int(address)
        best = None
        for module in self.modules():
            if not module.size:
                continue
            if module.base <= address < module.base + module.size:
                if best is None or module.size < best.size:
                    best = module
        return best

    def string_in_target(self, text):
        raw = text.encode("utf-8") + b"\x00"
        address = self.alloc(len(raw))
        self.write(address, raw)
        return address

    def read_cstr(self, address, limit=512):
        out = bytearray()
        cursor = address
        while len(out) < limit:
            chunk = self.read(cursor, min(32, limit - len(out)), partial=True)
            if not chunk:
                break
            end = chunk.find(b"\x00")
            if end != -1:
                out += chunk[:end]
                break
            out += chunk
            cursor += len(chunk)
        return out.decode("utf-8", "replace")

    def with_strings(self, values):
        return _TargetStrings(self, values)

    def pointer(self, address):
        return int.from_bytes(self.read_exact(address, self.ptr_size), "little")

    def follow(self, base_address, offsets):
        """Walk a pointer chain, returning the final address and each hop."""
        current = int(base_address)
        trail = []
        for offset in offsets:
            current = self.pointer(current)
            trail.append(current)
            current += offset
        return current, trail

    def _run_at(self, code_address, parameter, timeout):
        kernel32.FlushInstructionCache(
            self.handle, ctypes.c_void_p(code_address), BLOCK_SIZE
        )
        thread = kernel32.CreateRemoteThread(
            self.handle, None, 0, ctypes.c_void_p(code_address),
            ctypes.c_void_p(parameter), 0, None,
        )
        if not thread:
            raise Win32Error("CreateRemoteThread", ctypes.get_last_error())
        try:
            kernel32.WaitForSingleObject(thread, timeout)
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeThread(thread, ctypes.byref(code)):
                raise Win32Error("GetExitCodeThread", ctypes.get_last_error())
            return code.value
        finally:
            kernel32.CloseHandle(thread)

    def remote_call_n(self, func, args, timeout=15000):
        """Call func(args[0..n]) inside the target, returning the raw return value.

        args is a list of integers, one per register argument (rcx/rdx/r8/r9 on
        x64, the first cdecl pushes on x86). Up to 4 arguments on x64 and 8 on
        x86, which covers every mono_*/il2cpp_* entry point used here.

        The data pointer lives in rbx, which the x64 ABI makes callee saved, so
        it survives the call. Stack is push rbx; sub rsp,0x20 so rsp is 16-byte
        aligned at the call site.
        """
        if self.closed or not self.handle:
            raise Win32Error("remote_call", 6)
        if not self.writable:
            raise PermissionError("target is read-only; unlock it first")
        self.require_injection("calling a function inside the target")
        limit = 4 if self.is_64bit else 8
        if len(args) > limit:
            raise Win32Error(f"remote_call supports at most {limit} arguments")

        block = self.alloc(BLOCK_SIZE, executable=True)
        data = block + DATA_OFFSET
        try:
            args = [int(value) for value in args] + [0] * (limit - len(args))
            if self.is_64bit:
                # layout: 4 argument slots, then the function pointer, then the
                # result slot, all 8 bytes wide
                self.write(data, struct.pack("<6Q", *args, func, 0))
                shellcode = b"".join([
                    bytes([0x53]),                                 # push rbx
                    bytes([0x48, 0x83, 0xEC, 0x20]),               # sub rsp, 0x20
                    bytes([0x48, 0xBB]) + struct.pack("<Q", data),  # mov rbx, data
                    bytes([0x48, 0x8B, 0x0B]),                     # mov rcx, [rbx]
                    bytes([0x48, 0x8B, 0x53, 0x08]),               # mov rdx, [rbx+8]
                    bytes([0x4C, 0x8B, 0x43, 0x10]),               # mov r8,  [rbx+16]
                    bytes([0x4C, 0x8B, 0x4B, 0x18]),               # mov r9,  [rbx+24]
                    bytes([0xFF, 0x53, 0x20]),                     # call [rbx+32]
                    bytes([0x48, 0x89, 0x43, 0x28]),               # mov [rbx+40], rax
                    bytes([0x48, 0x83, 0xC4, 0x20]),               # add rsp, 0x20
                    bytes([0x5B]),                                 # pop rbx
                    bytes([0xC3]),                                 # ret
                ])
            else:
                # layout: 8 argument slots, then the function pointer, then the
                # result slot, all 4 bytes wide
                self.write(data, struct.pack("<10I", *args, func, 0))
                parts = []
                for index in reversed(range(len(args))):
                    parts.append(bytes([0xA1]) + struct.pack("<I", data + index * 4))
                    parts.append(bytes([0x50]))
                parts.append(bytes([0xFF, 0x15]) + struct.pack("<I", data + 32))
                parts.append(bytes([0x81, 0xC4]) + struct.pack("<I", len(args) * 4))
                parts.append(bytes([0xA3]) + struct.pack("<I", data + 40))
                parts.append(bytes([0xC3]))
                shellcode = b"".join(parts)
            result_slot = data + 40
            self.write(block + CODE_OFFSET, shellcode)
            self._run_at(block, 0, timeout)
            raw = self.read(result_slot, 8 if self.is_64bit else 4)
            return int.from_bytes(raw, "little") if raw else 0
        finally:
            try:
                self.free(block)
            except Exception:
                pass

    def remote_call(self, func, argbuf=b"", timeout=15000):
        """Single-argument form: func(argbuf), where argbuf is raw bytes."""
        if not argbuf:
            return self.remote_call_n(func, [], timeout)
        address = self.alloc(len(argbuf))
        try:
            self.write(address, argbuf)
            return self.remote_call_n(func, [address], timeout)
        finally:
            try:
                self.free(address)
            except Exception:
                pass


    def run_shellcode(self, code, timeout=15000):
        """Write and execute code in the target, returning the thread exit code."""
        if not self.writable:
            raise PermissionError("target is read-only; unlock it first")
        self.require_injection("running shellcode in the target")
        address = self.alloc(BLOCK_SIZE, executable=True)
        try:
            self.write(address, bytes(code))
            return self._run_at(address, 0, timeout)
        finally:
            try:
                self.free(address)
            except Exception:
                pass


class _TargetStrings:
    """Allocates NUL-terminated strings in the target and frees them on exit.

    Every managed lookup needs a namespace and a type name passed as const char*
    arguments, and leaking one allocation per lookup adds up fast in a long
    session.
    """

    def __init__(self, proc, values):
        self.proc = proc
        self.values = list(values)
        self.addresses = []

    def __enter__(self):
        for value in self.values:
            self.addresses.append(self.proc.string_in_target(value))
        return self.addresses

    def __exit__(self, *_):
        for address in self.addresses:
            try:
                self.proc.free(address)
            except Exception:
                pass
        return False

