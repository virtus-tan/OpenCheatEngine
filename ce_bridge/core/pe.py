"""Minimal PE reader: image size and export table lookup.

Used for two things: SizeOfImage for module sizing, and resolving an export
RVA off disk so a 64-bit bridge can find the 32-bit LoadLibraryA inside a
32-bit target (ASLR gives every process of the same bitness the same base).
"""

import os
import struct

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = b"PE\x00\x00"

OPTIONAL_PE32 = 0x10B
OPTIONAL_PE32_PLUS = 0x20B

SIZE_OF_IMAGE_OFFSET = 56
DATA_DIRECTORY_OFFSET = {OPTIONAL_PE32: 96, OPTIONAL_PE32_PLUS: 112}


class PEError(RuntimeError):
    pass


class Section:
    __slots__ = ("name", "virtual_size", "virtual_address", "raw_size", "raw_pointer",
                 "characteristics")

    def __init__(self, name, virtual_size, virtual_address, raw_size, raw_pointer,
                 characteristics=0):
        self.name = name
        self.virtual_size = virtual_size
        self.virtual_address = virtual_address
        self.raw_size = raw_size
        self.raw_pointer = raw_pointer
        self.characteristics = characteristics

    @property
    def executable(self):
        return bool(self.characteristics & 0x20000000)

    @property
    def writable(self):
        return bool(self.characteristics & 0x80000000)

    def contains(self, rva):
        span = max(self.virtual_size, self.raw_size)
        return self.virtual_address <= rva < self.virtual_address + span


class PEImage:
    def __init__(self, data):
        self.data = data
        if len(data) < 0x40 or struct.unpack_from("<H", data, 0)[0] != IMAGE_DOS_SIGNATURE:
            raise PEError("not a PE file (missing MZ)")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != IMAGE_NT_SIGNATURE:
            raise PEError("not a PE file (missing PE signature)")

        coff = pe_offset + 4
        self.machine, self.section_count = struct.unpack_from("<HH", data, coff)
        optional_size = struct.unpack_from("<H", data, coff + 16)[0]
        optional = coff + 20
        self.magic = struct.unpack_from("<H", data, optional)[0]
        if self.magic not in DATA_DIRECTORY_OFFSET:
            raise PEError(f"unsupported optional header magic 0x{self.magic:04X}")

        self.size_of_image = struct.unpack_from("<I", data, optional + SIZE_OF_IMAGE_OFFSET)[0]
        self.image_base = struct.unpack_from(
            "<Q" if self.magic == OPTIONAL_PE32_PLUS else "<I",
            data,
            optional + (24 if self.magic == OPTIONAL_PE32_PLUS else 28),
        )[0]
        self.entry_point = struct.unpack_from("<I", data, optional + 16)[0]

        directory = optional + DATA_DIRECTORY_OFFSET[self.magic]
        self.export_dir_rva, self.export_dir_size = struct.unpack_from("<II", data, directory)

        table = optional + optional_size
        self.sections = []
        for index in range(self.section_count):
            entry = table + index * 40
            name = data[entry:entry + 8].split(b"\x00")[0].decode("ascii", "replace")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                "<IIII", data, entry + 8
            )
            characteristics = struct.unpack_from("<I", data, entry + 36)[0]
            self.sections.append(Section(name, virtual_size, virtual_address, raw_size,
                                        raw_pointer, characteristics))

    @property
    def is_64bit(self):
        return self.magic == OPTIONAL_PE32_PLUS

    def rva_to_offset(self, rva):
        for section in self.sections:
            if section.contains(rva):
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    raise PEError(f"rva 0x{rva:X} is not backed by file data")
                return section.raw_pointer + delta
        raise PEError(f"rva 0x{rva:X} is outside every section")

    def read_rva(self, rva, size):
        offset = self.rva_to_offset(rva)
        return self.data[offset:offset + size]

    def exports(self):
        """Return {name: rva} for the export directory, empty when absent.

        Forwarded exports are included with their RVA pointing at the forwarder
        string, which is what the Windows loader itself does. Use is_forwarder
        to tell the two apart; calling a forwarder string as code silently
        returns garbage.
        """
        if not self.export_dir_rva:
            return {}
        base = self.rva_to_offset(self.export_dir_rva)
        fields = struct.unpack_from("<IIHHIIIIIII", self.data, base)
        number_of_functions = fields[6]
        number_of_names = fields[7]
        functions_rva = fields[8]
        names_rva = fields[9]
        ordinals_rva = fields[10]
        if not number_of_names:
            return {}

        names_offset = self.rva_to_offset(names_rva)
        ordinals_offset = self.rva_to_offset(ordinals_rva)
        functions_offset = self.rva_to_offset(functions_rva)

        table = {}
        for index in range(number_of_names):
            name_rva = struct.unpack_from("<I", self.data, names_offset + index * 4)[0]
            ordinal = struct.unpack_from("<H", self.data, ordinals_offset + index * 2)[0]
            if ordinal >= number_of_functions:
                continue
            func_rva = struct.unpack_from("<I", self.data, functions_offset + ordinal * 4)[0]
            name = self.read_rva(name_rva, 256).split(b"\x00")[0].decode("ascii", "replace")
            if name:
                table[name] = func_rva
        return table

    def is_forwarder(self, rva):
        """True when an export RVA points at a forwarder string, not code."""
        if not self.export_dir_rva or not self.export_dir_size:
            return False
        return self.export_dir_rva <= rva < self.export_dir_rva + self.export_dir_size

    def forwarder(self, rva):
        """The 'OTHER.dll.export' string an export RVA forwards to."""
        if not self.is_forwarder(rva):
            return None
        return self.read_rva(rva, 256).split(b"\x00")[0].decode("ascii", "replace")

    def export_rva(self, name):
        return self.exports().get(name)


def load(path):
    with open(path, "rb") as handle:
        return PEImage(handle.read())


def size_of_image(path):
    try:
        return load(path).size_of_image
    except Exception:
        return 0


def export_rva(path, name):
    try:
        return load(path).export_rva(name)
    except Exception:
        return None


def resolve_export_chain(path, name, max_hops=8):
    """Follow export forwarders, returning [(dll, name), ...] ending at real code.

    Windows 10 and 11 forward most of kernel32 to KernelBase, so the RVA in
    kernel32's own table points at a string, not at code. Anything that intends
    to call an export has to walk the chain.
    """
    chain = []
    current_path, current_name = path, name
    for _hop in range(max_hops):
        try:
            image = load(current_path)
            rva = image.export_rva(current_name)
        except Exception:
            return chain, None
        if rva is None:
            return chain, None
        if not image.is_forwarder(rva):
            return chain, rva
        target = image.forwarder(rva)
        if not target or "." not in target:
            return chain, None
        dll, _, exported = target.partition(".")
        directory = os.path.dirname(os.path.abspath(current_path))
        candidate = os.path.join(directory, dll)
        if not os.path.exists(candidate):
            system = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                  "System32" if os.path.basename(directory).lower() == "syswow64"
                                  else "SysWOW64" if directory.lower().endswith("system32")
                                  else "System32", dll)
            candidate = system if os.path.exists(system) else None
        if not candidate:
            return chain, None
        chain.append((dll, exported))
        current_path, current_name = candidate, exported
    return chain, None


def export_rvas(path, pattern=None):
    try:
        table = load(path).exports()
    except Exception:
        return {}
    if pattern is None:
        return table
    lowered = pattern.lower()
    return {name: rva for name, rva in table.items() if lowered in name.lower()}


_cache = {}


def cached_exports(path):
    key = os.path.normcase(os.path.abspath(path))
    if key not in _cache:
        _cache[key] = load(path).exports()
    return _cache[key]
