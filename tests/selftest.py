"""Self test: run the lab target and check the bridge against known addresses.

    python tests/selftest.py

The lab target prints the absolute address and the first bytes of every global
and function it owns, so each assertion is a fact about the process rather than
a guess. Exits non-zero if anything failed.
"""

import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ce_bridge.core import disasm, inject, signature
from ce_bridge.core import valuetypes as vt
from ce_bridge.session import Target

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, "lab", "lab_target.exe")
TRUTH_LOG = os.path.join(ROOT, "lab", "lab_truth.txt")

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"  pass  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def section(title):
    print(f"\n{title}")


def launch():
    handle = open(TRUTH_LOG, "w", encoding="utf-8")
    process = subprocess.Popen([LAB], stdout=handle)
    handle.close()
    truth = {}
    deadline = time.time() + 15
    while time.time() < deadline:
        with open(TRUTH_LOG, "r", encoding="utf-8") as reader:
            content = reader.read()
        for line in content.splitlines():
            if "=" in line:
                key, value = line.strip().split("=", 1)
                truth[key] = value
        if "LAB_TARGET_END" in content:
            return process, truth
        time.sleep(0.15)
    process.kill()
    raise SystemExit(f"lab target did not report its ground truth; see {TRUTH_LOG}")


def all_scan_addresses(target, page=500, cap=20000):
    """Page through every result, since a narrow hit can sit past the first page."""
    found = set()
    offset = 0
    while offset < cap:
        payload = target.scan_results(offset, page)
        for item in payload["results"]:
            found.add(int(item["address_dec"]))
        offset += payload["returned"]
        if offset >= payload["total"] or payload["returned"] == 0:
            break
    return found


def main():
    if not os.path.exists(LAB):
        raise SystemExit(f"lab target not built: {LAB}\nBuild it with lab\\build_lab.bat")
    process, truth = launch()
    print(f"lab target pid {process.pid}")
    try:
        run_tests(process, truth)
    finally:
        try:
            process.kill()
        except Exception:
            pass
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"  FAILED: {name} {detail}")
    return 1 if FAILED else 0


def run_tests(process, truth):
    target = Target(process.pid, writable=False, source="selftest")
    addr = lambda key: int(truth[key], 16)

    health = addr("g_health")
    mana = addr("g_mana")
    coins = addr("g_coins")
    hidden = addr("g_hidden")
    sentinel = addr("g_sentinel")
    player_ptr = addr("g_player_ptr")
    player = addr("player")
    health_offset = int(truth["offset_player_health"])

    section("attachment and layout")
    status = target.status()
    check("arch detected as x64", status["arch"] == "x64", status["arch"])
    check("pointer size is 8", status["pointer_size"] == 8)
    check("starts read-only", status["writable"] is False)
    modules = target.modules()
    check("module list is populated", modules["count"] > 5, str(modules["count"]))
    check("main module is present",
          any(item["name"].lower() == "lab_target.exe" for item in modules["modules"]))
    mapping = target.memory_map()
    check("memory map is populated", mapping["count"] > 20, str(mapping["count"]))

    section("reads against known addresses")
    check("g_health holds a plausible int", 0 < target.read(health, "i32")["value"] <= 100,
          str(target.read(health, "i32")["value"]))
    check("g_mana reads as 75.5", abs(target.read(mana, "f32")["value"] - 75.5) < 0.01,
          str(target.read(mana, "f32")["value"]))
    check("g_hidden reads as 987654", target.read(hidden, "i32")["value"] == 987654)
    check("g_sentinel reads as 0x11223344", target.read(sentinel, "u32")["value"] == 0x11223344)
    check("g_player_ptr points at the player struct",
          target.proc.pointer(player_ptr) == player,
          hex(target.proc.pointer(player_ptr)))
    check("player.health through the pointer is an int",
          isinstance(target.read(player + health_offset, "i32")["value"], int))
    region = target.query(health)
    check("health lives in a committed region", region["state"] == "COMMIT", region["state"])
    check("health region is writable", region["writable"] is True, region["protect"])
    check("region query reports the right base",
          int(region["base"], 16) <= health < int(region["base"], 16) + region["size"])

    section("value types")
    check("u32 round trip", struct.unpack("<I", vt._encode("u32", 0x11223344))[0] == 0x11223344)
    check("f64 round trip", vt._decode("f64", vt._encode("f64", 1.25)) == 1.25)
    check("int32 alias normalises", vt.normalise("int32") == "i32")
    check("float alias normalises", vt.normalise("float") == "f32")
    try:
        vt.normalise("nonsense")
        check("unknown type is rejected", False)
    except ValueError:
        check("unknown type is rejected", True)
    try:
        vt._encode("u8", -1)
        check("negative into unsigned is rejected", False)
    except ValueError:
        check("negative into unsigned is rejected", True)

    section("disassembly")
    marker = addr("marker")
    damage = addr("apply_damage")
    dis = target.disasm(marker, 3)
    check("marker disassembles", dis["count"] >= 1, dis.get("text", "")[:100])
    check("thunk following is reported", isinstance(dis["thunk_hops"], list),
          str(dis["thunk_hops"]))
    check("marker body loads the unique immediate",
          "0xefbeadde" in dis["text"].lower(), dis["text"][:100])
    marker_body = int(dis["address"], 16)
    damage_dis = target.disasm(damage, 1)
    damage_body = int(damage_dis["address"], 16)
    assembled, count = disasm.assemble("mov eax, 0xEFBEADDE", marker_body, True)
    check("keystone rebuilds the same bytes", assembled == b"\xb8\xde\xad\xbe\xef",
          assembled.hex())
    check("keystone counts instructions", count == 1, str(count))
    plain = target.disasm(marker, 1, follow_thunk=False)
    check("thunk following can be turned off",
          plain["address"] == hex(marker), f"{plain['address']} vs {hex(marker)}")

    section("signature scanning")
    pattern, mask = signature.parse_pattern("B8 DE AD BE ??")
    check("parser keeps the trailing wildcard",
          pattern == b"\xb8\xde\xad\xbe\x00" and mask == b"\xff\xff\xff\xff\x00",
          f"{pattern.hex()} {mask.hex()}")
    check("parser handles half byte wildcards",
          signature.parse_pattern("4?") [0] == b"\x40")
    hits = target.aob("B8 DE AD BE EF", max_hits=32)
    check("aob finds exactly one match for the marker immediate",
          hits["count"] == 1, str(hits["count"]))
    if hits["count"] == 1:
        hit = int(hits["hits"][0]["address"], 16)
        check("the aob hit is the marker body", hit == marker_body,
              f"{hex(hit)} vs {hex(marker_body)}")
        check("aob hit carries the instruction",
              "0xefbeadde" in (hits["hits"][0].get("instruction") or "").lower(),
              str(hits["hits"][0].get("instruction")))
    partial = target.aob("B8 ?? AD BE EF", max_hits=32)
    check("partial wildcard still matches", partial["count"] >= 1, str(partial["count"]))
    try:
        target.aob("B8 DE AD BE EF", max_hits=32, require_unique=True)
        check("require_unique accepts a unique signature", True)
    except Exception as error:
        check("require_unique accepts a unique signature", False, str(error)[:120])
    try:
        target.aob("ZZ ZZ")
        check("a malformed signature is rejected", False)
    except Exception as error:
        check("a malformed signature is rejected", "bad pattern" in str(error))

    section("cross references")
    refs = target.xrefs(health, code_only=True, max_hits=128)
    check("xrefs find references to g_health", refs["count"] > 0, str(refs["count"]))
    near = [item for item in refs["xrefs"]
            if abs(int(item["address"], 16) - damage_body) < 0x200]
    check("apply_damage is among the referencing code", bool(near),
          f"{refs['count']} refs; body at {hex(damage_body)}")
    check("xrefs are classified", {item["kind"] for item in refs["xrefs"]} <= {"pointer", "rip"},
          str({item["kind"] for item in refs["xrefs"]}))
    check("xrefs carry an instruction where possible",
          any(item.get("instruction") for item in refs["xrefs"]),
          str([item.get("instruction") for item in refs["xrefs"][:3]]))

    section("pointer chains")
    chains = target.pointer_chains(health, depth=2, max_results=8)
    check("pointer chain search completes", "chains" in chains and "count" in chains)
    if chains["count"]:
        head = int(chains["chains"][0]["head"], 16)
        walked = target.resolve_chain([head], 0)
        check("a discovered chain resolves", walked["steps"][0]["address"] == hex(head),
              str(walked)[:160])

    section("scanning: exact value that never changes")
    scan = target.scan_start(value_type="i32", scan_type="exact", value=987654,
                             alignment=4, max_results=200000)
    found = {int(item["address_dec"])
             for item in target.scan_results(0, 100)["results"]}
    check("exact scan finds g_hidden", hidden in found, f"{scan['results']} results")
    check("exact scan does not report g_health", health not in found)
    exact_sentinel = target.scan_start(value_type="u32", scan_type="exact",
                                       value=0x11223344, alignment=4, max_results=200000)
    sentinel_hits = {int(item["address_dec"])
                     for item in target.scan_results(0, 20)["results"]}
    check("exact scan finds g_sentinel", sentinel in sentinel_hits,
          f"{exact_sentinel['results']} results")

    section("scanning: narrowing")
    first = target.scan_start(value_type="i32", scan_type="unknown_initial",
                              alignment=4, max_results=400000)
    check("unknown initial scan produces candidates", first["results"] > 1000,
          str(first["results"]))
    time.sleep(0.9)
    second = target.scan_next("changed")
    check("changed narrows the set", second["results"] < first["results"],
          f"{first['results']} -> {second['results']}")
    time.sleep(2.0)
    third = target.scan_next("decreased")
    check("decreased narrows further or holds", third["results"] <= second["results"],
          f"{second['results']} -> {third['results']}")
    narrowed = all_scan_addresses(target)
    check("the narrowed set still contains g_health", health in narrowed,
          f"{third['results']} results, g_health at {truth['g_health']}")
    check("the narrowed set dropped g_hidden", hidden not in narrowed,
          "g_hidden never changes and should be gone")

    section("scanning: float and struct")
    live_mana = target.read(mana, "f32")["value"]
    target.scan_start(value_type="f32", scan_type="exact", value=live_mana, alignment=4,
                      max_results=200000)
    floats = all_scan_addresses(target)
    check("float scan finds g_mana", mana in floats,
          f"{len(floats)} results, scanning for {live_mana}")

    live_player = target.read(player, "i32")["value"]
    target.scan_start(value_type="array", scan_type="exact", struct="int32 health; float mana;",
                      values={"health": live_player, "mana": 75.5},
                      alignment=4, max_results=200000)
    structs = all_scan_addresses(target)
    check("struct scan finds the player record", player in structs, f"{len(structs)} results")

    section("scanning: error messages are actionable")
    target.scan_start(value_type="i32", scan_type="unknown_initial", alignment=4,
                      max_results=400000)
    try:
        target.scan_start(value_type="bytes", scan_type="exact",
                          value="AB" * 64, alignment=1, max_results=400000)
        check("an impossible scan raises", False, "no error")
    except Exception as error:
        check("an impossible scan explains itself",
              "no matches" in str(error).lower(), str(error)[:140])
    try:
        target.scan_start(value_type="i32", scan_type="exact", value=1, module="nope.dll")
        check("an unknown module raises", False)
    except Exception as error:
        check("an unknown module lists what is loaded",
              "not loaded" in str(error), str(error)[:140])
    target.scan_reset()
    try:
        target.scan_results()
        check("results without a session raise", False)
    except Exception as error:
        check("results without a session raise", "scan" in str(error).lower())

    section("read-only enforcement")
    try:
        target.write(health, 5, "i32")
        check("writes are refused while read-only", False, "write succeeded")
    except PermissionError as error:
        check("writes are refused while read-only", "read-only" in str(error))
    for name, call in (("inject", lambda: target.inject(r"C:\Windows\System32\user32.dll")),
                       ("shellcode", lambda: target.exec_shellcode("C3")),
                       ("patch", lambda: target.patch(sentinel, "44332211", "00"))):
        try:
            call()
            check(f"{name} is refused while read-only", False, "it ran")
        except PermissionError:
            check(f"{name} is refused while read-only", True)

    section("unlock, write, undo")
    target.unlock(True)
    check("unlock switches to writable", target.writable is True)
    before = target.read(sentinel, "u32")["value"]
    written = target.write(sentinel, 0xAABBCCDD, "u32", note="selftest")
    check("write lands", target.read(sentinel, "u32")["value"] == 0xAABBCCDD)
    check("write reports the previous value",
          int(written["before"][6:8] + written["before"][4:6]
              + written["before"][2:4] + written["before"][0:2], 16) == before,
          written["before"])
    check("write returns an undo id", bool(written.get("undo_id")))
    target.undo(written["undo_id"])
    check("undo restores the value", target.read(sentinel, "u32")["value"] == before)
    check("undo reports one entry", target.journal_list(10)["entries"][0]["undone"] is True)
    try:
        target.undo("deadbeef")
        check("an unknown undo id raises", False)
    except Exception as error:
        check("an unknown undo id raises", "no undoable" in str(error).lower())

    section("byte writes, reads and patches")
    raw = target.read_bytes(sentinel, 4)
    check("read_bytes round trips little endian", raw["hex"] == "44332211", raw["hex"])
    check("read_bytes produces a dump", "0000" in (raw["dump"] or ""), str(raw["dump"])[:80])
    patched_bytes = target.write_bytes(sentinel, "AABBCCDD")
    check("byte write lands", target.read(sentinel, "u32")["value"] == 0xDDCCBBAA)
    target.undo(patched_bytes["undo_id"])
    check("byte write undo restores", target.read(sentinel, "u32")["value"] == 0x11223344)
    patch = target.patch(sentinel, "44 33 22 11", "EF BE AD DE")
    check("patch applies when the bytes match", patch["after"] == "efbeadde", str(patch))
    check("patch names the owning module", patch.get("module", "").lower() == "lab_target.exe",
          str(patch.get("module")))
    target.undo(patch["undo_id"])
    check("patch undo restores", target.read(sentinel, "u32")["value"] == 0x11223344)
    try:
        target.patch(sentinel, "DE AD BE EF", "00 00 00 00")
        check("patch refuses a mismatched expectation", False, "it applied")
    except Exception as error:
        check("patch refuses a mismatched expectation", "refused" in str(error).lower(),
              str(error)[:140])
    check("the refused patch changed nothing",
          target.read(sentinel, "u32")["value"] == 0x11223344)

    section("freeze")
    target.write(health, 100, "i32")
    frozen = target.freeze(health, 100, "i32", interval=0.05)
    check("freeze registers the address", frozen["count"] == 1, str(frozen))
    time.sleep(1.4)
    held = target.read(health, "i32")["value"]
    check("freeze holds the value against the game loop", held == 100, str(held))
    target.unfreeze(health)
    time.sleep(0.9)
    released = target.read(health, "i32")["value"]
    check("unfreeze lets the game write again", released != 100, str(released))
    target.write(health, 100, "i32")
    target.freeze(health, 100, "i32", interval=0.05)
    target.unfreeze_all()
    check("unfreeze_all clears the list", target.freeze_status()["count"] == 0)

    section("watch")
    target.watch(health, "i32", interval=0.1, duration=4.0)
    time.sleep(4.4)
    history = target.watch_list(health)
    distinct = {item["value"] for item in history}
    check("watch collects samples", len(history) > 10, str(len(history)))
    check("watch observes the value changing", len(distinct) > 1, str(sorted(distinct)))
    check("watch samples move monotonically here",
          all(item["t"] <= later["t"] for item, later in zip(history, history[1:])))
    target.unwatch(health)
    check("unwatch stops the sampler", target.watch_list(health) == [])

    section("journal")
    entries = target.journal_list(50)["entries"]
    check("the journal recorded the writes", len(entries) >= 4, str(len(entries)))
    check("the journal records the note", any(item["note"] == "selftest" for item in entries))
    check("undone writes are marked undone", any(item["undone"] for item in entries),
          str([item["undone"] for item in entries]))
    check("the newest write is still active", entries[0]["undone"] is False,
          str(entries[0]))
    check("the journal records before and after bytes",
          all(item["before"] and item["after"] for item in entries),
          str(entries[0]))

    section("managed runtime detection on a native target")
    runtime = target.managed_runtime()
    check("detection completes", runtime.kind in ("native", "mono", "il2cpp"), runtime.kind)
    check("a native target reports no managed folder",
          runtime.status()["has_file_metadata"] is False)
    check("runtime status lists capabilities", isinstance(runtime.status()["capabilities"], list))

    section("export resolution")
    loader = inject.resolve_export(target.proc, "kernel32.dll", "LoadLibraryA")
    check("LoadLibraryA resolves in the target", loader > 0x10000, hex(loader))
    try:
        inject.resolve_export(target.proc, "kernel32.dll", "NoSuchExportAtAll")
        check("a missing export raises", False)
    except Exception as error:
        check("a missing export raises with a hint", "not exported" in str(error),
              str(error)[:140])
    try:
        inject.resolve_export(target.proc, "not_a_module.dll", "LoadLibraryA")
        check("a missing module raises", False)
    except Exception as error:
        check("a missing module raises", "not loaded" in str(error), str(error)[:140])

    section("cleanup")
    target.unfreeze_all()
    target.close()
    check("close is clean", target.proc.closed is True)


if __name__ == "__main__":
    raise SystemExit(main())
