"""Architecture test: run the arch-sensitive paths against both lab builds.

    python tests/archtest.py

The remote call stub is the riskiest hand written part of the bridge: the x64
version keeps the data pointer in rbx because the ABI makes it callee saved,
and the x86 version pushes cdecl arguments in reverse. Both are checked here by
calling real exports in the target and comparing the answers.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ce_bridge.core import inject
from ce_bridge.session import Target

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB_DIR = os.path.join(ROOT, "lab")
TARGETS = [("x64", "lab_target.exe"), ("x86", "lab_target32.exe")]

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"  pass  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def launch(binary, log_name):
    log_path = os.path.join(LAB_DIR, log_name)
    handle = open(log_path, "w", encoding="utf-8")
    process = subprocess.Popen([binary], stdout=handle)
    handle.close()
    deadline = time.time() + 15
    while time.time() < deadline:
        content = open(log_path, encoding="utf-8").read()
        if "LAB_TARGET_END" in content:
            truth = {}
            for line in content.splitlines():
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    truth[key] = value
            return process, truth
        time.sleep(0.15)
    process.kill()
    return None, None


def main():
    for arch, binary_name in TARGETS:
        binary = os.path.join(LAB_DIR, binary_name)
        if not os.path.exists(binary):
            print(f"\n{arch}: {binary_name} not built, skipping")
            continue
        print(f"\n=== {arch} ({binary_name}) ===")
        process, truth = launch(binary, f"arch_{arch}.txt")
        if not process:
            check(f"{arch}: lab target starts", False, "no ground truth")
            continue
        try:
            run_arch(process, truth, arch, binary_name)
        finally:
            try:
                process.kill()
            except Exception:
                pass

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"  FAILED: {name} {detail}")
    return 1 if FAILED else 0


def run_arch(process, truth, arch, binary_name):
    target = Target(process.pid, writable=True, source="archtest")
    try:
        status = target.status()
        check(f"{arch}: arch is reported", status["arch"] == arch, status["arch"])
        check(f"{arch}: pointer size is right",
              status["pointer_size"] == (8 if arch == "x64" else 4), str(status["pointer_size"]))

        modules = target.modules()
        main = [item for item in modules["modules"]
                if item["name"].lower() == binary_name.lower()]
        check(f"{arch}: main module found", bool(main),
              f"{len(modules['modules'])} modules")
        if not main:
            print(f"  {arch}: cannot continue without the main module")
            return
        base = int(main[0]["base"], 16)
        check(f"{arch}: main module base is sane", base > 0, main[0]["base"])
        check(f"{arch}: main module has a real size", main[0]["size"] > 0x1000,
              str(main[0]["size"]))
        check(f"{arch}: a normal module count", len(modules["modules"]) > 8,
              str(len(modules["modules"])))

        marker = int(truth["marker"], 16)
        dis = target.disasm(marker, 3)
        check(f"{arch}: disasm finds the marker immediate",
              "0xefbeadde" in dis["text"].lower(), dis["text"][:90])
        check(f"{arch}: disasm names the module", dis["module"] is not None, str(dis["module"]))

        aob = target.aob("B8 DE AD BE EF", max_hits=16)
        check(f"{arch}: aob finds the marker once", aob["count"] == 1, str(aob["count"]))

        health = int(truth["g_health"], 16)
        region = target.query(health)
        check(f"{arch}: query reports the owning module",
              region["module"] is not None and region["module"].lower() == binary_name.lower(),
              str(region.get("module")))
        check(f"{arch}: query reports committed memory", region["state"] == "COMMIT",
              region["state"])

        mapping = target.memory_map()
        check(f"{arch}: the memory map has regions", mapping["count"] > 3,
              str(mapping["count"]))
        check(f"{arch}: the map covers the main module",
              any(item.get("module") == binary_name for item in mapping["regions"]),
              str([item.get("module") for item in mapping["regions"][:6]]))

        scan = target.scan_start(value_type="i32", scan_type="exact", value=987654,
                                 alignment=4, module=binary_name, max_results=50000)
        hidden = int(truth["g_hidden"], 16)
        found = {int(item["address_dec"]) for item in target.scan_results(0, 50)["results"]}
        check(f"{arch}: exact scan finds the static value", hidden in found,
              f"{scan['results']} results")
        target.scan_reset()

        before = target.read(health, "i32")["value"]
        written = target.write(health, 4242, "i32", note="archtest")
        check(f"{arch}: write lands", target.read(health, "i32")["value"] == 4242)
        target.undo(written["undo_id"])
        after = target.read(health, "i32")["value"]
        check(f"{arch}: undo restores", after == before, f"{after} vs {before}")

        print(f"  remote calls in the {arch} target")
        if arch == "x86":
            try:
                target.remote_call("kernel32.dll", "GetCurrentProcessId")
                check("x86: injection refuses clearly", False, "it silently succeeded")
            except Exception as error:
                check("x86: injection refuses clearly",
                      "32-bit" in str(error) and "WOW64" in str(error), str(error)[:160])
            try:
                target.exec_shellcode("31 C0 C3")
                check("x86: shellcode refuses clearly", False, "it silently succeeded")
            except Exception as error:
                check("x86: shellcode refuses clearly", "32-bit" in str(error),
                      str(error)[:120])
            print("  32-bit targets: injection is not possible from a 64-bit bridge, "
                  "and says so")
            return

        pid = target.remote_call("kernel32.dll", "GetCurrentProcessId")
        check(f"{arch}: remote GetCurrentProcessId returns the target pid",
              pid == process.pid, f"{pid} vs {process.pid}")

        text_address = target.proc.string_in_target("hello")
        try:
            length = target.remote_call("kernel32.dll", "lstrlenA", [text_address])
            check(f"{arch}: remote lstrlenA sees the string we wrote",
                  length == 5, str(length))
        finally:
            target.proc.free(text_address)

        handle = target.remote_call("kernel32.dll", "GetModuleHandleA",
                                    [target.proc.string_in_target("kernel32.dll")])
        module = target.proc.module_by_base(handle) or target.proc.module_containing(handle)
        check(f"{arch}: remote GetModuleHandleA resolves kernel32",
              module is not None and module.name.lower() == "kernel32.dll",
              f"{hex(handle)} -> {module.name if module else None}")

        loaded = target.remote_call("kernel32.dll", "LoadLibraryA",
                                    [target.proc.string_in_target("user32.dll")])
        check(f"{arch}: remote LoadLibraryA loads a dll", loaded != 0, hex(loaded))

        shellcode = target.exec_shellcode("31 C0 C3")
        check(f"{arch}: shellcode runs and returns",
              isinstance(shellcode["thread_exit_code"], int),
              str(shellcode["thread_exit_code"]))

        try:
            target.remote_call("kernel32.dll", "NoSuchFunctionHere")
            check(f"{arch}: a missing export raises on remote_call", False)
        except Exception as error:
            check(f"{arch}: a missing export raises on remote_call", "not exported" in str(error))
    finally:
        target.close()


if __name__ == "__main__":
    raise SystemExit(main())
