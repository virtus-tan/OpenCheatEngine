"""Cheat Engine integration test: does the Lua agent actually work?

    python tests/cetest.py

Starts the bridge, launches Cheat Engine, waits for the agent to dial in over the
file spool, then drives it: attach a process, add rows to its address list,
register a symbol, disassemble, read the list back and detach.

This is the only test that needs Cheat Engine installed. It skips itself if the
agent is not in an autorun folder.
"""

import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ce_bridge.bridge import Bridge
from ce_bridge.config import Config
from ce_bridge.server import BridgeServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["CEBRIDGE_SPOOL"] = os.path.join(
    tempfile.gettempdir(), f"ce_spool_ce_{os.getpid()}")
LAB = os.path.join(ROOT, "lab", "lab_target.exe")
LAB_LOG = os.path.join(ROOT, "lab", "ce_truth.txt")

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


def wait_for(predicate, timeout=45.0, every=0.4):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception:
            pass
        time.sleep(every)
    return None


def launch_lab():
    with open(LAB_LOG, "w", encoding="utf-8") as handle:
        child = subprocess.Popen([LAB], stdout=handle)
    truth = {}
    deadline = time.time() + 15
    while time.time() < deadline:
        content = open(LAB_LOG, encoding="utf-8").read()
        for line in content.splitlines():
            if "=" in line:
                key, value = line.strip().split("=", 1)
                truth[key] = value
        if "LAB_TARGET_END" in content:
            return child, truth
        time.sleep(0.2)
    child.kill()
    return None, {}


def main():
    config = Config()
    config.data["port"] = 9911
    config.data["log_file"] = os.path.join(ROOT, "lab", "cetest.log")
    bridge = Bridge(config).start()
    server = BridgeServer(bridge)
    server.start_background()

    if not bridge.ce.agent_installed():
        print("The Cheat Engine agent is not installed. Run: python bridge.py install-agent")
        server.shutdown()
        bridge.stop()
        return 2

    lab, truth = launch_lab()
    ce = None
    try:
        section("launching Cheat Engine")
        launched = bridge.execute("ce_launch", {"arch": "x64"})
        check("Cheat Engine starts", launched["ok"] and launched["result"]["ok"],
              str(launched)[:200])
        ce_pid = launched["result"].get("pid")
        print(f"  Cheat Engine pid {ce_pid}")

        section("the agent dials in")
        seen = wait_for(lambda: bridge.ce.state.get("agent_seen"), 60)
        check("the agent connects within a minute", bool(seen),
              str(bridge.ce.status())[:300])
        if not seen:
            return finish(server, bridge, lab, ce_pid)

        hello = bridge.execute("ce_ce_status", {"action": "status"})["result"]
        check("the agent reports a version", bool(hello.get("agent_version")),
              str(hello)[:200])
        check("Cheat Engine reports its version", bool(hello.get("ce_version")),
              str(hello)[:200])
        check("the agent reports the address list as usable",
              hello.get("address_list_supported") is True, str(hello)[:300])
        print(f"  agent can do: {', '.join(hello.get('capabilities') or [])[:400]}")

        section("commands with nothing attached")
        status = bridge.execute("ce_addresses", {})["result"]
        check("the agent answers list_addresses", status["ok"], str(status)[:200])
        message = bridge.execute("ce_message", {"text": "bridge test"})["result"]
        check("the agent answers show_message", message["ok"], str(message)[:200])

        section("attaching a process through Cheat Engine")
        attached = bridge.execute("ce_status", {})["result"]
        check("Cheat Engine has nothing attached yet",
              not attached["cheat_engine"]["attached_pid"], str(attached)[:200])

        reply = bridge.ce.call("open_process", pid=lab.pid)
        check("the agent can open a process", reply.get("ok"), str(reply)[:200])

        adopted = wait_for(
            lambda: bridge.target if bridge.target and bridge.target.pid == lab.pid else None,
            25,
        )
        check("the bridge adopts the process the human attached in Cheat Engine",
              adopted is not None, str(bridge.status()["target"] or "no target")[:300])
        if not adopted:
            return finish(server, bridge, lab, ce_pid)

        target_status = bridge.status()["target"]
        check("the adopted target is the right process", target_status["pid"] == lab.pid,
              str(target_status)[:200])
        check("the target came from cheat-engine", target_status["source"] == "cheat-engine",
              target_status["source"])
        check("the target arch matches", target_status["arch"] == "x64", target_status["arch"])
        check("the target starts read-only", target_status["writable"] is False)

        ce_status = bridge.status()["cheat_engine"]
        check("the agent reports the same pid", ce_status["attached_pid"] == lab.pid,
              str(ce_status)[:200])
        check("the agent knows the process name",
              (ce_status["attached_name"] or "").lower().startswith("lab_target"),
              str(ce_status.get("attached_name")))

        section("reading the same memory both ways")
        health = int(truth["g_health"], 16)
        via_bridge = bridge.execute("read", {"address": hex(health), "type": "i32"})["result"]
        check("the bridge reads the adopted process", via_bridge["value"] is not None,
              str(via_bridge)[:200])
        resolved = bridge.execute("ce_resolve", {"expression": "lab_target.exe"})["result"]
        check("Cheat Engine resolves the module", resolved.get("address"),
              str(resolved)[:200])

        section("mirroring findings into Cheat Engine")
        mirror = bridge.execute("ce_ce_mirror", {"items": [
            {"address": hex(health), "name": "health?", "type": "i32",
             "comment": "found by the bridge"},
            {"address": truth["g_mana"], "name": "mana?", "type": "f32"},
        ]})["result"]
        check("two rows were added", mirror["added"] == 2, str(mirror)[:300])
        check("nothing failed", mirror["failed"] == 0, str(mirror)[:300])

        listing = bridge.execute("ce_addresses", {})["result"]
        names = [item["name"] for item in listing.get("items", []) if item.get("name")]
        check("the address list now holds the rows", "health?" in names, str(names)[:300])
        check("Cheat Engine agrees on the row count", listing.get("count", 0) >= 2,
              str(listing.get("count")))

        section("Cheat Engine side helpers")
        symbol = bridge.execute("ce_register_symbol",
                                {"name": "bridge_probe", "address": hex(health)})["result"]
        check("a symbol registers", symbol["name"] == "bridge_probe", str(symbol)[:200])
        after = bridge.execute("ce_resolve", {"expression": "bridge_probe"})["result"]
        check("the symbol resolves to the address",
              after.get("address", "").lower() == hex(health).lower(),
              f"{after} vs {hex(health)}")

        dis = bridge.execute("ce_disassemble",
                             {"address": truth["marker"], "count": 2})["result"]
        check("Cheat Engine disassembles at an address", bool(dis.get("text")),
              str(dis)[:200])

        auto = bridge.execute("ce_autoassemble", {
            "script": "[ENABLE]\nalloc(aobtest,8)\nregistersymbol(aobtest)\n"
                      "aobtest:\ndb 90 90 90 90 90 90 90 90\n[DISABLE]\n"
                      "dealloc(aobtest)\nunregistersymbol(aobtest)\n",
        })["result"]
        check("Cheat Engine autoassembles", auto.get("success") is True, str(auto)[:200])

        section("detaching")
        reply = bridge.ce.call("close_process", timeout=10)
        check("the agent can close the process", reply.get("ok"), str(reply)[:200])
        released = wait_for(lambda: bridge.target is None, 20)
        check("the bridge releases the target when Cheat Engine detaches", bool(released),
              str(bridge.status()["target"] or "no target")[:200])
    finally:
        ce = ce_pid
        return finish(server, bridge, lab, ce)


def finish(server, bridge, lab, ce_pid):
    try:
        if lab:
            lab.kill()
    except Exception:
        pass
    if ce_pid:
        subprocess.run(["taskkill", "/PID", str(ce_pid), "/F"],
                       capture_output=True, text=True)
    server.shutdown()
    bridge.stop()
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"  FAILED: {name} {detail}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())

