"""Test the bridge's Cheat Engine side against the stand-in agent.

    python tests/celink_test.py

Covers the spool protocol, command dispatch, the attach handshake and the
mirroring path, without needing Cheat Engine, elevation or a GUI.
"""

import os
import subprocess
import tempfile
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ce_bridge.bridge import Bridge
from ce_bridge.config import Config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["CEBRIDGE_SPOOL"] = os.path.join(
    tempfile.gettempdir(), f"ce_spool_link_{os.getpid()}")
LAB = os.path.join(ROOT, "lab", "lab_target.exe")
FAKE = os.path.join(ROOT, "tests", "fake_agent.py")
LAB_LOG = os.path.join(ROOT, "lab", "celink_truth.txt")

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


def wait_for(predicate, timeout=25.0, every=0.3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(every)
    return False


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
    config.data["port"] = 9912
    config.data["log_file"] = os.path.join(ROOT, "lab", "celink.log")
    bridge = Bridge(config).start()

    lab, truth = launch_lab()
    agent = subprocess.Popen([sys.executable, FAKE], cwd=ROOT,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        section("the agent connects")
        check("the agent is seen", wait_for(lambda: bridge.ce.state.get("agent_seen")),
              str(bridge.ce.status())[:300])

        section("the handshake")
        hello = bridge.execute("ce_status", {})["result"]
        check("the agent version is read", hello.get("agent_version") == "1.0",
              str(hello.get("agent_version")))
        check("the Cheat Engine version is read", hello.get("ce_version") == "7.4-fake",
              str(hello.get("ce_version")))
        check("capabilities are reported", len(hello.get("capabilities") or []) > 5,
              str(hello.get("capabilities"))[:200])
        check("the address list is reported as usable",
              hello.get("address_list_supported") is True, str(hello)[:200])
        check("nothing is attached yet", not hello.get("attached_pid"), str(hello)[:200])

        section("commands")
        listing = bridge.execute("ce_addresses", {})["result"]
        check("an empty address list reads cleanly", listing["count"] == 0, str(listing)[:200])
        message = bridge.execute("ce_message", {"text": "hello"})["result"]
        check("show_message works", message.get("shown") == "hello", str(message)[:200])
        resolved = bridge.execute("ce_resolve", {"expression": "game.exe"})["result"]
        check("a module expression resolves", resolved.get("address") == "0x140000000",
              str(resolved)[:200])

        section("mirroring findings")
        health = 0x7FF000001000
        mirror = bridge.execute("ce_mirror", {"items": [
            {"address": hex(health), "name": "health?", "type": "i32", "comment": "found"},
            {"address": "0x7FF000002000", "name": "mana?", "type": "f32"},
        ]})["result"]
        check("both rows are added", mirror["added"] == 2, str(mirror)[:300])
        check("no row failed", mirror["failed"] == 0, str(mirror)[:300])
        after = bridge.execute("ce_addresses", {})["result"]
        check("the list now has two rows", after["count"] == 2,
              str(after)[:200])
        names = [item.get("name") for item in after["items"]]
        check("the names came through", "health?" in names and "mana?" in names, str(names))
        check("Cheat Engine resolved the address",
              str(after["items"]).lower().count("0x7ff000001000") > 0, str(after)[:300])

        partial = bridge.execute("ce_mirror", {"items": [
            {"address": "0x2000", "name": "good row"},
            {"address": "", "name": "bad row"},
        ]})["result"]
        check("a bad row fails but the good one lands",
              partial["added"] == 1 and partial["failed"] == 1, str(partial)[:300])


        section("symbols")
        symbol = bridge.execute("ce_register_symbol", {"name": "health_ptr", "address": hex(health)})["result"]
        check("a symbol registers", symbol["name"] == "health_ptr", str(symbol)[:200])
        back = bridge.execute("ce_resolve", {"expression": "health_ptr"})["result"]
        check("the symbol resolves back",
              back.get("address", "").lower() == hex(health).lower(),
              f"{back} vs {hex(health)}")

        section("autoassemble reporting")
        good = bridge.execute("ce_autoassemble", {"script": "[ENABLE]\nalloc(x,8)\n[DISABLE]\n"})["result"]
        check("a valid script succeeds", good.get("success") is True, str(good)[:200])
        bad = bridge.execute("ce_autoassemble", {"script": "bogus"})["result"]
        check("an invalid script reports its failure rather than raising", bad.get("success") is False and bad.get("error"), str(bad)[:200])

        section("the attach handshake")
        reply = bridge.ce.call("open_process", pid=lab.pid, name="lab_target.exe")
        check("the agent opens a process", reply.get("ok"), str(reply)[:200])
        check("the bridge adopts it",
              wait_for(lambda: bridge.target and bridge.target.pid == lab.pid),
              str(bridge.status()["target"] or "no target")[:200])
        target = bridge.status()["target"]
        check("the adopted target is read-only", target["writable"] is False)
        check("the source is recorded as cheat-engine", target["source"] == "cheat-engine",
              target["source"])
        check("the agent reports the same pid",
              bridge.ce.status()["attached_pid"] == lab.pid,
              str(bridge.ce.status()["attached_pid"]))
        check("the agent knows the name",
              bridge.ce.status()["attached_name"] == "lab_target.exe",
              str(bridge.ce.status()["attached_name"]))

        section("reading the adopted process")
        real = int(truth["g_health"], 16)
        value = bridge.execute("read", {"address": hex(real), "type": "i32"})["result"]
        check("reads work on the adopted process", value is not None, str(value)[:200])

        section("the detach handshake")
        bridge.ce.call("close_process")
        check("the bridge releases the target",
              wait_for(lambda: bridge.target is None, 40),
              str(bridge.status()["target"] or "no target")[:200])
        gone = bridge.execute("read", {"address": hex(int(truth["g_health"], 16)), "type": "i32"})
        check("reads fail cleanly after the detach", not gone["ok"], str(gone)[:200])

        section("failure paths")
        agent.terminate()
        agent.wait(timeout=10)
        check("the agent is seen as gone",
              wait_for(lambda: not bridge.ce.state.get("agent_seen"), 15),
              str(bridge.ce.state)[:200])
        after_gone = bridge.execute("ce_mirror", {"items": [{"address": "0x1"}]})
        check("mirroring without an agent fails clearly",
              not after_gone["ok"] and "agent" in after_gone["error"],
              str(after_gone)[:200])
    finally:
        for process in (agent, lab):
            try:
                if process:
                    process.terminate()
                    process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        bridge.stop()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"  FAILED: {name} {detail}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())










