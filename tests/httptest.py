"""HTTP surface test: starts the bridge in-process and drives it over HTTP.

    python tests/httptest.py
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ce_bridge.bridge import TOOLS, Bridge
from ce_bridge.config import Config
from ce_bridge.server import BridgeServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["CEBRIDGE_SPOOL"] = os.path.join(
    tempfile.gettempdir(), f"ce_spool_http_{os.getpid()}")
LAB = os.path.join(ROOT, "lab", "lab_target.exe")
TRUTH_LOG = os.path.join(ROOT, "lab", "lab_http_truth.txt")

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"  pass  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class Client:
    def __init__(self, host, port, token):
        self.base = f"http://{host}:{port}"
        self.token = token

    def get(self, path, token=None):
        headers = {} if token is None else {"X-CE-Bridge-Token": token}
        request = urllib.request.Request(f"{self.base}{path}", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    def post(self, tool, params, token=None):
        request = urllib.request.Request(
            f"{self.base}/api/{tool}",
            data=json.dumps(params).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json",
                     "X-CE-Bridge-Token": self.token if token is None else token},
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))


def launch_lab():
    handle = open(TRUTH_LOG, "w", encoding="utf-8")
    process = subprocess.Popen([LAB], stdout=handle)
    handle.close()
    truth = {}
    deadline = time.time() + 15
    while time.time() < deadline:
        content = open(TRUTH_LOG, encoding="utf-8").read()
        for line in content.splitlines():
            if "=" in line:
                key, value = line.strip().split("=", 1)
                truth[key] = value
        if "LAB_TARGET_END" in content:
            return process, truth
        time.sleep(0.15)
    process.kill()
    raise SystemExit("lab target did not start")


def main():
    if not os.path.exists(LAB):
        raise SystemExit(f"lab target not built: {LAB}")
    lab, truth = launch_lab()
    config = Config()
    config.data["port"] = 9901
    config.data["log_file"] = os.path.join(ROOT, "lab", "httptest.log")
    bridge = Bridge(config).start()
    server = BridgeServer(bridge)
    server.start_background()
    client = Client(server.host, server.port, config["token"])
    try:
        run(client, truth, lab)
    finally:
        server.shutdown()
        bridge.stop()
        try:
            lab.kill()
        except Exception:
            pass
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"  FAILED: {name} {detail}")
    return 1 if FAILED else 0


def run(client, truth, lab):
    print("auth and routing")
    status, body = client.get("/api/status", token="wrong")
    check("a wrong token is rejected", status == 401, str(status))
    status, body = client.get("/api/status")
    check("status without a token is rejected", status == 401, str(status))
    status, body = client.get("/api/status", token=client.token)
    check("status with a token is 200", status == 200, str(status))
    check("status has no target yet", body["result"]["target"] is None)
    check("status suggests a next step", bool(body["result"].get("next_step")))
    status, body = client.post("ping", {}, token="wrong")
    check("a bad token is rejected", status == 401, str(status))
    status, body = client.post("nosuchtool", {})
    check("an unknown tool is a 200 with an error", status == 200 and not body["ok"])
    check("an unknown tool lists the real ones", "read" in body["error"], body["error"][:80])
    status, body = client.get("/api/tools", token=client.token)
    check("the tool list matches the dispatch table",
          sorted(body["result"]["tools"]) == sorted(TOOLS))
    status, body = client.post("status", {})
    check("tool status works", body["ok"] and "cheat_engine" in body["result"])
    check("elapsed time is reported", "elapsed_ms" in body)

    print("\nno-target behaviour")
    status, body = client.post("read", {"address": "0x1000", "type": "u32"})
    check("reading without a target fails cleanly", not body["ok"], str(body)[:100])
    check("the failure says to attach in CE",
          "cheat engine" in body["error"].lower(), body["error"][:120])
    check("the failure is classified as no_target", body.get("kind") == "no_target")

    print("\nprocesses")
    status, body = client.post("processes", {"filter": "lab_target"})
    check("the lab process is listed", body["ok"] and body["result"]["count"] >= 1,
          str(body.get("result", {}).get("count")))
    listing = body["result"]["processes"]
    check("the listing includes the pid", any(item["pid"] == lab.pid for item in listing))
    check("the listing includes the exe path",
          any((item["exe"] or "").lower().endswith("lab_target.exe") for item in listing))

    print("\nattaching by name")
    status, body = client.post("attach", {"name": "lab_target.exe"})
    check("attach by name works", body["ok"], body.get("error", "")[:120])
    target = body["result"]
    check("the target reports x64", target["arch"] == "x64", target["arch"])
    check("the target starts read-only", target["writable"] is False)
    check("the target records its source", target["source"] == "api", target["source"])

    status, body = client.post("attach", {"name": "lab_target"})
    check("attaching again is idempotent", body["ok"])
    status, body = client.post("attach", {"name": "definitely_not_running_xyz"})
    check("attaching to a missing name fails", not body["ok"])
    status, body = client.post("attach", {"name": "lab_target.exe"})
    check("re-attach after failure works", body["ok"], body.get("error", "")[:120])

    health = int(truth["g_health"], 16)
    hidden = int(truth["g_hidden"], 16)
    sentinel = int(truth["g_sentinel"], 16)
    marker = int(truth["marker"], 16)

    print("\nreads")
    status, body = client.post("read", {"address": truth["g_hidden"], "type": "i32"})
    check("read accepts C's bare %p form", body["ok"] and body["result"]["value"] == 987654,
          f"{truth['g_hidden']} -> {str(body.get('result', {}).get('value'))}")
    status, body = client.post("read", {"address": hex(hidden), "type": "i32"})
    check("read by 0x hex string", body["ok"] and body["result"]["value"] == 987654,
          str(body.get("result")))
    status, body = client.post("read", {"address": hex(sentinel), "type": "u32"})
    check("read reports the region", body["result"]["region"]["module"] == "lab_target.exe",
          str(body["result"]["region"].get("module")))
    status, body = client.post("modules", {"filter": "lab_target"})
    main_module = [item for item in body["result"]["modules"]
                   if item["name"].lower() == "lab_target.exe"][0]
    base = int(main_module["base"], 16)
    sentinel_offset = hex(sentinel - base)
    status, body = client.post("read", {"module": "lab_target.exe",
                                        "offset": sentinel_offset, "type": "u32"})
    check("read by module plus offset",
          body["ok"] and body["result"]["value"] == 0x11223344,
          f"{sentinel_offset} -> {str(body.get('result', {}).get('value'))}")
    status, body = client.post("read", {"address": "nothex"})
    check("a bad address fails cleanly", not body["ok"] and "error" in body)

    print("\ndisassembly and signatures")
    status, body = client.post("disasm", {"address": hex(marker), "count": 3})
    check("disasm works", body["ok"] and "0xefbeadde" in body["result"]["text"].lower(),
          body["result"]["text"][:80] if body["ok"] else body.get("error", "")[:80])
    check("disasm reports the module", body["result"]["module"] == "lab_target.exe",
          str(body["result"].get("module")))
    status, body = client.post("aob", {"pattern": "B8 DE AD BE EF", "max_hits": 8})
    check("aob over http finds the marker", body["ok"] and body["result"]["count"] == 1,
          str(body.get("result", {}).get("count")))

    print("\nscanning over http")
    status, body = client.post("scan_start", {
        "type": "i32", "scan_type": "exact", "value": 987654, "alignment": 4,
        "module": "lab_target.exe", "max_results": 100000,
    })
    check("scan_start restricted to a module",
          body["ok"] and body["result"]["results"] > 0, str(body)[:120])
    status, body = client.post("scan_results", {"offset": 0, "limit": 50})
    check("scan_results", body["ok"] and body["result"]["returned"] > 0)
    check("scan_results carries values", all("value" in item for item in body["result"]["results"]))
    status, body = client.post("scan_results", {"group": True})
    check("grouped results", body["ok"] and "groups" in body["result"])
    status, body = client.post("scan_start", {
        "type": "i32", "scan_type": "unknown_initial", "alignment": 4,
        "module": "lab_target.exe", "max_results": 100000,
    })
    check("unknown initial over http", body["ok"], str(body)[:120])
    time.sleep(0.8)
    status, body = client.post("scan_next", {"scan_type": "changed"})
    check("scan_next", body["ok"] and body["result"]["results"] >= 0, str(body)[:120])
    check("the scan history is kept", len(body["result"]["history"]) == 2,
          str(body["result"].get("history")))
    status, body = client.post("scan_reset", {})
    check("scan_reset", body["ok"] and body["result"]["active_scan"] is None)

    print("\nwrite gating and undo over http")
    status, body = client.post("write", {"address": hex(sentinel), "value": 1, "type": "u32"})
    check("write is refused while read-only", not body["ok"])
    check("the refusal explains the unlock", "ce_unlock" in body["error"], body["error"][:120])
    check("the refusal is classified read_only", body.get("kind") == "read_only")

    status, body = client.post("unlock", {"writable": True})
    check("unlock", body["ok"] and body["result"]["writable"] is True)
    before = client.post("read", {"address": hex(sentinel), "type": "u32"})[1]["result"]["value"]
    status, body = client.post("write", {"address": hex(sentinel), "value": 0x99887766,
                                         "type": "u32", "note": "httptest"})
    check("write after unlock", body["ok"] and body["result"]["value"] == 0x99887766,
          str(body.get("result", {}).get("value")))
    undo_id = body["result"]["undo_id"]
    status, body = client.post("read", {"address": hex(sentinel), "type": "u32"})
    check("the write is visible", body["result"]["value"] == 0x99887766)
    status, body = client.post("undo", {"id": undo_id})
    check("undo by id", body["ok"] and body["result"]["undone"] == 1)
    status, body = client.post("read", {"address": hex(sentinel), "type": "u32"})
    check("undo restored the value", body["result"]["value"] == before)

    status, body = client.post("journal", {"limit": 5})
    check("journal", body["ok"] and body["result"]["count"] >= 1)
    status, body = client.post("undo", {"all": True})
    check("undo all", body["ok"], str(body)[:100])
    status, body = client.post("unlock", {"writable": False})
    check("relock", body["ok"] and body["result"]["writable"] is False)

    print("\ncheat engine link")
    status, body = client.post("ce_status", {})
    check("ce_status responds even with no agent running", body["ok"], str(body)[:120])
    check("ce_status reports the agent as not seen",
          body["result"]["agent_seen"] is False, str(body["result"])[:120])
    check("ce_status explains the missing agent", bool(body["result"].get("hint")),
          str(body["result"])[:160])
    check("ce_status names the spool directory",
          isinstance(body["result"].get("spool"), str) and body["result"]["spool"],
          str(body["result"].get("spool")))
    status, body = client.post("ce_mirror", {"items": [{"address": "0x1", "name": "x"}]})
    check("ce_mirror refuses without an agent", not body["ok"] and "agent" in body["error"])
    status, body = client.post("ce_resolve", {"expression": "lab_target.exe"})
    check("ce_resolve reports the agent is not connected", not body["ok"],
          str(body)[:120])

    print("\nmanaged metadata without a target dependency")
    status, body = client.post("managed_metadata", {"path": os.path.join(ROOT, "lab",
                                                                       "lab_target.exe"),
                                                   "filter": "nothing_matches_this"})
    check("metadata on a native binary reports no types or fails clearly",
          not body["ok"] or body["result"]["types"] == 0, str(body)[:160])

    print("\ndetach")
    status, body = client.post("detach", {})
    check("detach", body["ok"] and body["result"]["detached"] is True)
    status, body = client.post("read", {"address": hex(hidden), "type": "i32"})
    check("reads fail again after detach", not body["ok"] and body.get("kind") == "no_target")
    status, body = client.post("status", {})
    check("status shows no target after detach", body["result"]["target"] is None)
    check("the event log records the cycle",
          any(item["event"] == "attached" for item in body["result"]["events"]),
          str(body["result"]["events"])[:200])


if __name__ == "__main__":
    raise SystemExit(main())

