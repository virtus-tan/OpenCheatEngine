"""A stand-in for the Cheat Engine Lua agent.

Speaks the same file protocol as ce_bridge_agent.lua, so the bridge's Cheat
Engine side can be tested without Cheat Engine, without administrator rights
and without a GUI. Useful for developing the bridge too.

    python tests/fake_agent.py [--pid 1234] [--name game.exe]
"""

import argparse
import json
import os
import tempfile
import time

SPOOL = os.environ.get("CEBRIDGE_SPOOL") or os.path.join(
    tempfile.gettempdir(), "ce_bridge_spool"
)
CMD = os.path.join(SPOOL, "cmd.txt")
RES = os.path.join(SPOOL, "res.txt")
STATUS = os.path.join(SPOOL, "status.txt")
HELLO = os.path.join(SPOOL, "hello.txt")

TICK = 0.15

STATE = {
    "pid": -1,
    "name": None,
    "symbols": {},
    "rows": [],
    "running": True,
}


def write_atomic(path, text):
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(temp, path)


def encode(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ",".join(encode(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(f"{json.dumps(k)}:{encode(v)}" for k, v in value.items()) + "}"
    return "null"


def announce():
    payload = {
        "version": "1.0",
        "spool": SPOOL,
        "ce_version": "7.4-fake",
        "functions": [
            "getOpenedProcessID", "getProcessName", "getAddress", "getAddressSafe",
            "getCEVersion", "openProcess", "closeProcess", "createMemoryRecord",
            "registerSymbol", "unregisterSymbol", "getSymbolAddress", "autoAssemble",
            "disassemble", "showMessage", "targetIs64bit",
        ],
        "type_constants": ["vtByte", "vtWord", "vtDword", "vtQword", "vtFloat", "vtDouble",
                           "vtSingle", "vtPointer", "vtBytes", "vtString"],
        "addresslist": True,
    }
    write_atomic(HELLO, "json=" + bytes(encode(payload), "utf-8").hex() + "\n")


def status():
    return {
        "pid": STATE["pid"],
        "name": STATE["name"] if STATE["pid"] >= 0 else None,
        "arch": "x64" if STATE["pid"] >= 0 else None,
        "address_list_count": len(STATE["rows"]),
        "ce_version": "7.4-fake",
    }


def resolve(expression):
    text = (expression or "").strip()
    if text in STATE["symbols"]:
        return STATE["symbols"][text]
    if text.lower().endswith(".exe"):
        return 0x140000000
    if text.lower().startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def handle(fields):
    command = fields.get("command")
    if command == "status":
        return status()
    if command == "caps":
        return {"version": "1.0", "spool": SPOOL, "addresslist": True}
    if command == "list_addresses":
        return {"count": len(STATE["rows"]), "items": list(STATE["rows"])}
    if command == "add_address":
        address = fields.get("address")
        if not address:
            return None, "address is required"
        row = {
            "index": len(STATE["rows"]),
            "address": address,
            "name": fields.get("name") or "",
            "value": fields.get("value") or "",
            "is_header": False,
        }
        STATE["rows"].append(row)
        resolved = resolve(address)
        return {
            "address": address,
            "resolved": f"0x{resolved:X}" if resolved else None,
            "name": row["name"],
            "type": fields.get("type") or "f32",
            "address_list_count": len(STATE["rows"]),
        }
    if command == "set_value":
        try:
            index = int(fields.get("index", 0))
        except ValueError:
            return None, "bad index"
        if index >= len(STATE["rows"]):
            return None, f"no row at {index}"
        STATE["rows"][index]["value"] = fields.get("value")
        return {"index": index, "value": fields.get("value")}
    if command == "set_comment":
        try:
            index = int(fields.get("index", 0))
        except ValueError:
            return None, "bad index"
        if index >= len(STATE["rows"]):
            return None, f"no row at {index}"
        return {"index": index, "comment": fields.get("comment")}
    if command == "register_symbol":
        name, address = fields.get("name"), fields.get("address")
        if not name or not address:
            return None, "name and address are required"
        resolved = resolve(address)
        if resolved is None:
            return None, f"cannot resolve {address}"
        STATE["symbols"][name] = resolved
        return {"name": name, "address": address, "resolved": f"0x{resolved:X}"}
    if command == "unregister_symbol":
        STATE["symbols"].pop(fields.get("name"), None)
        return {"name": fields.get("name")}
    if command == "resolve":
        resolved = resolve(fields.get("expression"))
        if resolved is None:
            return None, f"could not resolve {fields.get('expression')}"
        return {"expression": fields.get("expression"), "address": f"0x{resolved:X}"}
    if command == "disassemble":
        address = fields.get("address")
        if not address:
            return None, "address is required"
        count = int(fields.get("count", 12) or 12)
        return {
            "address": address,
            "count": count,
            "text": f"{address}:  mov eax, 1    fake disassembly",
        }
    if command == "autoassemble":
        script = fields.get("script") or ""
        if "[ENABLE]" not in script:
            return {"success": False, "error": "script has no [ENABLE] block"}
        if "bogus" in script.lower():
            return {"success": False, "error": "invalid instruction at line 3"}
        return {"success": True, "error": None}
    if command == "show_message":
        print(f"[fake agent] {fields.get('text')}")
        return {"shown": fields.get("text")}
    if command == "open_process":
        try:
            pid = int(fields.get("pid"))
        except (TypeError, ValueError):
            return None, "pid is required"
        if pid <= 0:
            return None, "no such process"
        STATE["pid"] = pid
        STATE["name"] = fields.get("name") or f"process{pid}.exe"
        return {"pid": pid, "opened": pid}
    if command == "close_process":
        STATE["pid"] = -1
        STATE["name"] = None
        return {"closed": True}
    return None, f"unknown command: {command}"


def read_fields(path):
    fields = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                if "=" in line:
                    key, value = line.rstrip("\r\n").split("=", 1)
                    fields[key] = value
    except OSError:
        return None
    return fields


def tick():
    if os.path.exists(CMD):
        fields = read_fields(CMD)
        os.remove(CMD)
        if fields:
            result = handle(fields)
            error = None
            if isinstance(result, tuple):
                result, error = result
            lines = [f"id={fields.get('id', '0')}", f"ok={0 if error else 1}"]
            if error:
                lines.append(f"error={error}")
            else:
                lines.append("json=" + bytes(encode(result or {}), "utf-8").hex())
            write_atomic(RES, "\n".join(lines) + "\n")
    write_atomic(STATUS, "json=" + bytes(encode(status()), "utf-8").hex() + "\n")


def main():
    parser = argparse.ArgumentParser(description="stand-in for the Cheat Engine agent")
    parser.add_argument("--pid", type=int, default=-1, help="pretend to be attached to this pid")
    parser.add_argument("--name", default=None, help="name for the pretended process")
    parser.add_argument("--seconds", type=float, default=0, help="stop after this long")
    args = parser.parse_args()

    os.makedirs(SPOOL, exist_ok=True)
    STATE["pid"] = args.pid
    STATE["name"] = args.name
    announce()
    print(f"fake Cheat Engine agent in {SPOOL}, attached to {args.pid}")
    deadline = time.time() + args.seconds if args.seconds else None
    try:
        while STATE["running"]:
            tick()
            if deadline and time.time() > deadline:
                break
            time.sleep(TICK)
    except KeyboardInterrupt:
        pass
    finally:
        for path in (CMD, RES, STATUS, HELLO):
            try:
                os.remove(path)
            except OSError:
                pass


if __name__ == "__main__":
    main()
