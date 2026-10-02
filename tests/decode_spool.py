"""Decode what the real Cheat Engine agent wrote into the spool."""
import json
import os
import sys
import tempfile

spool = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tempfile.gettempdir(), "ce_bridge_spool")
for name in ("hello.txt", "status.txt"):
    path = os.path.join(spool, name)
    print(f"=== {name} ===")
    if not os.path.exists(path):
        print("  missing")
        continue
    with open(path, encoding="utf-8") as handle:
        content = handle.read()
    print(f"  raw: {content[:120]}")
    for line in content.splitlines():
        if line.startswith("json="):
            try:
                decoded = bytes.fromhex(line[5:].strip()).decode("utf-8", "replace")
                print(f"  json: {decoded}")
                print(f"  parsed: {json.dumps(json.loads(decoded), indent=4)[:1600]}")
            except Exception as error:
                print(f"  could not decode: {error}")
                print(f"  hex head: {line[5:60]}")
