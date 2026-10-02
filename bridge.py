#!/usr/bin/env python
"""CE Testing bridge: entry point.

    python bridge.py start          start the bridge and Cheat Engine
    python bridge.py start --no-ce   start the bridge only
    python bridge.py status          one-shot status
    python bridge.py call <tool> [k=v ...]
    python bridge.py install-agent   copy the Lua agent into Cheat Engine
    python bridge.py tools           list every tool

start runs the server in the foreground; the opencode tools talk to it over
http://127.0.0.1:9877. Attach to your game inside Cheat Engine and the target
appears on its own.
"""

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ce_bridge.bridge import TOOLS, Bridge  # noqa: E402
from ce_bridge.config import Config  # noqa: E402
from ce_bridge.server import BridgeServer, ensure_token  # noqa: E402


def _print(payload):
    print(json.dumps(payload, indent=2, default=str))


def _request(config, tool, params, timeout):
    url = f"http://{config.get('host')}:{config.get('port')}/api/{tool}"
    body = json.dumps(params or {}).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-CE-Bridge-Token": config.get("token") or "",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return {"ok": False, "error": error.read().decode("utf-8", "replace")}
    except urllib.error.URLError as error:
        return {
            "ok": False,
            "error": f"cannot reach the bridge at {url}: {error.reason}. "
                     "Is it running? Start it with: python bridge.py start",
        }


def command_start(args, config):
    bridge = Bridge(config).start()
    server = BridgeServer(bridge, verbose=args.verbose)
    token = ensure_token(config)

    print(f"CE Testing bridge listening on http://{server.host}:{server.port}")
    print(f"  token      {token}")
    print(f"  log        {config.get('log_file')}")
    print(f"  config     {config.path}")
    print(f"  CE folder  {config.get('ce_dir')}")
    print(f"  CE agent   {'installed' if bridge.ce.agent_installed() else 'NOT installed'}")
    if not bridge.ce.agent_installed():
        print("\n  The Cheat Engine agent is not installed yet. Run this once from an")
        print("  elevated terminal:   python bridge.py install-agent")
        print("  then restart Cheat Engine.\n")

    if args.ce:
        result = bridge.execute("ce_launch", {"arch": args.arch, "avx": args.avx})
        if result.get("ok") and result["result"].get("ok"):
            print(f"  Cheat Engine started (pid {result['result'].get('pid')})")
            print("  Attach to your game in Cheat Engine; the target is picked up here.\n")
        else:
            print(f"  Cheat Engine: {result.get('result') or result.get('error')}\n")

    stop = {"flag": False}

    def handle_signal(_signum, _frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, handle_signal)
    try:
        signal.signal(signal.SIGTERM, handle_signal)
    except (AttributeError, ValueError):
        pass

    server.start_background()
    print("  ready. Press Ctrl+C to stop.\n")
    try:
        while not stop["flag"]:
            time.sleep(0.4)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nstopping")
        server.shutdown()
        bridge.stop()
    return 0


def command_status(config, timeout):
    return _request(config, "status", {}, timeout)


def command_call(tool, pairs, config, timeout):
    params = {}
    for pair in pairs:
        if "=" not in pair:
            print(f"expected key=value, got {pair!r}", file=sys.stderr)
            return 2
        key, value = pair.split("=", 1)
        params[key.strip()] = _coerce(value)
    return _request(config, tool, params, timeout)


def _coerce(text):
    lowered = text.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("null", "none"):
        return None
    try:
        return int(text, 0)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    if text.startswith("[") or text.startswith("{"):
        try:
            return json.loads(text)
        except ValueError:
            pass
    return text


def command_install_agent(config):
    bridge = Bridge(config)
    result = bridge.execute("ce_install", {})
    _print(result.get("result") or result)
    if not (result.get("ok") and result["result"].get("ok")):
        return 1
    print(f"\n{result['result'].get('note', 'Restart Cheat Engine for the agent to load.')}")
    return 0


def command_install_opencode(config, args):
    from ce_bridge.opencode import install, status

    if args.status:
        _print(status())
        return 0
    result = install(args.target, args.path)
    print(f"Installed {result['total']} file(s) into {result['installed_to']}")
    print(f"  {result['files']['tools']} tool(s)")
    print(f"  {result['files']['plugins']} plugin(s)")
    print(f"  {result['files']['lib']} shared client file(s)")
    print(f"  package.json updated: {result['package_json']}")
    print("\nRestart opencode so it loads them.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="bridge.py", description="CE Testing bridge",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command")

    start = sub.add_parser("start", help="run the bridge (and Cheat Engine) in the foreground")
    start.add_argument("--no-ce", dest="ce", action="store_false",
                       help="do not launch Cheat Engine")
    start.add_argument("--arch", default="x64", choices=("x64", "x86"),
                       help="which Cheat Engine build to launch (default x64)")
    start.add_argument("--avx", action="store_true", help="prefer the SSE4-AVX2 build")
    start.add_argument("--verbose", action="store_true")
    start.add_argument("--port", type=int)
    start.add_argument("--host")
    start.add_argument("--config", default=None,
                       help="use a different config.json, e.g. to run a second bridge")

    call = sub.add_parser("call", help="call one tool against a running bridge")
    call.add_argument("tool")
    call.add_argument("params", nargs="*")
    call.add_argument("--timeout", type=float, default=180.0)
    call.add_argument("--config", default=None, help="use a different config.json")

    tools_install = sub.add_parser(
        "install-opencode",
        help="copy the tools and plugin where opencode can see them",
    )
    tools_install.add_argument("--target", default="global",
                               choices=("global", "project"),
                               help="global for every project (default), or project for this one")
    tools_install.add_argument("--path", default=None, help="project root, for --target=project")
    tools_install.add_argument("--status", action="store_true",
                               help="show where things are installed instead of installing")

    sub.add_parser("status", help="print the current status")
    sub.add_parser("tools", help="list every tool")
    sub.add_parser("install-agent", help="copy the Lua agent into Cheat Engine")

    args = parser.parse_args(argv)
    config = Config(
        path=getattr(args, "config", None),
        overrides={"port": getattr(args, "port", None),
                   "host": getattr(args, "host", None)},
    )
    ensure_token(config)

    if args.command == "start":
        return command_start(args, config)
    if args.command == "status":
        _print(command_status(config, 15.0))
        return 0
    if args.command == "tools":
        for name in TOOLS:
            print(name)
        return 0
    if args.command == "install-agent":
        return command_install_agent(config)
    if args.command == "install-opencode":
        return command_install_opencode(config, args)
    if args.command == "call":
        result = command_call(args.tool, args.params, config, args.timeout)
        _print(result)
        return 0 if result.get("ok") else 1
    parser.print_help()
    return 1



if __name__ == "__main__":
    raise SystemExit(main())
