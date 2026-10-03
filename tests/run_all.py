"""Run every test suite and summarise.

    python tests/run_all.py            everything except the real Cheat Engine test
    python tests/run_all.py --with-ce  also run tests/cetest.py, which needs
                                      Cheat Engine and a UAC prompt

Each suite runs in its own process so one failure cannot leave a target
process or a bridge behind for the next one.
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SUITES = [
    ("core", ["python", os.path.join(HERE, "selftest.py")],
     "memory, scanning, disassembly, signatures, freeze, journal"),
    ("architectures", ["python", os.path.join(HERE, "archtest.py")],
     "x64 and x86 against both lab builds, including remote calls"),
("http api", ["python", os.path.join(HERE, "httptest.py")],
     "the token, routing, every tool over HTTP, and the event stream"),
    ("cheat engine link", ["python", os.path.join(HERE, "celink_test.py")],
     "the spool protocol and attach handshake, against a stand-in agent"),
    ("cheat engine lua", ["python", os.path.join(HERE, "luatest.py")],
     "the agent's own logic against CE 7.4's real Lua API surface"),
    ("opencode tools", ["node", "--experimental-strip-types", os.path.join(HERE, "tools.test.ts")],
     "all 43 tools loaded and driven end to end"),
    ("live link", ["node", "--experimental-strip-types", os.path.join(HERE, "stream.test.ts")],
     "the plugin's open connection: state changes arrive with no tool call"),
    ("global install", ["node", "--experimental-strip-types", os.path.join(HERE, "verify_install.ts")],
     "the tools load from the global config directory, where opencode looks"),
    ("cheat engine itself", ["python", os.path.join(HERE, "cetest.py")],
     "the real Cheat Engine agent; needs the UAC prompt accepted"),
]


def kill_strays():
    """Clear out what previous runs of these suites may have left behind.

    Deliberately does not touch Cheat Engine. A real Cheat Engine may be open
    with a game attached, and a test runner has no business closing it. The only
    suite that starts Cheat Engine is cetest.py, and that kills the one it
    started, by pid.
    """
    try:
        import psutil
    except ImportError:
        return
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (process.info["name"] or "").lower()
            command = " ".join(process.info["cmdline"] or [])
            if name in ("lab_target.exe", "lab_target32.exe") or "fake_agent.py" in command:
                if "psutil" not in command:
                    process.kill()
        except Exception:
            continue



def main():
    with_ce = "--with-ce" in sys.argv
    results = []
    try:
        for name, command, description in SUITES:
            if name == "cheat engine itself" and not with_ce:
                print(f"\n{'=' * 70}\nSKIPPED: {name} ({description})\n{'=' * 70}")
                results.append((name, None, "skipped"))
                continue
            print(f"\n{'=' * 70}\n{name}: {description}\n{'=' * 70}")
            kill_strays()
            time.sleep(0.3)
            started = time.time()
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            elapsed = time.time() - started
            output = (completed.stdout or "") + (completed.stderr or "")
            summary = ""
            for line in output.splitlines():
                if " passed, " in line:
                    summary = line.strip()
                    break
            if summary:
                print(summary)
            else:
                print(output.strip()[-2000:])
            if completed.returncode != 0:
                print(f"--- {name} output tail ---")
                print(output.strip()[-3000:])
                print(f"--- end {name} ---")
            results.append((name, completed.returncode, summary or f"exit {completed.returncode}"))
            time.sleep(0.3)
    finally:
        kill_strays()

    print(f"\n{'=' * 70}\nsummary\n{'=' * 70}")
    failed = 0
    for name, code, summary in results:
        if code is None:
            mark = "skip"
        elif code == 0:
            mark = "pass"
        else:
            mark = "FAIL"
            failed += 1
        print(f"  {mark:4}  {name:22} {summary}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

