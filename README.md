# CE bridge

A process-memory bridge for Windows with a link to Cheat Engine, and 43 opencode
tools that let an AI drive it. Built for learning reverse engineering on games
you own: finding a value, reading the code that writes it, naming it from the
game's own metadata, and patching it.

The human picks the process. The AI does the rest.

```
  you play the game  ->  start the bridge (Cheat Engine opens)  ->  you attach in
  Cheat Engine  ->  the target appears by itself  ->  ask the AI for things
```

## Quick start

```powershell
python -m pip install -r requirements.txt
python bridge.py install-agent      # one time, no administrator rights needed
python bridge.py install-opencode   # puts the tools where opencode can see them
python bridge.py start              # starts Cheat Engine, waits
```

Then open your game, attach to it in Cheat Engine, and ask for what you want:

> find my health value, tell me which class and field it is, and keep it at 100

Restart the bridge the same way next time. `python bridge.py start --no-ce` skips
opening Cheat Engine if it is already running.

## Why `install-opencode` exists

opencode only reads two directories: `.opencode/tools/` and `.opencode/plugins/`
in the **project root**, and the same two in its global config directory. It does
not scan subdirectories — so tools left inside a nested folder are invisible, and
no error is shown. That is the usual reason the tools seem to be missing.

`python bridge.py install-opencode` copies the 43 tools, the plugin and the shared
client into `~/.config/opencode/`, so they are available in every project rather
than only in this folder. That matters because the game you are working on is
somewhere else entirely. Use `--target=project` to install into just one project
instead, and `--status` to see where things currently are.

The tools find the bridge on their own: the bridge writes its URL and token to
`endpoint.json` in `%TEMP%\ce_bridge_spool` when it starts, and the tools read
that file. No paths, no environment variables, nothing to configure. Override
with `CEBRIDGE_URL` and `CEBRIDGE_TOKEN` if you move things.


## The workflow it is designed around

The whole design follows from one decision: **you attach in Cheat Engine, the AI
adopts that process.** Nothing picks a PID for you.

| State | What is true | What the AI can do |
|---|---|---|
| bridge starting | server up, no agent | `ce_status` |
| Cheat Engine open, nothing attached | agent reporting, no target | `ce_ce_status`, `ce_ce_launch` |
| you attached | target adopted, **read-only** | everything except writes |
| after `ce_unlock` | writable, every write journaled | writing, patching, freezing, injection |
| you detached | target released, addresses stale | status only |

Every tool refuses clearly when there is no target, and every write is refused
until you deliberately unlock. Nothing changes your game by accident.

## What the AI can do

**Reading** — `ce_read` `ce_read_bytes` `ce_query` `ce_modules` `ce_memory_map`
`ce_disasm` `ce_assemble` `ce_xrefs` `ce_pointer_chains` `ce_aob`

**Scanning** — `ce_scan` `ce_scan_results` `ce_scan_reset`, with every pass type
Cheat Engine has: unknown initial, changed, unchanged, increased, decreased,
exact, fuzzy, and array-of-struct. Float, integer, pointer, byte-array and
`"int32 hp; float mp"` struct searches.

**Changing** — `ce_write` `ce_write_bytes` `ce_patch` `ce_freeze` `ce_undo`
`ce_journal` `ce_watch` `ce_watch_history`

**Managed games** — `ce_runtime` `ce_managed` `ce_managed_metadata` `ce_managed_call`
for Unity Mono and IL2CPP, plus reading `Assembly-CSharp.dll` straight off disk.

**Code** — `ce_remote_call` `ce_inject` `ce_shellcode` `ce_hook` `ce_unhook`

**Cheat Engine** — `ce_ce_launch` `ce_ce_status` `ce_ce_install` `ce_ce_mirror`
`ce_ce_symbol` `ce_ce_autoassemble` `ce_ce_addresses`

The managed half is the one that matters most. Instead of hunting for a float,
the AI reads `Player.TakeDamage(System.Single)` and `Player::m_health` out of the
game's own metadata, gives you the field offset, and turns the code into a byte
signature. Next time you start the game it skips the searching entirely.

## Install

**Python** 3.10 or newer, 64-bit. Four packages: capstone, keystone-engine,
psutil, dnfile.

**The Cheat Engine agent** — `python bridge.py install-agent`. It tries to write
into `C:\Program Files\Cheat Engine 7.4\autorun`, and if that needs
administrator rights it copies Cheat Engine to
`%LOCALAPPDATA%\CEBridge\Cheat Engine` (about 75 MB, once) and installs the agent
there instead. Cheat Engine resolves its `autorun` folder relative to its own
executable, so the copy behaves identically. No elevation, ever.

**The tools** are installed with `python bridge.py install-opencode`, which puts
them in `~/.config/opencode/` so they work in every project. See
`python bridge.py install-opencode --status` for where things are.

## How it works

```
opencode tool  ->  HTTP  ->  bridge (127.0.0.1:9877, token)  ->  Win32
       ^                                             |
       |                                             +-- spool in %TEMP%  ->  CE Lua agent
       |                                             |
       +---------- SSE /api/events <-----------------+
```

The Python side does the real memory work: `ReadProcessMemory`,
`WriteProcessMemory`, `VirtualQueryEx`, and a hand-written remote-call stub for
`VirtualAllocEx` + `CreateRemoteThread`. Cheat Engine stays the control panel
and the viewer, and findings get mirrored into its address list so you can watch
them yourself. It is deliberately not in the critical path, so a Cheat Engine
crash costs you nothing.

Cheat Engine's Lua has no socket library, so the agent talks over files in
`%TEMP%\ce_bridge_spool`: the agent writes `status.txt` on a timer, the bridge
writes `cmd.txt`, the agent answers `res.txt`. `tests/fake_agent.py` implements
the same protocol, so the Cheat Engine side can be developed and tested without
the GUI or elevation.

## Seeing the connection

The tools are request/response, which means the shell has nothing to show
between calls: attaching in Cheat Engine looked like it had done nothing until
the AI happened to run a tool. So the plugin holds one connection open instead.

`GET /api/events` is a server-sent event stream. A client opens it once and the
bridge writes to it whenever its state changes — Cheat Engine's agent appears or
disappears, a target is attached or released, `ce_unlock` changes a read-only
target into a writable one. The first frame is the full status, so a client can
render without a second round trip, and a comment every ten seconds keeps the
connection provably alive through anything that would otherwise time it out.

That is what the opencode plugin in `.opencode/plugins/ce-bridge.ts` does:

```
$ python bridge.py start        # in another terminal
                                 # attach in Cheat Engine
                                 # -> "Target attached" toast, no tool call involved
```

So in the shell:

| You see | It means |
|---|---|
| `CE bridge not running` | nothing is listening on the port yet; it retries |
| `CE bridge connected` | the stream is open; `status.bridge.subscribers` counts the clients |
| `Cheat Engine agent connected` / `gone` | `hello.txt`/`status.txt` appearing or going stale |
| `Target attached` / `released` | a pid arrived or went away |
| `Target unlocked` / `locked` | `PROCESS_VM_WRITE` was requested or dropped |

Every one of those also goes to the opencode log under the service name
`ce-bridge`, which is the durable answer to "is this thing actually connected?"
when a toast has scrolled away. Shell commands can read `CE_BRIDGE_STREAM`,
which is `connected` or `disconnected`.

The token can travel in the query string as well as the header, because
`EventSource` cannot set headers. It is still required: the stream is on the same
authenticated port as everything else, and an unauthenticated one would hand
process control to anything that can open a socket.


## Verifying it

The bridge is tested against a purpose-built lab target that prints the address
of every global it owns, so each assertion is a fact about the process rather
than a guess.

```powershell
python tests/run_all.py             # 387 tests
python tests/run_all.py --with-ce   # plus the real Cheat Engine agent
```

| Suite | Tests | What it covers |
|---|---|---|
| `selftest.py` | 93 | read/write/undo, scanning, disassembly, AOB, xrefs, freeze, watch, journal |
| `archtest.py` | 40 | x64 and x86 against both lab builds, including real remote calls |
| `httptest.py` | 79 | token, routing, every tool over HTTP, and the event stream |
| `celink_test.py` | 30 | spool protocol, attach handshake, mirroring, against a stand-in agent |
| `luatest.py` | 32 | the agent's Lua, run in a real interpreter against CE 7.4's API surface |
| `tools.test.ts` | 94 | all 43 opencode tools loaded and driven end to end |
| `stream.test.ts` | 19 | the plugin's open connection: it learns of a state change with no tool call, loses the stream when the bridge dies, and reconnects when it comes back |
| `cetest.py` | 25 | the real Cheat Engine agent; needs the UAC prompt |

`luatest.py` is the interesting one. Cheat Engine 7.4's Lua turns out not to
expose `createMemoryRecord`, `getSymbolAddress`, `getProcessName`, `targetIs64bit`
or `closeProcess` — which was only discovered by running the agent in the real
application. `lupa` runs a genuine Lua interpreter against a mock with exactly
CE 7.4's globals and nothing more, so those fallbacks are now tested rather than
assumed. The record constructor lives on `AddressList`, and symbols resolve
through `getAddress`.

The remote-call stub is checked by calling `GetCurrentProcessId` in the target
and comparing the answer with the real pid, and by writing a string into the
target and asking `lstrlenA` to measure it. Both architectures.

## Known limits

These are real and deliberately reported rather than papered over.

**32-bit injection is not possible from a 64-bit process.** Windows will not
create a 32-bit thread in a WOW64 process, so `ce_inject`, `ce_shellcode`,
`ce_hook` and `ce_remote_call` refuse with that explanation rather than
returning a zero that looks real. Reading, writing, scanning, disassembly and
signatures all work on 32-bit targets. For injection there, run Cheat Engine's
32-bit build against the process, or run the bridge from a 32-bit Python.

**32-bit memory maps are module images only.** `VirtualQueryEx` cannot see a
WOW64 target's 32-bit view — the kernel owns a 64-bit map and the low addresses
read back as free — so for 32-bit targets the map is built from each module's
section table. Scanning covers the game's own image, which is where its values
are, but not the whole 32-bit address space.

**"Find what wrote this" is a cross-reference scan, not a hardware breakpoint.**
`ce_xrefs` finds the instructions and pointer slots that reference an address, and
`ce_watch` shows when a value changes. A true hardware breakpoint needs
`DebugActiveProcess`, which suspends threads and destabilises a running game, so
it is not done behind your back.

**Mono static field values need IL2CPP's API.** Reading a live static uses
`il2cpp_field_static_get_value`, which Mono does not export. For Mono, use
`ce_managed_metadata` for names and offsets.

**The Lua agent was verified against the real Cheat Engine 7.4.** It connects, and
its first live run is what revealed the API gaps listed above. `tests/cetest.py`
drives it end to end when run with `--with-ce`; the UAC prompt has to be accepted
by hand, which is why it is not part of the default run. Its protocol counterpart
is covered by `fake_agent.py` and its own logic by `luatest.py`.

## Layout

```
bridge.py                  CLI: start, status, call, install-agent, tools
config.json                port, Cheat Engine paths, token
ce_bridge/
  bridge.py                state, and the tool surface the HTTP layer exposes
  server.py                HTTP/JSON, token auth, endpoint publishing, /api/events
  events.py                the fan-out behind the event stream
  session.py               target lifecycle, read-only gate, undo journal
  celink.py                the Cheat Engine spool protocol and launcher
  config.py  logging
  ce_agent/
    ce_bridge_agent.lua    the agent that runs inside Cheat Engine
  core/
    winapi.py              ctypes Win32, the remote call stub
    pe.py                  PE image and export parsing, forwarder following
    scanner.py             the scan engine
    signature.py           AOB, xrefs, pointer chains
    disasm.py              capstone and keystone
    valuetypes.py          typed reads and writes, struct parsing
    managed.py             Mono and IL2CPP, metadata from disk
    inject.py              export resolution, patching, hooks
.opencode/
  tools/                   43 tools, one file each
  plugins/ce-bridge.ts     the live link: toasts, logs, the workflow hint
  lib/bridge-client.ts     the shared HTTP client
lab/                       the lab target and its build script
tests/                     the suites above, plus fake_agent.py
```

## Safety notes

The bridge binds to `127.0.0.1` only, and every call needs the token from
`config.json`. It opens targets read-only, and `PROCESS_VM_WRITE` is only
requested when you unlock. Every write records the bytes that were there before,
and `ce_undo` puts them back. `ce_patch` refuses when the bytes it expected are
not the bytes it found, which is what stops you corrupting a different build of
a game. These guard against accidents, not against a determined attacker on
your own machine, who has easier options than the bridge anyway.
