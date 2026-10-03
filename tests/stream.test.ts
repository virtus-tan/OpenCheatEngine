/**
 * End to end test for the plugin's live link to the bridge.
 *
 *   node --experimental-strip-types tests/stream.test.ts
 *
 * The 43 tools are covered by tools.test.ts. What is tested here is the other
 * half: that the plugin holds one connection open and learns about state
 * changes without anyone calling a tool. That is the difference between
 * "attached in Cheat Engine" doing something visible and doing nothing at all.
 *
 * A real bridge process is started on its own port and spool, so this cannot
 * reach a bridge the user already has running.
 */

import { spawn, type ChildProcess } from "node:child_process"
import { existsSync, openSync, closeSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, "..")
const PLUGIN = join(ROOT, ".opencode", "plugins", "ce-bridge.ts")
const LAB = join(ROOT, "lab", "lab_target.exe")
const LAB_LOG = join(ROOT, "lab", "stream_truth.txt")
const PORT = 9908
const SPOOL = join(tmpdir(), `ce_spool_stream_${process.pid}`)
const CONFIG = join(tmpdir(), `ce_config_stream_${process.pid}.json`)
process.env.CEBRIDGE_SPOOL = SPOOL
process.env.CEBRIDGE_CONFIG = CONFIG
writeFileSync(CONFIG, JSON.stringify({ host: "127.0.0.1", port: PORT }, null, 2))

let passed = 0
const failures: string[] = []

function check(name: string, ok: boolean, detail = "") {
  if (ok) {
    passed++
    console.log(`  pass  ${name}`)
  } else {
    failures.push(`${name} ${detail}`)
    console.log(`  FAIL  ${name}  ${detail}`)
  }
}

function section(title: string) {
  console.log(`\n${title}`)
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function eventually(fn: () => boolean, timeoutMs = 20000, every = 200): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (fn()) return true
    await sleep(every)
  }
  return fn()
}

/** Everything the plugin logs and toasts, in order, so assertions can look at it. */
class Recorder {
  logs: string[] = []
  toasts: { title: string; message: string; variant: string }[] = []

  client = {
    app: {
      log: async ({ body }: any) => {
        this.logs.push(`${body.level}: ${body.message}`)
      },
    },
    tui: {
      showToast: async ({ body }: any) => {
        this.toasts.push(body)
      },
    },
  }

  logged(match: string) {
    return this.logs.some((line) => line.includes(match))
  }

  toasted(title: string) {
    return this.toasts.some((toast) => toast.title === title)
  }

  toastText(title: string) {
    return this.toasts.filter((t) => t.title === title).map((t) => t.message).join(" | ")
  }
}

function launchLab(): ChildProcess {
  const fd = openSync(LAB_LOG, "w")
  const child = spawn(LAB, [], { stdio: ["ignore", fd, fd] })
  closeSync(fd)
  return child
}

async function labReady(): Promise<boolean> {
  try {
    return readFileSync(LAB_LOG, "utf8").includes("LAB_TARGET_END")
  } catch {
    return false
  }
}

function startBridge(): ChildProcess {
  return spawn(
    "python",
    [join(ROOT, "bridge.py"), "start", "--no-ce", "--port", String(PORT), "--config", CONFIG],
    {
      cwd: ROOT,
      stdio: "ignore",
      env: { ...process.env, PYTHONUNBUFFERED: "1", CEBRIDGE_SPOOL: SPOOL },
    },
  )
}

async function post(tool: string, params: Record<string, unknown> = {}) {
  const endpoint = JSON.parse(readFileSync(join(SPOOL, "endpoint.json"), "utf8"))
  const response = await fetch(`${endpoint.url}/api/${tool}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CE-Bridge-Token": endpoint.token,
    },
    body: JSON.stringify(params),
  })
  return response.json()
}

async function main() {
  if (!existsSync(LAB)) {
    console.error(`lab target not built: ${LAB}`)
    process.exit(2)
  }

  const lab = launchLab()
  let bridge: ChildProcess | null = null
  const recorder = new Recorder()
  let hooks: any = null
  try {
    await eventually(labReady, 20000)

    section("no bridge running")
    const module = await import(pathToFileURL(PLUGIN).href)
    check("the plugin exports a factory", typeof module.CEBridgePlugin === "function")
    hooks = await module.CEBridgePlugin({
      client: recorder.client,
      project: {},
      directory: ROOT,
      worktree: ROOT,
      $: () => {},
    } as any)
    check("it returns the hooks opencode expects",
      typeof hooks.event === "function" &&
        typeof hooks["tool.execute.after"] === "function" &&
        typeof hooks["shell.env"] === "function")

    await eventually(() => recorder.toasted("CE bridge not running"), 15000)
    check("an absent bridge is reported once, not in a loop",
      recorder.toasted("CE bridge not running") &&
        recorder.toasts.filter((t) => t.title === "CE bridge not running").length === 1,
      JSON.stringify(recorder.toasts.slice(0, 3)))
    check("the warning says how to start it",
      recorder.toastText("CE bridge not running").includes("bridge.py start"),
      recorder.toastText("CE bridge not running"))

    const env: Record<string, string> = {}
    await hooks["shell.env"]({ cwd: ROOT, env: {} }, { env })
    check("the shell is told the stream is down", env.CE_BRIDGE_STREAM === "disconnected",
      env.CE_BRIDGE_STREAM)
    check("the shell still gets the workflow hint",
      typeof env.CE_BRIDGE_AGENT_HINT === "string" && env.CE_BRIDGE_AGENT_HINT.length > 50)

    section("bridge starts while the session is already open")
    bridge = startBridge()
    await eventually(() => existsSync(join(SPOOL, "endpoint.json")), 30000)
    await eventually(() => recorder.logged("stream open"), 20000)
    check("the plugin connects without being asked again",
      recorder.logged("stream open"), recorder.logs.slice(-3).join(" / "))
    check("reconnecting is announced",
      recorder.toasted("CE bridge connected"), JSON.stringify(recorder.toasts.slice(-3)))
    await hooks["shell.env"]({ cwd: ROOT, env: {} }, { env })
    check("the shell now sees a connected stream", env.CE_BRIDGE_STREAM === "connected",
      env.CE_BRIDGE_STREAM)

    section("state changes arrive without a tool call")
    const before = recorder.toasts.length
    await post("attach", { name: "lab_target.exe" })
    await eventually(() => recorder.toasted("Target attached"), 15000)
    check("attaching raises a toast with no tool involved",
      recorder.toasts.length > before, JSON.stringify(recorder.toasts.slice(-2)))
    const attached = recorder.toastText("Target attached")
    check("the toast names the process", attached.includes("lab_target.exe"), attached)
    check("the toast says the target is read-only", attached.includes("read-only"), attached)

    await post("unlock", { writable: true })
    await eventually(() => recorder.toasted("Target unlocked"), 15000)
    check("unlocking is announced",
      recorder.toasted("Target unlocked") &&
        recorder.toastText("Target unlocked").includes("journaled"),
      recorder.toastText("Target unlocked"))

    await post("detach", {})
    await eventually(() => recorder.toasted("Target released"), 15000)
    check("detaching is announced", recorder.toasted("Target released"),
      JSON.stringify(recorder.toasts.slice(-2)))
    check("the release toast says what to do next",
      recorder.toastText("Target released").includes("Attach in Cheat Engine"),
      recorder.toastText("Target released"))

    section("a tool failure is still logged")
    const logsBefore = recorder.logs.length
    await hooks["tool.execute.after"](
      { tool: "ce_read", args: {} },
      { error: "no target is attached" },
    )
    check("a failing tool is logged", recorder.logs.length > logsBefore,
      recorder.logs.slice(-1)[0])

    section("the bridge goes away")
    const losses = recorder.logs.filter((l) => l.includes("bridge stream unavailable")).length
    bridge.kill()
    bridge = null
    // Counted, not matched: the same line was already logged once in the first
    // phase, and waiting on it alone would pass before the kill had landed.
    await eventually(
      () => recorder.logs.filter((l) => l.includes("bridge stream unavailable")).length > losses,
      20000,
    )
    check("losing the stream is reported",
      recorder.logs.filter((l) => l.includes("bridge stream unavailable")).length > losses,
      recorder.logs.slice(-4).join(" / "))
    await hooks["shell.env"]({ cwd: ROOT, env: {} }, { env })
    check("the shell goes back to disconnected", env.CE_BRIDGE_STREAM === "disconnected",
      env.CE_BRIDGE_STREAM)

    section("and comes back")
    bridge = startBridge()
    await eventually(() => recorder.logged("stream open") &&
      recorder.logs.filter((l) => l.includes("stream open")).length >= 2, 30000)
    check("the plugin reconnects on its own",
      recorder.logs.filter((l) => l.includes("stream open")).length >= 2,
      recorder.logs.slice(-4).join(" / "))
  } finally {
    bridge?.kill()
    lab.kill()
  }

  console.log(`\n${passed} passed, ${failures.length} failed`)
  for (const f of failures) console.log(`  FAILED: ${f}`)
  process.exit(failures.length ? 1 : 0)
}

await main()
