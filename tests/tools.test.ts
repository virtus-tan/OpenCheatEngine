/**
 * End to end test for the opencode tools.
 *
 *   node --experimental-strip-types tests/tools.test.ts
 *
 * Starts the lab target and a real bridge process, then calls the tool
 * functions the way opencode would. A tool that will not import, has no
 * description, or returns something unreadable fails here.
 */

import { spawn, type ChildProcess } from "node:child_process"
import { tmpdir } from "node:os"
import { openSync, closeSync, existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, "..")
const TOOLS_DIR = resolve(ROOT, ".opencode", "tools")
const LAB = join(ROOT, "lab", "lab_target.exe")
const LAB_LOG = join(ROOT, "lab", "tools_truth.txt")
const PORT = 9907
// its own spool and its own config, so this cannot collide with a bridge the
// user already has running, and cannot fall back to the project config either
const SPOOL = join(tmpdir(), `ce_spool_tools_${process.pid}`)
const CONFIG = join(tmpdir(), `ce_config_tools_${process.pid}.json`)
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

async function waitFor(fn: () => unknown, timeoutMs = 25000, every = 250): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let last: unknown
  while (Date.now() < deadline) {
    try {
      await fn()
      return
    } catch (error) {
      last = error
      await new Promise((r) => setTimeout(r, every))
    }
  }
  throw last instanceof Error ? last : new Error(String(last))
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms))
}

async function eventually(fn: () => Promise<string>, accept: (out: string) => boolean,
                          timeoutMs = 6000, every = 200): Promise<string> {
  let last = ""
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      last = await fn()
      if (accept(last)) return last
    } catch (error) {
      last = (error as Error).message
    }
    await sleep(every)
  }
  return last
}


function launchLab(): ChildProcess {
  const fd = openSync(LAB_LOG, "w")
  const child = spawn(LAB, [], { stdio: ["ignore", fd, fd] })
  closeSync(fd)
  return child
}

async function labTruth(): Promise<Record<string, string>> {
  const content = readFileSync(LAB_LOG, "utf8")
  if (!content.includes("LAB_TARGET_END")) throw new Error("lab target not ready")
  const truth: Record<string, string> = {}
  for (const line of content.split(/\r?\n/)) {
    const at = line.indexOf("=")
    if (at > 0) truth[line.slice(0, at)] = line.slice(at + 1)
  }
  return truth
}

async function loadTools(): Promise<Record<string, any>> {
  const tools: Record<string, any> = {}
  for (const file of readdirSync(TOOLS_DIR).filter((f) => f.endsWith(".ts"))) {
    const mod = await import(pathToFileURL(join(TOOLS_DIR, file)).href)
    const base = file.replace(/\.ts$/, "")
    if (mod.default) tools[base] = mod.default
    for (const [name, value] of Object.entries(mod)) {
      if (name === "default") continue
      tools[`${base}_${name}`] = value
    }
  }
  return tools
}

function checkToolShape(tools: Record<string, any>) {
  for (const [name, def] of Object.entries(tools)) {
    const problems: string[] = []
    if (typeof def?.description !== "string" || def.description.length < 20) {
      problems.push("description missing or too short")
    }
    if (def?.args === undefined) problems.push("no args")
    if (typeof def?.execute !== "function") problems.push("no execute function")
    check(`tool ${name} is well formed`, problems.length === 0, problems.join("; "))
  }
}

async function main() {
  if (!existsSyncLab()) {
    console.error(`lab target not built: ${LAB}`)
    process.exit(2)
  }

  const lab = launchLab()
  let bridge: ChildProcess | null = null
  try {
    const truth = await waitFor(labTruth, 20000).then(labTruth)

    bridge = spawn("python", [join(ROOT, "bridge.py"), "start", "--no-ce", "--port", String(PORT), "--config", CONFIG], {
      cwd: ROOT,
      stdio: "ignore",
      env: { ...process.env, PYTHONUNBUFFERED: "1", CEBRIDGE_SPOOL: SPOOL },
    })

    const tools = await loadTools()
    section("tool definitions")
    console.log(`  loaded ${Object.keys(tools).length} tools`)
    checkToolShape(tools)

    const status = tools.ce_status
    // Wait for the bridge to publish its endpoint before calling anything, so
    // this can never quietly talk to a different bridge that happens to be
    // running on the default port.
    const endpointFile = join(SPOOL, "endpoint.json")
    const deadline = Date.now() + 30000
    let published = false
    while (Date.now() < deadline) {
      if (existsSync(endpointFile)) {
        try {
          if (JSON.parse(readFileSync(endpointFile, "utf8")).port === PORT) {
            published = true
            break
          }
        } catch {}
      }
      await sleep(200)
    }
    check("the bridge published its own endpoint", published,
      existsSync(endpointFile) ? readFileSync(endpointFile, "utf8") : "no endpoint file")
    if (published) {
      const statusText = await status.execute({})
      check("ce_status reports the bridge", statusText.includes(`127.0.0.1:${PORT}`),
        statusText.slice(0, 120))
    } else {
      await sleep(500)
    }
    await waitFor(async () => {
      const out = await status.execute({})
      if (typeof out !== "string" || !out.includes("Bridge up")) {
        throw new Error("bridge not up yet")
      }
    })

    const statusText = await status.execute({})
    check("ce_status reports the bridge", statusText.includes("Bridge up"), statusText.slice(0, 80))
    check("ce_status reports the missing CE agent", statusText.includes("agent installed"),
      statusText.slice(0, 200))
    check("ce_status has next steps when no target", statusText.includes("none"),
      statusText.slice(0, 400))

    section("attaching and discovering the target")
    const processes = await tools.ce_processes.execute({ filter: "lab_target" })
    check("ce_processes lists the lab target", processes.includes("lab_target.exe"),
      processes.slice(0, 200))

    const attached = await tools.ce_attach.execute({ name: "lab_target.exe" })
    check("ce_attach attaches by name", attached.includes("Attached"), attached.slice(0, 200))
    check("ce_attach warns writes are refused", attached.includes("ce_unlock"),
      attached.slice(0, 200))

    const after = await status.execute({})
    check("ce_status now shows the target", after.includes("lab_target.exe"), after.slice(0, 300))

    const modules = await tools.ce_modules.execute({})
    check("ce_modules lists the main module", modules.includes("lab_target.exe"),
      modules.slice(0, 300))
    const moduleRows = modules.split("\n").filter((l: string) => l.includes("lab_target.exe"))
    check("ce_modules gives a base and size", moduleRows.length === 1 && moduleRows[0].includes("0x"),
      moduleRows.join(" | "))

    const mapping = await tools.ce_memory_map.execute({})
    check("ce_memory_map has regions and a total", /regions, .*MB/.test(mapping),
      mapping.slice(0, 160))

    section("reading")
    const health = truth["g_health"]
    const hidden = truth["g_hidden"]
    const read = await tools.ce_read.execute({ address: hidden, type: "i32" })
    check("ce_read returns the value", read.includes("987654"), read.slice(0, 200))
    check("ce_read names the owning module", read.includes("module lab_target.exe"),
      read.slice(0, 300))

    const base = moduleRows[0].trim().split(/\s+/)[1]
    const offset = "0x" + (BigInt("0x" + health) - BigInt(base)).toString(16)
    const byModule = await tools.ce_read.execute({
      module: "lab_target.exe",
      offset,
      type: "i32",
    })
    check("ce_read works by module plus offset", !byModule.includes("required"),
      byModule.slice(0, 200))

    const bytes = await tools.ce_read_bytes.execute({ address: hidden, size: 8 })
    check("ce_read_bytes hex dumps", bytes.includes("hex:") && bytes.includes("|"),
      bytes.slice(0, 200))
    check("ce_read_bytes shows 987654 little endian", bytes.includes("06120f00"),
      bytes.split("\n")[1])


    section("scanning")
    const started = await tools.ce_scan.execute({
      phase: "start",
      scan_type: "exact",
      type: "i32",
      value: "987654",
      alignment: 4,
      module: "lab_target.exe",
    })
    check("ce_scan start finds candidates", /Started: \d+ candidates/.test(started),
      started.slice(0, 200))
    check("ce_scan start explains the next step", started.includes("phase=next"),
      started.slice(0, 300))

    const results = await tools.ce_scan_results.execute({ group: true })
    check("ce_scan_results groups by value", results.includes("x  "), results.slice(0, 200))
    check("ce_scan_results finds the hidden value", results.includes("987654"),
      results.slice(0, 400))

    const narrowed = await tools.ce_scan.execute({
      phase: "start",
      scan_type: "unknown_initial",
      type: "i32",
      alignment: 4,
      module: "lab_target.exe",
    })
    check("ce_scan start with unknown initial", /Started: \d+ candidates/.test(narrowed),
      narrowed.slice(0, 200))
    const changed = await eventually(
      () => tools.ce_scan.execute({ phase: "next", scan_type: "changed" }),
      (out) => out.includes("pass 1") && !out.includes("Narrowed to 0"),
      6000,
    )
    check("ce_scan next reports the history", changed.includes("pass 1"), changed.slice(0, 300))
    const changedResults = await tools.ce_scan_results.execute({ limit: 5 })
    check("ce_scan_results pages the narrowed set", changedResults.includes("result(s)"),
      changedResults.slice(0, 200))
    await tools.ce_scan_reset.execute({})


    section("disassembly and signatures")
    const marker = truth["marker"]
    const dis = await tools.ce_disasm.execute({ address: marker, count: 3 })
    check("ce_disasm finds the marker constant", dis.toLowerCase().includes("0xefbeadde"),
      dis.slice(0, 300))
    check("ce_disasm names the module", dis.includes("lab_target.exe+"), dis.slice(0, 300))

    const aob = await tools.ce_aob.execute({
      pattern: "B8 DE AD BE EF",
      module: "lab_target.exe",
      require_unique: true,
    })
    check("ce_aob requires a unique hit and gets one", aob.includes("1 match"),
      aob.slice(0, 200))

    const refs = await tools.ce_xrefs.execute({ address: health })
    check("ce_xrefs finds references", /reference\(s\)/.test(refs), refs.slice(0, 200))
    check("ce_xrefs suggests a next step", refs.includes("Disassemble"), refs.slice(-200))

    const asm = await tools.ce_assemble.execute({ asm: "mov eax, 1; ret" })
    check("ce_assemble encodes x64", asm.includes("b801000000c3"), asm.slice(0, 200))

    section("writes are gated, then undoable")
    const denied = await tools.ce_write
      .execute({ address: truth["g_sentinel"], value: "1", type: "u32" })
      .then(() => "no error")
      .catch((e: Error) => e.message)
    check("ce_write is refused while read-only", denied.includes("ce_unlock"), denied)

    const unlocked = await tools.ce_unlock.execute({ writable: true })
    check("ce_unlock allows writes", unlocked.includes("allowed"), unlocked)

    const written = await tools.ce_write.execute({
      address: truth["g_sentinel"],
      value: "0xAABBCCDD",
      type: "u32",
      note: "tools test",
    })
    check("ce_write confirms the value landed", written.includes("2864434397"),
      written.slice(0, 300))
    const undoId = written.match(/undo id (\w+)/)?.[1]
    check("ce_write returns an undo id", Boolean(undoId), written.slice(0, 300))

    const journal = await tools.ce_journal.execute({})
    check("ce_journal lists the write with its note", journal.includes("tools test"),
      journal.slice(0, 300))

    const undone = await tools.ce_undo.execute({ id: undoId })
    check("ce_undo reverts the write", undone.includes("Reverted 1"), undone.slice(0, 200))

    const afterUndo = await tools.ce_read.execute({
      address: truth["g_sentinel"],
      type: "u32",
    })
    check("the value is back", afterUndo.includes("287454020"), afterUndo.slice(0, 200))

    section("freeze and watch")
    const frozen = await tools.ce_freeze.execute({
      address: health,
      value: "100",
      type: "i32",
      interval: 0.05,
    })
    check("ce_freeze pins a value", frozen.includes("Freezing"), frozen.slice(0, 200))
    const held = await eventually(
      () => tools.ce_read.execute({ address: health, type: "i32" }),
      (out) => out.includes("=  100"),
      6000,
    )
    check("the frozen value holds against the game loop", held.includes("=  100"),
      held.slice(0, 200))
    const cleared = await tools.ce_freeze.execute({})
    check("ce_freeze with no address clears all", cleared.includes("Cleared"), cleared.slice(0, 200))

    const watching = await tools.ce_watch.execute({
      address: health,
      type: "i32",
      interval: 0.1,
      duration: 3,
    })
    check("ce_watch starts sampling", watching.includes("Watching"), watching.slice(0, 200))
    const history = await eventually(
      () => tools.ce_watch_history.execute({ address: health }),
      (out) => (out.match(/<- changed/g) ?? []).length > 0,
      8000,
    )
    check("ce_watch_history shows changes", history.includes("changed"), history.slice(0, 300))
    check("ce_watch_history shows more than one value",
      new Set(history.match(/  \d+\.\d+  (-?\d+)/g) ?? []).size > 1, history.slice(0, 400))


    section("managed runtime on a native target")
    const runtime = await tools.ce_runtime.execute({})
    check("ce_runtime reports a native target", runtime.includes("Runtime: native"),
      runtime.slice(0, 200))
    check("ce_runtime points at the native workflow", runtime.includes("ce_scan"),
      runtime.slice(-300))

    section("cheat engine integration without CE running")
    const ceStatus = await tools.ce_ce_status.execute({})
    check("ce_ce_status says the agent is not connected",
      ceStatus.includes("agent connected : no"), ceStatus.slice(0, 300))
    check("ce_ce_status explains what to do about it",
      /ce_ce_install/.test(ceStatus), ceStatus.slice(0, 400))
    const mirror = await tools.ce_ce_mirror
      .execute({ addresses: [{ address: "0x1", name: "x" }] })
      .then(() => "no error")
      .catch((e: Error) => e.message)
    check("ce_ce_mirror fails cleanly with no agent", mirror.includes("agent"),
      mirror.slice(0, 200))
    const symbol = await tools.ce_ce_symbol
      .execute({ name: "probe", address: "0x1" })
      .then(() => "no error")
      .catch((e: Error) => e.message)
    check("ce_ce_symbol fails cleanly with no agent", symbol.includes("agent"),
      symbol.slice(0, 200))

    section("detach")
    const detached = await tools.ce_detach.execute({})
    check("ce_detach reports the release", detached.includes("Released"), detached)
    const gone = await tools.ce_read
      .execute({ address: hidden, type: "i32" })
      .then(() => "no error")
      .catch((e: Error) => e.message)
    check("reads fail after detach with an attach hint", gone.includes("Cheat Engine"),
      gone.slice(0, 200))
  } finally {
    bridge?.kill()
    lab.kill()
  }

  console.log(`\n${passed} passed, ${failures.length} failed`)
  for (const f of failures) console.log(`  FAILED: ${f}`)
  process.exit(failures.length ? 1 : 0)
}

function existsSyncLab(): boolean {
  try {
    readFileSync(LAB)
    return true
  } catch {
    return false
  }
}

writeFileSync(LAB_LOG, "")
await main()





