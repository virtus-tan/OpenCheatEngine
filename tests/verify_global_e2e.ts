/**
 * End to end: a tool loaded from the global install, against a live bridge.
 *
 *   node --experimental-strip-types tests/verify_global_e2e.ts
 *
 * The global copy has to find the bridge on its own, with no config and no
 * working directory set to the bridge project. That is the whole point of
 * installing globally.
 */

import { spawn } from "node:child_process"
import { openSync, closeSync, readFileSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, "..")
const LAB = join(ROOT, "lab", "lab_target.exe")
const LOG = join(tmpdir(), "ce_global_e2e_lab.txt")
const PORT = 9931
const SPOOL = join(tmpdir(), "ce_spool_global_e2e")
process.env.CEBRIDGE_SPOOL = SPOOL

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

function launchLab() {
  const fd = openSync(LOG, "w")
  const child = spawn(LAB, [], { stdio: ["ignore", fd, fd] })
  closeSync(fd)
  return child
}

function labReady(): boolean {
  if (!existsSync(LOG)) return false
  return readFileSync(LOG, "utf8").includes("LAB_TARGET_END")
}

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

const globalTools = join(process.env.USERPROFILE!, ".config", "opencode", "tools")
if (!existsSync(globalTools)) {
  console.error(`no global tools at ${globalTools}; run: python bridge.py install-opencode`)
  process.exit(2)
}

const lab = launchLab()
let bridge: ReturnType<typeof spawn> | null = null
try {
  for (let i = 0; i < 60 && !labReady(); i++) await sleep(250)
  check("the lab target started", labReady())

  bridge = spawn("python", [join(ROOT, "bridge.py"), "start", "--no-ce", "--port", String(PORT)], {
    cwd: tmpdir(),
    stdio: "ignore",
    env: { ...process.env, PYTHONUNBUFFERED: "1", CEBRIDGE_SPOOL: SPOOL },
  })

  const status = (await import(pathToFileURL(join(globalTools, "ce_status.ts")).href)).default
  let text = ""
  for (let i = 0; i < 80; i++) {
    try {
      text = await status.execute({})
      if (text.includes("Bridge up")) break
    } catch {}
    await sleep(250)
  }
  check("a tool from the global install reaches the bridge", text.includes("Bridge up"),
    text.slice(0, 160))
  check("it reports no target yet", text.includes("none"), text.slice(0, 300))

  const attach = (await import(pathToFileURL(join(globalTools, "ce_attach.ts")).href)).default
  const attached = await attach.execute({ name: "lab_target.exe" })
  check("the global install can attach", attached.includes("Attached"), attached.slice(0, 200))

  const read = (await import(pathToFileURL(join(globalTools, "ce_read.ts")).href)).default
  const modules = (await import(pathToFileURL(join(globalTools, "ce_modules.ts")).href)).default
  const list = await modules.execute({ filter: "lab_target" })
  check("modules come back", list.includes("lab_target.exe"), list.slice(0, 200))
  const base = list.split("\n").find((l: string) => l.includes("lab_target.exe"))!
    .trim().split(/\s+/)[1]
  const truth = readFileSync(LOG, "utf8")
  const health = truth.split(/\r?\n/).find((l) => l.startsWith("g_health="))!.split("=")[1]
  const offset = "0x" + (BigInt("0x" + health) - BigInt(base)).toString(16)
  const value = await read.execute({ module: "lab_target.exe", offset, type: "i32" })
  check("a real value reads through the global install", /=\s+\d+/.test(value), value.slice(0, 200))

  const unlock = (await import(pathToFileURL(join(globalTools, "ce_unlock.ts")).href)).default
  const scan = (await import(pathToFileURL(join(globalTools, "ce_scan.ts")).href)).default
  const undo = (await import(pathToFileURL(join(globalTools, "ce_undo.ts")).href)).default
  const write = (await import(pathToFileURL(join(globalTools, "ce_write.ts")).href)).default

  const started = await scan.execute({
    phase: "start", scan_type: "exact", type: "i32", value: "987654",
    alignment: 4, module: "lab_target.exe",
  })
  check("scanning works from the global install", /Started: \d+ candidates/.test(started),
    started.slice(0, 160))

  check("unlock works", (await unlock.execute({ writable: true })).includes("allowed"))
  const written = await write.execute({
    address: "0x" + health, value: "12345", type: "i32", note: "global e2e",
  })
  check("writing works", written.includes("12345"), written.slice(0, 200))
  const undoId = written.match(/undo id (\w+)/)?.[1]
  check("undo works", (await undo.execute({ id: undoId })).includes("Reverted 1"))
} finally {
  bridge?.kill()
  lab.kill()
}

console.log(`\n${passed} passed, ${failures.length} failed`)
for (const f of failures) console.log(`  FAILED: ${f}`)
process.exit(failures.length ? 1 : 0)
