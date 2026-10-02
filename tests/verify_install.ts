/**
 * Verify the tools load from wherever they are installed.
 *
 *   node --experimental-strip-types tests/verify_install.ts
 *
 * Loading them is the real test: the tools import the shared client by relative
 * path, so a copy that lands in the wrong place fails here rather than silently
 * not appearing in opencode.
 */

import { existsSync, readdirSync } from "node:fs"
import { homedir } from "node:os"
import { join, resolve } from "node:path"
import { pathToFileURL } from "node:url"

const GLOBAL = join(homedir(), ".config", "opencode")
const PLACES = [
  { name: "global", base: GLOBAL },
  { name: "this project", base: resolve(process.cwd(), ".opencode") },
]

let problems = 0
for (const place of PLACES) {
  const toolsDir = join(place.base, "tools")
  if (!existsSync(toolsDir)) {
    console.log(`  skip  ${place.name}: no ${toolsDir}`)
    continue
  }
  const files = readdirSync(toolsDir).filter((f) => f.endsWith(".ts"))
  if (!files.length) {
    console.log(`  skip  ${place.name}: ${toolsDir} has no tools`)
    continue
  }
  let loaded = 0
  const failures: string[] = []
  for (const file of files) {
    try {
      const mod = await import(pathToFileURL(join(toolsDir, file)).href)
      const def = mod.default
      if (typeof def?.description !== "string" || def.description.length < 20) {
        failures.push(`${file}: no usable description`)
      } else if (typeof def?.execute !== "function") {
        failures.push(`${file}: no execute function`)
      } else {
        loaded++
      }
    } catch (error) {
      failures.push(`${file}: ${(error as Error).message.split("\n")[0]}`)
    }
  }
  const pluginsDir = join(place.base, "plugins")
  const plugins = existsSync(pluginsDir)
    ? readdirSync(pluginsDir).filter((f) => f.endsWith(".ts"))
    : []
  let pluginOk = 0
  for (const file of plugins) {
    try {
      await import(pathToFileURL(join(pluginsDir, file)).href)
      pluginOk++
    } catch (error) {
      failures.push(`plugins/${file}: ${(error as Error).message.split("\n")[0]}`)
    }
  }
  problems += failures.length
  console.log(
    `  ${failures.length ? "FAIL" : "pass"}  ${place.name}: ${loaded}/${files.length} tools, ` +
      `${pluginOk}/${plugins.length} plugins  ->  ${place.base}`,
  )
  for (const failure of failures) console.log(`        ${failure}`)
}

console.log(problems ? `\n${problems} problem(s)` : "\neverything loads")
process.exit(problems ? 1 : 0)
