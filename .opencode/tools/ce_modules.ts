import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** List the modules loaded in the target. */
export default tool({
  description:
    "List the modules loaded in the target: name, base address, size and path. Start " +
    "here when you want to work in module-relative offsets, which is the only kind of " +
    "address that survives restarting the game. For a 32-bit target this walks the " +
    "target's own loader list, which is the only way to see a WOW64 process's modules.",
  args: {
    filter: tool.schema
      .string()
      .optional()
      .describe("case-insensitive substring of the module name"),
  },
  async execute(args) {
    const result = await call("modules", { filter: args.filter ?? "" })
    if (!result.count) return "No modules matched."
    const rows = result.modules.map((m: any) =>
      "  " + [m.name.padEnd(30), m.base.padEnd(18), String(m.size).padStart(10), m.bitness].join("  "),
    )
    return `${result.count} module(s):\n${rows.join("\n")}`
  },
})
