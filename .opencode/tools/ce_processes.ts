import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** List running processes, to find a pid for ce_attach. */
export default tool({
  description:
    "List running processes with their pid, window title and executable path, so you can " +
    "find a game and hand its pid to ce_attach. The human normally chooses the process " +
    "in Cheat Engine instead, so this is mostly for diagnosis and for driving the " +
    "bridge with no Cheat Engine involved.",
  args: {
    filter: tool.schema
      .string()
      .optional()
      .describe("case-insensitive substring matched against name, title and path"),
    include_system: tool.schema
      .boolean()
      .optional()
      .describe("include processes with no visible executable path"),
  },
  async execute(args) {
    const result = await call("processes", {
      filter: args.filter ?? "",
      include_system: args.include_system ?? false,
    })
    if (!result.count) return "No processes matched."
    const rows = result.processes.map((p: any) => {
      const bits = [`pid ${String(p.pid).padStart(6)}`, (p.name ?? "?").padEnd(24)]
      if (p.title) bits.push(`"${p.title}"`)
      if (p.exe) bits.push(p.exe)
      return "  " + bits.join("  ")
    })
    return `${result.count} process(es):\n${rows.join("\n")}`
  },
})
