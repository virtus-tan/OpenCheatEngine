import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Show the target's memory regions. */
export default tool({
  description:
    "Show the target's memory regions with protection, size and owning module. Use it to " +
    "decide where to scan, for example that a value is in a writable region rather than " +
    "in the code. For a 32-bit target this describes the module images from their " +
    "section tables, because Windows does not expose a 32-bit view to a 64-bit process.",
  args: {
    writable_only: tool.schema.boolean().optional().describe("only writable regions"),
    executable_only: tool.schema.boolean().optional().describe("only executable regions"),
  },
  async execute(args) {
    const result = await call("memory_map", {
      writable_only: args.writable_only ?? false,
      executable_only: args.executable_only ?? false,
      committed_only: true,
    })
    const shown = result.regions
      .filter((r: any) => r.state === "COMMIT")
      .slice(0, 60)
      .map(
        (r: any) =>
          "  " +
          [
            r.base.padEnd(18),
            String(r.size).padStart(10),
            r.state.padEnd(8),
            r.protect.padEnd(5),
            (r.module ?? r.type).padEnd(24),
            r.section ?? "",
          ].join("  "),
      )
    return (
      `${result.count} regions, ${result.total_mb} MB committed\n` +
      (shown.length ? shown.join("\n") : "  (none)") +
      (result.count > shown.length ? `\n  ... ${result.count - shown.length} more` : "")
    )
  },
})
