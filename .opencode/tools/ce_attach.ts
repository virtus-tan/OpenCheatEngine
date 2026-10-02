import { tool } from "@opencode-ai/plugin"
import { call, describeTarget } from "../lib/bridge-client.ts"

/** Attach the bridge to a process. Normally unnecessary: Cheat Engine reports the attach itself. */
export default tool({
  description:
    "Attach the bridge to a process by pid, or look one up by name. You rarely need " +
    "this: when Cheat Engine is attached to the game the bridge adopts that process " +
    "within a second on its own. Use it when Cheat Engine's agent is not installed, or " +
    "to drive the bridge without Cheat Engine at all. The target starts read-only and " +
    "writes are refused until ce_unlock is called.",
  args: {
    pid: tool.schema.number().optional().describe("process id to attach to"),
    name: tool.schema.string().optional().describe("process name to look up, e.g. game.exe"),
    writable: tool.schema
      .boolean()
      .optional()
      .describe("allow writes immediately instead of starting read-only"),
  },
  async execute(args) {
    const result = await call("attach", {
      pid: args.pid,
      name: args.name,
      writable: args.writable ?? false,
    })
    return (
      `Attached: ${describeTarget(result)}\nPath: ${result.path}\n` +
      `Writes are ${result.writable ? "allowed" : "refused until you call ce_unlock"}.`
    )
  },
})
