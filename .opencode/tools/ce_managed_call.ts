import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Call a managed method inside the target. */
export default tool({
  description:
    "Call a managed method inside the target. This runs game code, so it can have real " +
    "side effects: use it for something you want the game to do, not to poke around. " +
    "argc must match the method's parameter count. x64 only.",
  args: {
    assembly: tool.schema.string().describe("assembly name"),
    type: tool.schema.string().describe("full type name"),
    method: tool.schema.string().describe("method name"),
    argc: tool.schema.number().optional().describe("parameter count, default 0"),
  },
  async execute(args) {
    const r = await call("managed_call", {
      assembly: args.assembly,
      type: args.type,
      method: args.method,
      argc: args.argc ?? 0,
      timeout: 20000,
    })
    return (
      `Called ${r.assembly}!${r.type}::${r.method}\n` +
      `  returned ${r.result}\n` +
      (r.exception ? `  raised an exception: ${r.exception}` : "  no exception")
    )
  },
})
