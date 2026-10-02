import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Remove a hook and restore the original bytes. */
export default tool({
  description: "Remove a hook, put the original bytes back and free its trampoline.",
  args: {
    address: tool.schema.string().describe("the hooked address"),
  },
  async execute(args) {
    const r = await call("unhook", { address: args.address })
    return `Restored ${r.address} to ${r.restored}.`
  },
})
