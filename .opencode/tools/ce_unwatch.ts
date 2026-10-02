import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Stop sampling an address. */
export default tool({
  description: "Stop sampling an address and release its sampler.",
  args: {
    address: tool.schema.string().describe("the watched address"),
  },
  async execute(args) {
    const result = await call("unwatch", { address: args.address })
    return `Stopped watching ${args.address}. ${result.history.length} samples were kept.`
  },
})
