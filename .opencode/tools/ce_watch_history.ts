import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Read the samples a running ce_watch has collected. */
export default tool({
  description:
    "Read the samples a running ce_watch has collected, marking the moments the value " +
    "actually changed. The timestamps are what tell you whether a change was caused by " +
    "something you did in the game.",
  args: {
    address: tool.schema.string().describe("the watched address"),
  },
  async execute(args) {
    const result = await call("watch_history", { address: args.address })
    if (!result.history.length) {
      return "No samples yet. Is ce_watch still running for this address? Give it a second or two."
    }
    const lines = [`${result.history.length} samples at ${result.address}:`]
    let previous: unknown = undefined
    for (const sample of result.history) {
      const changed = previous !== undefined && sample.value !== previous
      lines.push(`  ${sample.t}  ${JSON.stringify(sample.value)}${changed ? "   <- changed" : ""}`)
      previous = sample.value
    }
    return lines.join("\n")
  },
})
