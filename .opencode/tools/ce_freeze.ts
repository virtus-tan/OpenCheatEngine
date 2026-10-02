import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Keep a value pinned by rewriting it on a timer. */
export default tool({
  description:
    "Keep a value pinned by rewriting it on a timer, which is how you defeat a game that " +
    "keeps putting the value back. Leave value out to just list what is frozen. Pass no " +
    "address at all to clear everything. Needs ce_unlock.",
  args: {
    address: tool.schema
      .string()
      .optional()
      .describe("address to freeze; omit with no value to list, omit entirely to clear all"),
    value: tool.schema.string().optional().describe("the value to keep writing"),
    type: tool.schema.string().optional().describe("value type, default f32"),
    interval: tool.schema.number().optional().describe("seconds between writes, default 0.1"),
  },
  async execute(args) {
    if (args.address === undefined) {
      const result = await call("unfreeze", {})
      return `Cleared ${result.removed} frozen value(s). ${result.count} still frozen.`
    }
    if (args.value === undefined) {
      const result = await call("freeze", { address: args.address })
      if (!result.count) return "Nothing is frozen."
      return result.frozen
        .map((f: any) => `  ${f.address}  ${f.type} = ${f.value}  (${f.writes} writes so far)`)
        .join("\n")
    }
    const result = await call("freeze", {
      address: args.address,
      value: args.value,
      type: args.type ?? "f32",
      interval: args.interval ?? 0.05,
    })
    const added = result.frozen.find((f: any) => f.address === args.address)
    return `Freezing ${added?.address} to ${added?.value} (${added?.type}). Call ce_freeze with no address to clear.`
  },
})
