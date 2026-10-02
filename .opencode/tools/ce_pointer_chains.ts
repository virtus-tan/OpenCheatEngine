import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Search for a static pointer chain that reaches an address. */
export default tool({
  description:
    "Search for a static pointer chain that reaches an address: a fixed pointer in a " +
    "module, then perhaps another, ending at the value. Use it when the address moves " +
    "between runs, because the chain itself stays valid and can be typed into Cheat " +
    "Engine as game.exe+1234 -> +0x18.",
  args: {
    address: tool.schema.string().describe("the target address as hex"),
    depth: tool.schema.number().optional().describe("how many levels, default 6"),
    max_results: tool.schema.number().optional().describe("stop after this many chains"),
    module: tool.schema
      .string()
      .optional()
      .describe("only look for the first pointer in this module"),
  },
  async execute(args) {
    const result = await call("pointer_chains", {
      address: args.address,
      depth: args.depth ?? 6,
      max_results: args.max_results ?? 32,
      module: args.module,
    })
    if (!result.count) return `No pointer chain reaches ${result.target}.`
    const lines = [`${result.count} chain(s) to ${result.target}:`]
    for (const chain of result.chains) lines.push(`  ${chain.chain}`)
    return lines.join("\n")
  },
})
