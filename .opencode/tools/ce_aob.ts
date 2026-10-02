import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Find a byte signature. */
export default tool({
  description:
    "Find a byte signature in the target, for example \"48 8B ?? 05\" where ?? is any " +
    "byte and A? matches half a byte. Restrict it to a module and set require_unique to " +
    "prove the signature is good: it fails unless there is exactly one hit. Once a " +
    "signature resolves cleanly you can find the same code again after restarting the " +
    "game, with no scanning at all.",
  args: {
    pattern: tool.schema.string().describe('bytes as hex, e.g. "B8 DE AD BE EF"'),
    module: tool.schema.string().optional().describe("restrict to this module"),
    max_hits: tool.schema.number().optional().describe("stop after this many hits"),
    require_unique: tool.schema
      .boolean()
      .optional()
      .describe("fail unless exactly one hit"),
  },
  async execute(args) {
    const result = await call("aob", {
      pattern: args.pattern,
      module: args.module,
      max_hits: args.max_hits ?? 256,
      require_unique: args.require_unique ?? false,
    })
    if (!result.count) return `No match for ${result.pattern}.`
    const lines = [
      `${result.count} match(es) for ${result.pattern}${result.truncated ? " [stopped early]" : ""}:`,
    ]
    for (const hit of result.hits) {
      lines.push(
        `  ${hit.address}` +
          (hit.module ? `  ${hit.module}+${hit.offset}` : "") +
          (hit.instruction ? `\n      ${hit.bytes}  ${hit.instruction}` : ""),
      )
    }
    return lines.join("\n")
  },
})
