import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Show the current scan's results. */
export default tool({
  description:
    "Show the current scan's results, paged, with the value at each address. Use " +
    "group=true first: it clusters addresses by value, which is how you spot the right " +
    "one before the scan has narrowed down to a single hit.",
  args: {
    offset: tool.schema.number().optional().describe("result index to start at"),
    limit: tool.schema.number().optional().describe("how many results, default 500"),
    group: tool.schema
      .boolean()
      .optional()
      .describe("group addresses by value, largest group first"),
  },
  async execute(args) {
    const result = await call("scan_results", {
      offset: args.offset ?? 0,
      limit: args.limit ?? 500,
      group: args.group ?? false,
      values: true,
    })
    const lines = [
      `${result.total} result(s), showing ${result.returned} from ${result.offset} (pass ${result.pass})` +
        (result.truncated ? " [truncated at max_results]" : ""),
    ]
    if (args.group) {
      if (!result.groups?.length) lines.push("  (no results)")
      for (const g of result.groups) {
        lines.push(`  ${g.count}x  ${g.value}`)
        lines.push(`      ${g.addresses.slice(0, 6).join(" ")}`)
      }
    } else {
      for (const item of result.results) {
        lines.push(`  ${item.address}  ${JSON.stringify(item.value)}`)
      }
      if (result.total > result.returned) {
        lines.push(`  ... ${result.total - result.returned} more, pass offset=${result.offset + result.returned}`)
      }
    }
    return lines.join("\n")
  },
})
