import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** List classes, fields and methods inside a managed assembly on disk. */
export default tool({
  description:
    "List the classes, fields and methods inside a managed assembly straight from disk, " +
    "with no target access at all, so it works even while the game is closed. This is the " +
    "fastest route to the value you want: point it at the game's " +
    "<Game>_Data/Managed/Assembly-CSharp.dll with a filter such as \"Player|Health|Money\", " +
    "read the real field names, then use ce_managed to get the offset or the live value. " +
    "Leave path empty once a target is attached and the bridge will find the folder itself.",
  args: {
    path: tool.schema
      .string()
      .optional()
      .describe("full path to a managed dll; omit to auto-detect from the target"),
    filter: tool.schema
      .string()
      .optional()
      .describe('case-insensitive regex on the full type name, e.g. "Player|Health"'),
    limit: tool.schema.number().optional().describe("how many types to return"),
  },
  async execute(args) {
    const r = await call("managed_metadata", {
      path: args.path,
      filter: args.filter ?? "",
      limit: args.limit ?? 400,
    })
    if (!r.filtered) return `${r.assembly} has ${r.types} types, none matched ${args.filter}.`
    const lines = [`${r.assembly}: ${r.filtered} of ${r.types} types`]
    for (const t of r.result) {
      lines.push(`  ${t.full_name}`)
      if (t.fields.length) lines.push(`      fields:  ${t.fields.join(", ")}`)
      if (t.methods.length) lines.push(`      methods: ${t.methods.slice(0, 20).join(", ")}`)
    }
    if (r.truncated) lines.push(`  ... truncated at ${r.limit}`)
    return lines.join("\n")
  },
})
