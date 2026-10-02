import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Push findings into Cheat Engine's address list. */
export default tool({
  description:
    "Add addresses to Cheat Engine's own address list, with names and comments, so what " +
    "the bridge found appears in the Cheat Engine window. Do this after narrowing a scan " +
    "or reading a managed field, so the human can watch the value themselves and see " +
    "what the AI found.",
  args: {
    addresses: tool.schema
      .array(
        tool.schema.object({
          address: tool.schema.string().describe("address as hex"),
          name: tool.schema.string().optional().describe("display name"),
          type: tool.schema.string().optional().describe("value type, default f32"),
          comment: tool.schema.string().optional().describe("comment shown in the list"),
          value: tool.schema.number().optional().describe("value to set it to"),
        }),
      )
      .describe("the rows to add"),
  },
  async execute(args) {
    const r = await call("ce_mirror", { items: args.addresses })
    const lines = [
      `Added ${r.added} row(s) to the Cheat Engine address list (now ${r.address_list_count} entries).`,
    ]
    for (const e of r.entries) {
      lines.push(`  ${e.address}  ${e.name ?? ""}${e.resolved ? `  -> ${e.resolved}` : ""}`)
    }
    for (const err of r.errors ?? []) lines.push(`  failed: ${err.error}`)
    return lines.join("\n")
  },
})
