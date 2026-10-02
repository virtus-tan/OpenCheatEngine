import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** List every write this session made. */
export default tool({
  description:
    "List every write this session made, with the bytes before and after, newest first. " +
    "Use it to review what you changed, or to find the undo id of something you want " +
    "to put back.",
  args: {
    limit: tool.schema.number().optional().describe("how many, newest first"),
    include_undone: tool.schema.boolean().optional().describe("include reverted writes"),
  },
  async execute(args) {
    const result = await call("journal", {
      limit: args.limit ?? 100,
      include_undone: args.include_undone ?? true,
    })
    if (!result.count) return "No writes have been journaled."
    const rows = result.entries.map(
      (e: any) =>
        `  ${e.timestamp}  ${e.address}  ${e.kind.padEnd(12)} ${e.before} -> ${e.after}` +
        `${e.undone ? "  [undone]" : ""}${e.note ? `  ${e.note}` : ""}`,
    )
    return `${result.count} journaled write(s):\n${rows.join("\n")}`
  },
})
