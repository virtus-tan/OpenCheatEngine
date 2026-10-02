import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Revert writes. */
export default tool({
  description:
    "Revert writes. Give one undo id to revert that write, or all=true to revert every " +
    "write this session, newest first. The journal holds the exact bytes that were " +
    "there before each write, so this restores memory precisely. Read the value " +
    "afterwards with ce_read to confirm.",
  args: {
    id: tool.schema.string().optional().describe("the undo id returned by a write"),
    all: tool.schema.boolean().optional().describe("revert every write, newest first"),
  },
  async execute(args) {
    const result = await call("undo", { id: args.id, all: args.all ?? false })
    if (!result.undone) return "Nothing to undo."
    return (
      `Reverted ${result.undone} write(s):\n` +
      result.entries.map((e: any) => `  ${e.address}  restored ${e.restored}`).join("\n")
    )
  },
})
