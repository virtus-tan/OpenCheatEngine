import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Write raw bytes into the target. */
export default tool({
  description:
    "Write raw bytes at an address. Use this for structs, byte arrays, or patching " +
    "machine code. Journaled and undoable like ce_write.",
  args: {
    address: tool.schema.string().describe("absolute address as hex"),
    data: tool.schema.string().describe('bytes as hex, e.g. "90 90 90" or "909090"'),
    note: tool.schema.string().optional().describe("what this write is for"),
  },
  async execute(args) {
    const result = await call("write_bytes", {
      address: args.address,
      data: args.data,
      note: args.note,
    })
    return (
      `Wrote ${result.bytes} byte(s) to ${result.address}\n` +
      `  was ${result.before}\n  now ${result.value}\n  undo id ${result.undo_id}`
    )
  },
})
