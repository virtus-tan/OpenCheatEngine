import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Patch machine code at an address, with a guard on what should be there. */
export default tool({
  description:
    "Patch machine code at an address. expected is what you believe is there now; the " +
    "patch is refused if it does not match, which is what stops you from corrupting a " +
    "different build of the game, and tells you the game has already been patched. " +
    "Journaled and undoable.",
  args: {
    address: tool.schema.string().describe("address to patch, as hex"),
    expected: tool.schema
      .string()
      .optional()
      .describe('the bytes that must be there now, e.g. "74 05"; omit to skip the check'),
    replacement: tool.schema.string().describe("the bytes to write, as hex"),
    note: tool.schema.string().optional().describe("what this patch does"),
  },
  async execute(args) {
    const result = await call("patch", {
      address: args.address,
      expected: args.expected,
      replacement: args.replacement,
      note: args.note,
    })
    return (
      `Patched ${result.address}${result.module ? ` (${result.module}+${result.module_offset})` : ""}\n` +
      `  was ${result.before}\n  now ${result.after}\n  undo id ${result.undo_id}`
    )
  },
})
