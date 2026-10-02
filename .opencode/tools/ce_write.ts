import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Write a typed value into the target. */
export default tool({
  description:
    "Write a value into the target. Needs ce_unlock first, because the target starts " +
    "read-only. The bytes that were there before are journaled and the reply carries an " +
    "undo id, so ce_undo can put them back. This reads the value again afterwards and " +
    "reports what it actually is, which is how you notice a write that did not take.",
  args: {
    address: tool.schema.string().describe("absolute address as hex"),
    value: tool.schema.string().describe("the value to write, as a number"),
    type: tool.schema
      .string()
      .optional()
      .describe("value type: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 ptr"),
    note: tool.schema
      .string()
      .optional()
      .describe("what this write is for, kept in the journal"),
  },
  async execute(args) {
    const result = await call("write", {
      address: args.address,
      value: args.value,
      type: args.type ?? "u32",
      note: args.note,
    })
    const verify = await call("read", { address: result.address, type: result.type })
    return (
      `Wrote ${result.value} (${result.type}) to ${result.address}\n` +
      `  was ${result.before}\n` +
      `  now ${JSON.stringify(verify.value)}\n` +
      `  undo id ${result.undo_id}`
    )
  },
})
