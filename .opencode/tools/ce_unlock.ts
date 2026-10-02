import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Allow or forbid writes. */
export default tool({
  description:
    "Turn writes on or off for the attached target. The bridge starts read-only on " +
    "purpose so that nothing is changed by accident. Once writable, every write is " +
    "journaled with the bytes that were there before, so ce_undo can put them back. " +
    "Call this with writable=false to go back to read-only.",
  args: {
    writable: tool.schema.boolean().optional().describe("true to allow writes"),
  },
  async execute(args) {
    const result = await call("unlock", { writable: args.writable ?? true })
    return result.writable
      ? "Writes are now allowed. Every write is journaled; use ce_undo to revert."
      : "Back to read-only. Writes, patches, injection and freezes are refused."
  },
})
