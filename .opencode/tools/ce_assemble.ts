import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Assemble instructions into bytes without writing anything. */
export default tool({
  description:
    "Assemble x86 or x64 text into bytes for the target's architecture, without writing " +
    "anything. Use it to see what an instruction encodes, to find the right offset for a " +
    "relative jump, or to build the replacement bytes for ce_patch.",
  args: {
    asm: tool.schema.string().describe('instructions, e.g. "mov eax, 1; ret"'),
    address: tool.schema
      .string()
      .optional()
      .describe("the address it will live at, which relative jumps depend on"),
  },
  async execute(args) {
    const result = await call("assemble", { asm: args.asm, address: args.address ?? "0x0" })
    return `${result.asm}\n  at ${result.address}\n  ${result.count} instruction(s) = ${result.bytes}`
  },
})
