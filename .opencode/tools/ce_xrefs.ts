import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Find what refers to an address. */
export default tool({
  description:
    "Find what refers to an address: instructions that read or write it, and pointer " +
    "slots that hold it. This is the step from a value you found by scanning back to the " +
    "code that changes it. Handles both direct pointer references and x64 RIP-relative " +
    "references, which is how 64-bit compilers address data.",
  args: {
    address: tool.schema.string().describe("the address to find references to, as hex"),
    code_only: tool.schema
      .boolean()
      .optional()
      .describe("only scan code, default true; false also finds data pointers"),
    max_hits: tool.schema.number().optional().describe("stop after this many"),
  },
  async execute(args) {
    const result = await call("xrefs", {
      address: args.address,
      code_only: args.code_only ?? true,
      max_hits: args.max_hits ?? 256,
    })
    if (!result.count) {
      return (
        `Nothing references ${result.target}. ` +
        `If the value is reached through a pointer, run ce_pointer_chains on it instead.`
      )
    }
    const lines = [
      `${result.count} reference(s) to ${result.target}${result.truncated ? " [stopped early]" : ""}:`,
    ]
    for (const ref of result.xrefs) {
      lines.push(
        `  ${ref.address}  ${ref.kind.padEnd(8)}` +
          (ref.instruction ? `  ${ref.instruction_bytes}  ${ref.instruction}` : ""),
      )
    }
    lines.push("")
    lines.push("Disassemble around these with ce_disasm to see what the code does with the value.")
    return lines.join("\n")
  },
})
