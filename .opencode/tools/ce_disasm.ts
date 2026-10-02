import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Disassemble instructions at an address. */
export default tool({
  description:
    "Disassemble instructions at an address, for the target's own architecture. Jump " +
    "thunks are followed by default, because a linker often leaves a five byte jump at " +
    "the address of a function and the code you want is one hop away. This is how you " +
    "read the code that writes a value you found by scanning.",
  args: {
    address: tool.schema.string().describe("absolute address as hex"),
    count: tool.schema.number().optional().describe("how many instructions, default 16"),
    module: tool.schema
      .string()
      .optional()
      .describe("module name; then address is an offset from its base"),
    follow_thunk: tool.schema
      .boolean()
      .optional()
      .describe("follow a leading jmp, default true"),
  },
  async execute(args) {
    const result = await call("disasm", {
      address: args.address,
      count: args.count ?? 16,
      module: args.module,
      follow_thunk: args.follow_thunk ?? true,
    })
    const head =
      `${result.address}` +
      (result.module ? `  ${result.module}+${result.module_offset}` : "") +
      (result.thunk_hops?.length
        ? `\nfollowed ${result.thunk_hops.map((h: any) => `${h.from}->${h.to}`).join(", ")}`
        : "")
    return `${head}\n\n${result.text}`
  },
})
