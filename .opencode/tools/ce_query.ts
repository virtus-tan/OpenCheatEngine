import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Describe an address: region, protection and owning module. */
export default tool({
  description:
    "Describe an address: the region it is in, its protection, and which module owns it. " +
    "The quickest way to find out whether an address is still valid after the game moved " +
    "things around, and to turn a raw address into a module-relative offset you can reuse.",
  args: {
    address: tool.schema.string().describe("absolute address as hex"),
  },
  async execute(args) {
    const r = await call("query", { address: args.address })
    return (
      `${r.base} +${r.size}  ${r.state} ${r.protect} ${r.type}\n` +
      `  writable=${r.writable} executable=${r.executable}\n` +
      (r.module ? `  module ${r.module}${r.module_offset ? "+" + r.module_offset : ""}\n` : "") +
      (r.section ? `  section ${r.section}\n` : "")
    )
  },
})
