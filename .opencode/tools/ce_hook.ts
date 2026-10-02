import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Redirect execution at an address. */
export default tool({
  description:
    "Redirect execution at an address to somewhere else, with a trampoline so the " +
    "original function can still be called. Needs ce_unlock, and is x64 only. It refuses " +
    "to patch across a relative branch rather than producing a broken trampoline, so " +
    "hook the first instruction of a function rather than a jump in the middle of it.",
  args: {
    address: tool.schema.string().describe("the address to redirect"),
    replacement: tool.schema.string().describe("where to jump to instead"),
  },
  async execute(args) {
    const r = await call("hook", { address: args.address, replacement: args.replacement })
    return (
      `Hooked ${r.address} -> ${r.replacement}\n` +
      `  overwrote ${r.window} byte(s), was ${r.original}\n` +
      (r.trampoline ? `  trampoline at ${r.trampoline}` : "  no trampoline")
    )
  },
})
