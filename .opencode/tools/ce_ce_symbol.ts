import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Register a name in Cheat Engine so its UI shows it. */
export default tool({
  description:
    "Register a name in Cheat Engine for an address, so the address list and the " +
    "disassembly show something meaningful instead of a hex number. Use a " +
    "module-relative expression such as \"game.exe+1234\" when the address moves between " +
    "runs, so the name keeps resolving.",
  args: {
    name: tool.schema.string().describe("the name to register"),
    address: tool.schema.string().describe("address, or a module+offset expression"),
  },
  async execute(args) {
    const r = await call("ce_register_symbol", { name: args.name, address: args.address })
    return `Registered ${r.name} at ${r.address}${r.resolved ? ` (resolved to ${r.resolved})` : ""}. Cheat Engine will show it from now on.`
  },
})
