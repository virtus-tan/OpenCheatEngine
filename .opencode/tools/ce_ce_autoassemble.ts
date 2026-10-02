import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Run a Cheat Engine autoassemble script. */
export default tool({
  description:
    "Run a Cheat Engine autoassemble script. Use it when you want Cheat Engine's own " +
    "assembler and symbol table to do the work, for example an [ENABLE]/[DISABLE] script " +
    "that patches code and can be switched on and off from the Cheat Engine window. " +
    "Cheat Engine reports failures inside the script rather than raising, so read the " +
    "success flag in the reply.",
  args: {
    script: tool.schema.string().describe("the autoassemble script text"),
  },
  async execute(args) {
    const r = await call("ce_autoassemble", { script: args.script })
    return r.success
      ? "Autoassemble succeeded."
      : `Autoassemble failed: ${r.error ?? "no reason given"}`
  },
})
