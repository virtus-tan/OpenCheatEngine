import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Call an exported function inside the target. */
export default tool({
  description:
    "Call an exported function inside the target and get its return value. Use it to ask " +
    "the game itself a question, for example GetTickCount or lstrlenA, and to reach the " +
    "Mono and IL2CPP runtime functions directly. Up to 4 arguments on x64, 8 on x86. " +
    "Not available for 32-bit targets: Windows will not create a 32-bit thread in a " +
    "WOW64 process from a 64-bit one.",
  args: {
    module: tool.schema.string().describe("module holding the export, e.g. kernel32.dll"),
    export: tool.schema.string().describe("export name, e.g. GetCurrentProcessId"),
    args: tool.schema
      .array(tool.schema.number())
      .optional()
      .describe("integer arguments, each a raw pointer or value"),
  },
  async execute(args) {
    const r = await call("remote_call", {
      module: args.module,
      export: args.export,
      args: args.args ?? [],
    })
    return `${r.module}!${r.export} returned ${r.result}`
  },
})
