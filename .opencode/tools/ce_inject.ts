import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Load a DLL into the target. */
export default tool({
  description:
    "Load a DLL into the target with LoadLibraryA, which is how a code cave or a probe " +
    "module gets in. The DLL must match the target's architecture, so a 32-bit game " +
    "needs a 32-bit DLL. Needs ce_unlock, and is x64 only.",
  args: {
    path: tool.schema.string().describe("full path to the dll"),
    call_entry: tool.schema
      .boolean()
      .optional()
      .describe("also call its DllMain with DLL_PROCESS_ATTACH"),
    entry_name: tool.schema.string().optional().describe("the entry export to call, default DllMain"),
  },
  async execute(args) {
    const r = await call("inject", {
      path: args.path,
      call_entry: args.call_entry ?? false,
      entry_name: args.entry_name ?? "DllMain",
    })
    return (
      `Injected ${r.path}\n  base ${r.base}\n` +
      (r.entry_called ? `  called ${r.entry}` : "  entry not called") +
      (r.entry_error ? `\n  entry error: ${r.entry_error}` : "")
    )
  },
})
