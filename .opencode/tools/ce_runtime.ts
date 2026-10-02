import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Detect native vs Mono vs IL2CPP, and what is available. */
export default tool({
  description:
    "Detect whether the target is native C++, Unity Mono, or Unity IL2CPP, and say which " +
    "managed operations are available. Call this before any other ce_managed tool. It " +
    "decides the whole approach: a Mono or IL2CPP game can be read by class and field " +
    "name, which beats scanning for a number, while a native game means scanning and " +
    "reading the code that writes the value.",
  args: {
    refresh: tool.schema
      .boolean()
      .optional()
      .describe("re-detect, needed if the game loaded a new assembly or scene"),
  },
  async execute(args) {
    const r = await call("runtime", { refresh: args.refresh ?? false })
    const lines = [
      `Runtime: ${r.kind}`,
      `  module           : ${r.module ?? "none"}`,
      `  module base      : ${r.module_base ?? "n/a"}`,
      `  exports came from: ${r.export_source ?? "n/a"}`,
      `  managed folder   : ${r.has_file_metadata ? "found" : "not found"}`,
      `  available        : ${r.capabilities.join(", ") || "nothing"}`,
    ]
    if (r.note) lines.push(`  note             : ${r.note}`)
    if (r.kind === "native") {
      lines.push("")
      lines.push("This looks like a native game. Use ce_scan to find values, then ce_xrefs")
      lines.push("on what you find to read the code that writes it.")
    } else {
      lines.push("")
      lines.push(`Start with ce_managed action=metadata and filter="Health|Player|Money".`)
    }
    return lines.join("\n")
  },
})
