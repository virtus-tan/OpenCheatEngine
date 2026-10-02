import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Start Cheat Engine. */
export default tool({
  description:
    "Start Cheat Engine, if it is not already running. Use the default for a 64-bit " +
    "game; pass arch=x86 for a 32-bit one. The human then opens the game and attaches to " +
    "it in Cheat Engine, and the bridge picks the target up on its own within a second. " +
    "This never chooses a process for them, which is deliberate.",
  args: {
    arch: tool.schema
      .enum(["x64", "x86"])
      .optional()
      .describe("which Cheat Engine build to start, default x64"),
    avx: tool.schema
      .boolean()
      .optional()
      .describe("prefer the SSE4-AVX2 build, which scans faster"),
  },
  async execute(args) {
    const r = await call("ce_launch", { arch: args.arch ?? "x64", avx: args.avx ?? false })
    if (!r.ok) return `Could not start Cheat Engine: ${r.error}`
    if (r.already_running) return `Cheat Engine is already running (pid ${r.pid}). ${r.next}`
    return `Cheat Engine started (pid ${r.pid}) from ${r.path}.\n${r.next}`
  },
})
