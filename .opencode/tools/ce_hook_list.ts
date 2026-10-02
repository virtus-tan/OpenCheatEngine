import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** List installed hooks. */
export default tool({
  description: "List the hooks this session installed, with their trampolines.",
  args: {},
  async execute() {
    const r = await call("hook_list", {})
    if (!r.count) return "No hooks installed."
    return (
      `${r.count} hook(s):\n` +
      r.hooks
        .map(
          (h: any) =>
            `  ${h.address} -> ${h.replacement}  window ${h.window}  original ${h.original}` +
            (h.trampoline ? `  trampoline ${h.trampoline}` : ""),
        )
        .join("\n")
    )
  },
})
