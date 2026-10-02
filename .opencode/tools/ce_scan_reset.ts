import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Discard the current scan. */
export default tool({
  description: "Discard the current scan and start over. Freees the candidate list.",
  args: {},
  async execute() {
    await call("scan_reset")
    return "Scan cleared."
  },
})
