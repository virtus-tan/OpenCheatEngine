import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Release the target. */
export default tool({
  description:
    "Release the target: stop freezing and watching, close the handle, and invalidate " +
    "every cached address. The bridge does this on its own when you detach in Cheat " +
    "Engine or the game exits, so this is only for switching targets deliberately.",
  args: {},
  async execute() {
    const result = await call("detach")
    return result.detached
      ? `Released the target (was pid ${result.pid}). All addresses are now stale.`
      : "No target was attached."
  },
})
