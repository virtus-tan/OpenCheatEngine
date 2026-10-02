import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Sample a value over time. */
export default tool({
  description:
    "Start sampling a value on a timer. Non-invasive, so it is safe against a running " +
    "game. Start it, change something in the game, then read ce_watch_history to see " +
    "exactly which values moved. This finds the address of a change that a plain " +
    "changed scan would miss, and pairs with ce_xrefs to find the code responsible.",
  args: {
    address: tool.schema.string().describe("the address to sample"),
    type: tool.schema.string().optional().describe("value type, default f32"),
    interval: tool.schema.number().optional().describe("seconds between samples, default 0.25"),
    duration: tool.schema
      .number()
      .optional()
      .describe("seconds to keep sampling; 0 means until ce_unwatch"),
  },
  async execute(args) {
    const result = await call("watch", {
      address: args.address,
      type: args.type ?? "f32",
      interval: args.interval ?? 0.25,
      duration: args.duration ?? 0,
    })
    return (
      `Watching ${result.watching} as ${result.type} every ${result.interval}s.\n` +
      `Change something in the game, wait a moment, then call ce_watch_history.`
    )
  },
})
