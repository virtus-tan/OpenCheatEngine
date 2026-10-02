import type { Plugin } from "@opencode-ai/plugin"
import { call, resetEndpointCache } from "../lib/bridge-client.ts"

const AGENT_HINT = `The CE Testing bridge drives Cheat Engine. Workflow:
  1. ce_ce_status to see whether Cheat Engine and its agent are connected.
  2. The human opens the game and attaches to it in Cheat Engine. There is no tool that
     picks a process for them, and none is needed: the target appears on its own.
  3. ce_status to confirm the target, then ce_modules or ce_runtime to find out what
     kind of game it is.
  4. ce_managed when the game is Mono or IL2CPP, because reading the class and field
     name beats scanning for a float. ce_scan for native games.
  5. Mirror anything interesting into Cheat Engine with ce_ce_mirror so the human can
     watch it.
  The target starts read-only: call ce_unlock before writing, and ce_undo to revert.`

let reported = { agent: false, target: null as number | null }

export const CEBridgePlugin: Plugin = async ({ client }) => {
  await client.app.log({
    body: {
      service: "ce-bridge",
      level: "debug",
      message: "plugin loaded",
    },
  }).catch(() => {})

  const refresh = async () => {
    resetEndpointCache()
    let status: any
    try {
      status = await call("status")
    } catch (error) {
      if (!reported.agent) {
        reported.agent = true
        await client.app
          .log({
            body: {
              service: "ce-bridge",
              level: "info",
              message: (error as Error).message,
            },
          })
          .catch(() => {})
        await client.tui
          .showToast({
            body: {
              title: "CE bridge not running",
              message: "Start it with: python bridge.py start",
              variant: "warning",
            },
          })
          .catch(() => {})
      }
      return
    }
    if (!reported.agent) {
      reported.agent = true
      await client.tui
        .showToast({
          body: {
            title: "CE bridge connected",
            message: `Cheat Engine ${status.cheat_engine?.ce_version ?? "?"} Â· agent ${
              status.cheat_engine?.agent_seen ? "connected" : "not installed"
            }`,
            variant: "info",
          },
        })
        .catch(() => {})
    }
    const pid = status.target?.pid ?? null
    if (pid !== reported.target) {
      reported.target = pid
      await client.tui
        .showToast({
          body: {
            title: pid ? "Target attached" : "Target released",
            message: pid
              ? `${status.target.name} Â· pid ${pid} Â· ${status.target.arch} Â· ${
                  status.target.writable ? "writable" : "read-only"
                }`
              : "No process is attached. Attach in Cheat Engine to continue.",
            variant: pid ? "success" : "info",
          },
        })
        .catch(() => {})
    }
  }

  return {
    event: async ({ event }) => {
      if (event.type === "server.connected") await refresh()
      if (event.type === "session.idle") await refresh()
    },

    "tool.execute.after": async (input, output) => {
      if (!input.tool.startsWith("ce_")) return
      if (output.error) {
        await client.app
          .log({
            body: {
              service: "ce-bridge",
              level: "warn",
              message: `${input.tool} failed: ${output.error}`,
            },
          })
          .catch(() => {})
      }
      if (input.tool === "ce_status" || input.tool === "ce_ce_status") await refresh()
    },

    "shell.env": async (input, output) => {
      output.env.CE_BRIDGE_AGENT_HINT = AGENT_HINT
      output.env.CE_BRIDGE_URL = output.env.CE_BRIDGE_URL ?? "http://127.0.0.1:9877"
    },
  }
}

