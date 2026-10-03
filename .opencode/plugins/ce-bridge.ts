import type { Plugin } from "@opencode-ai/plugin"
import { endpoint } from "../lib/bridge-client.ts"

/**
 * Live link to the CE Testing bridge.
 *
 * The 43 tools are request/response, so between calls there is nothing on
 * screen and no way to tell a bridge that is running from one that is not.
 * That made attaching in Cheat Engine look like it had done nothing.
 *
 * This plugin holds one connection open instead: GET /api/events is a stream
 * the bridge writes to whenever its state changes. So the shell knows the
 * moment a target appears, and "connected" becomes a fact rather than an
 * inference from a poll that may never have run.
 */

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

const RECONNECT_MIN_MS = 1000
const RECONNECT_MAX_MS = 15000

type Level = "debug" | "info" | "warn" | "error"
type Frame = { kind: string; data: any }

// Module level so shell.env can report the state, and so a plugin reloaded
// during development replaces its stream instead of leaking a second one.
let inflight: AbortController | null = null
let connected = false
let lastEventAt = 0

/**
 * Split a text/event-stream body into frames.
 *
 * Heartbeat comments and unparseable payloads are skipped rather than thrown
 * on: a keepalive must never be able to tear the connection down, and a
 * truncated frame just means the stream was cut mid-write.
 */
function parseFrames(buffer: string): { frames: Frame[]; rest: string } {
  const frames: Frame[] = []
  let rest = buffer
  for (;;) {
    const split = rest.indexOf("\n\n")
    if (split < 0) break
    const raw = rest.slice(0, split)
    rest = rest.slice(split + 2)

    let kind = "message"
    const data: string[] = []
    for (const line of raw.split("\n")) {
      if (line.startsWith(":")) continue
      if (line.startsWith("event:")) kind = line.slice(6).trim()
      else if (line.startsWith("data:")) data.push(line.slice(5).trimStart())
    }
    if (!data.length) continue
    try {
      frames.push({ kind, data: JSON.parse(data.join("\n")) })
    } catch {}
  }
  return { frames, rest }
}

function describeTarget(target: any): string {
  if (!target) return "No process is attached. Attach in Cheat Engine to continue."
  return (
    `${target.name} · pid ${target.pid} · ${target.arch} · ` +
    `${target.writable ? "writable" : "read-only"}`
  )
}

export const CEBridgePlugin: Plugin = async ({ client }) => {
  const log = (level: Level, message: string) =>
    client.app.log({ body: { service: "ce-bridge", level, message } }).catch(() => {})

  const toast = (title: string, message: string, variant: "info" | "success" | "warning") =>
    client.tui.showToast({ body: { title, message, variant } }).catch(() => {})

  // Whether the human has already been told the bridge is unreachable. Without
  // this the retry loop would raise the same toast every second.
  let reportedDown = false
  let reportedAgent: boolean | null = null

  const handle = async (frame: Frame) => {
    const { kind, data } = frame
    lastEventAt = Date.now()

    switch (kind) {
      case "hello":
        if (reportedDown) {
          await toast(
            "CE bridge connected",
            `Cheat Engine ${data?.cheat_engine?.ce_version ?? "?"} · agent ${
              data?.cheat_engine?.agent_seen ? "connected" : "not installed"
            }`,
            "info",
          )
        }
        reportedDown = false
        reportedAgent = data?.cheat_engine?.agent_seen ?? false
        await log("info", `stream open at ${endpoint().url} · ${describeTarget(data?.target)}`)
        return

      case "attached":
        await log("info", `target attached: ${describeTarget(data?.target)}`)
        await toast("Target attached", describeTarget(data.target), "success")
        return

      case "detached":
        await log("info", `target released: ${describeTarget(data?.target)}`)
        await toast("Target released", describeTarget(data.target), "info")
        return

      case "attach_failed":
        await log("error", `attach failed for pid ${data?.pid}: ${data?.error}`)
        await toast("Attach failed", `pid ${data?.pid}: ${data?.error}`, "warning")
        return

      case "unlocked": {
        const target = data?.target
        const writable = Boolean(target?.writable)
        await log("info", `target is now ${writable ? "writable" : "read-only"}`)
        await toast(
          writable ? "Target unlocked" : "Target locked",
          writable
            ? `${target.name} · writes are allowed and journaled`
            : `${target?.name ?? "Target"} · back to read-only`,
          writable ? "warning" : "info",
        )
        return
      }

      case "cheat_engine": {
        // Fires whenever the agent's report changes, which includes Cheat
        // Engine closing. Only the edges get a toast: the middle would fire on
        // every status.txt tick.
        const seen = Boolean(data?.cheat_engine?.agent_seen)
        const version = data?.cheat_engine?.ce_version
        if (seen && reportedAgent !== true) {
          reportedAgent = true
          await toast("Cheat Engine agent connected", `Cheat Engine ${version ?? "?"}`, "info")
        } else if (!seen && reportedAgent === true) {
          reportedAgent = false
          await log("warn", "the Cheat Engine agent stopped reporting")
          await toast(
            "Cheat Engine agent gone",
            "Start Cheat Engine again, or install the agent once with ce_ce_install",
            "warning",
          )
        }
        await log("debug", `cheat_engine: agent_seen=${seen} version=${version ?? "?"}`)
        return
      }

      case "bridge_stopped":
        await log("warn", "the bridge shut down; the stream will reconnect")
        await toast("CE bridge stopped", "Start it again with: python bridge.py start", "warning")
        return

      default:
        await log("debug", `event ${kind}`)
    }
  }

  const wait = (ms: number) => new Promise((done) => setTimeout(done, ms))

  const watch = async (signal: AbortSignal) => {
    let backoff = RECONNECT_MIN_MS
    while (!signal.aborted) {
      const { url, token } = endpoint()
      try {
        const response = await fetch(`${url}/api/events`, {
          headers: { "X-CE-Bridge-Token": token, Accept: "text/event-stream" },
          signal,
        })
        if (response.status === 401) {
          // Retrying the same token would fail identically forever. The bridge
          // rewrites endpoint.json on every start, so wait for a new one.
          connected = false
          if (!reportedDown) {
            reportedDown = true
            await log("warn", "the bridge rejected the token")
            await toast(
              "CE bridge token rejected",
              "Restart the bridge so it publishes a new token",
              "warning",
            )
          }
          await wait(backoff)
          backoff = Math.min(backoff * 2, RECONNECT_MAX_MS)
          continue
        }
        if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`)

        connected = true
        backoff = RECONNECT_MIN_MS
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ""
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })
          const parsed = parseFrames(buffer)
          buffer = parsed.rest
          for (const frame of parsed.frames) await handle(frame)
        }
        throw new Error("the stream ended")
      } catch (error) {
        if (signal.aborted) return
        connected = false
        if (!reportedDown) {
          reportedDown = true
          await log("warn", `bridge stream unavailable: ${(error as Error).message}`)
          await toast(
            "CE bridge not running",
            `Cannot reach ${url}. Start it with: python bridge.py start`,
            "warning",
          )
        }
        await log("debug", `reconnecting to ${url} in ${backoff} ms`)
        await wait(backoff)
        backoff = Math.min(backoff * 2, RECONNECT_MAX_MS)
      }
    }
  }

  await log("debug", "plugin loaded")

  inflight?.abort()
  inflight = new AbortController()
  void watch(inflight.signal)

  return {
    event: async ({ event }) => {
      // server.connected fires once per opencode start, which is too early to
      // be the only signal: the bridge is usually started afterwards. The
      // stream is already running, so this only reports where it got to.
      if (event.type === "server.connected") {
        await log("info", connected ? "bridge stream connected" : "bridge stream not connected yet")
      }
      if (event.type === "session.idle" && connected) {
        await log(
          "debug",
          `stream healthy, last event ${Math.round((Date.now() - lastEventAt) / 1000)}s ago`,
        )
      }
    },

    "tool.execute.after": async (input, output) => {
      if (!input.tool.startsWith("ce_")) return
      if (output.error) await log("warn", `${input.tool} failed: ${output.error}`)
    },

    "shell.env": async (input, output) => {
      output.env.CE_BRIDGE_AGENT_HINT = AGENT_HINT
      output.env.CE_BRIDGE_URL = output.env.CE_BRIDGE_URL ?? "http://127.0.0.1:9877"
      // So a command the agent runs can see whether the live link is up,
      // instead of assuming a tool would have failed if it were not.
      output.env.CE_BRIDGE_STREAM = connected ? "connected" : "disconnected"
    },
  }
}
