/**
 * Shared client for the CE Testing bridge.
 *
 * The bridge publishes its url and token to endpoint.json in the same temp
 * directory it uses for the Cheat Engine agent, so these tools need no path
 * configuration. Environment variables override it, which is what makes the
 * bridge usable from any project directory.
 */

import { readFileSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

export type BridgeError = Error & { kind?: string; detail?: unknown }

export interface Endpoint {
  url: string
  token: string
}

const HERE = dirname(fileURLToPath(import.meta.url))
const DEFAULT_URL = "http://127.0.0.1:9877"

let cachedConfig: Endpoint | null = null

function spoolEndpoint(): Endpoint | null {
  // When CEBRIDGE_SPOOL names a spool, that is the only one consulted. Falling
  // back to the default spool as well would let a leftover endpoint from some
  // other bridge answer, and the tools would talk to the wrong process.
  const dirs = process.env.CEBRIDGE_SPOOL
    ? [process.env.CEBRIDGE_SPOOL]
    : [join(tmpdir(), "ce_bridge_spool")]
  for (const dir of dirs) {
    const path = join(dir, "endpoint.json")
    try {
      if (!existsSync(path)) continue
      const data = JSON.parse(readFileSync(path, "utf8"))
      if (data?.url && data?.token) return { url: data.url, token: data.token }
    } catch {}
  }
  return null
}

function configEndpoint(): Endpoint | null {
  // The bridge publishes endpoint.json when it starts, so this is only a
  // fallback for the case where the bridge is running but its spool is not the
  // default one. Searched in order: an explicit override, this project's
  // config, then a couple of conventional locations near the tool.
  const roots = [
    process.env.CEBRIDGE_CONFIG,
    resolve(HERE, "..", "..", "config.json"),
    resolve(HERE, "..", "..", "CE Testing bridge", "config.json"),
    resolve(HERE, "..", "..", "ce-bridge.json"),
  ].filter(Boolean) as string[]
  for (const path of roots) {
    try {
      if (!existsSync(path)) continue
      const data = JSON.parse(readFileSync(path, "utf8"))
      if (data?.token) {
        return {
          url: `http://${data.host ?? "127.0.0.1"}:${data.port ?? 9877}`,
          token: data.token,
        }
      }
    } catch {}
  }
  return null
}

export function endpoint(): Endpoint {
  if (process.env.CEBRIDGE_URL) {
    return { url: process.env.CEBRIDGE_URL, token: process.env.CEBRIDGE_TOKEN ?? "" }
  }
  // Re-read on every call: the bridge publishes endpoint.json when it starts, so
  // a call made a moment too early must find it rather than stay cached on a
  // guess for the rest of the session.
  const published = spoolEndpoint()
  if (published) return published
  if (!cachedConfig) {
    cachedConfig = configEndpoint() ?? { url: DEFAULT_URL, token: "" }
  }
  return cachedConfig
}

export function resetEndpointCache() {
  cachedConfig = null
}

/** Call one bridge tool. Throws an Error carrying the bridge's own message. */
export async function call(tool: string, params: Record<string, unknown> = {}): Promise<any> {
  const { url, token } = endpoint()
  let response: Response
  try {
    response = await fetch(`${url}/api/${tool}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CE-Bridge-Token": token,
      },
      body: JSON.stringify(params),
    })
  } catch (error) {
    const failure = new Error(
      `Cannot reach the CE bridge at ${url}. Start it with "python bridge.py start" ` +
        `in the "CE Testing bridge" folder. (${(error as Error).message})`,
    ) as BridgeError
    failure.kind = "unreachable"
    throw failure
  }

  if (response.status === 401) {
    const failure = new Error(
      `The CE bridge rejected the token. Delete ${join(tmpdir(), "ce_bridge_spool", "endpoint.json")} ` +
        `and restart the bridge so it publishes a new one.`,
    ) as BridgeError
    failure.kind = "auth"
    throw failure
  }

  let body: any
  try {
    body = await response.json()
  } catch {
    throw new Error(`The CE bridge returned a non-JSON reply (HTTP ${response.status}).`)
  }

  if (!body?.ok) {
    const failure = new Error(body?.error ?? `bridge tool ${tool} failed`) as BridgeError
    failure.kind = body?.kind ?? "error"
    failure.detail = body
    throw failure
  }
  return body.result
}

export function hex(value: number | string): string {
  if (typeof value === "number") return "0x" + value.toString(16)
  return value
}

export function fmtBytes(n: number): string {
  if (!Number.isFinite(n)) return String(n)
  if (n >= 1024 * 1024 * 1024) return `${(n / 1024 ** 3).toFixed(2)} GB`
  if (n >= 1024 * 1024) return `${(n / 1024 ** 2).toFixed(2)} MB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}

export function md(text: string | undefined): string {
  return text ?? ""
}

/** Compact summary of a target's status, used by several tools. */
export function describeTarget(status: any): string {
  if (!status) return "No target attached."
  return (
    `${status.name} (pid ${status.pid}, ${status.arch}, ` +
    `${status.writable ? "writable" : "read-only"}) attached ${status.attached_at} from ${status.source}`
  )
}
