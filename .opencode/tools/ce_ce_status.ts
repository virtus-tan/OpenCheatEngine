import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Cheat Engine agent status, and the one-time install. */
export default tool({
  description:
    "The Cheat Engine side of the bridge: whether its agent is connected, what that agent " +
    "can do, and how many rows are in its address list. If the agent is missing, action=" +
    "install copies it into Cheat Engine's autorun folder, which has to be done once from " +
    "an elevated terminal and needs Cheat Engine restarted afterwards.",
  args: {
    action: tool.schema
      .enum(["status", "install"])
      .optional()
      .describe("status by default, or install the agent"),
  },
  async execute(args) {
    if (args.action === "install") {
      const r = await call("ce_install", {})
      return r.ok
        ? `Agent installed to ${r.destination}. ${r.note}`
        : `Install failed: ${r.error}` +
          (r.destination
            ? `\n  run this once from an elevated terminal:\n  copy "${r.source}" "${r.destination}"`
            : "")
    }
    const r = await call("ce_status", { refresh: true })
    const lines = [
      `agent connected : ${r.agent_seen ? "yes" : "no"}`,
      `agent version   : ${r.agent_version ?? "n/a"}`,
      `CE version      : ${r.ce_version ?? "unknown"}`,
      `CE running      : ${r.ce_running ? `pid ${r.ce_pid}` : "no"}`,
      `agent installed : ${r.agent_installed ? "yes" : "no"}`,
      `attached in CE  : ${r.attached_pid ? `pid ${r.attached_pid} ${r.attached_name ?? ""}` : "nothing"}`,
      `address list    : ${r.address_list_count} entries`,
      `spool           : ${r.spool}`,
    ]
    if (r.capabilities?.length) lines.push(`agent can do    : ${r.capabilities.join(", ")}`)
    if (r.hint) lines.push(`note            : ${r.hint}`)
    return lines.join("\n")
  },
})
