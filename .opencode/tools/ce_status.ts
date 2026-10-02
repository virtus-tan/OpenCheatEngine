import { tool } from "@opencode-ai/plugin"
import { call, describeTarget, fmtBytes } from "../lib/bridge-client.ts"

/** Bridge and target status: is the server up, is Cheat Engine attached, what is the target. */
export default tool({
  description:
    "CE Testing bridge status. Call this first. Reports whether the bridge server is " +
    "running, whether Cheat Engine is connected, and the attached target process. " +
    "If there is no target, attach the game inside Cheat Engine and the target appears here.",
  args: {},
  async execute() {
    const status = await call("status")
    const lines: string[] = []
    lines.push(
      `Bridge up since ${status.bridge.started_at} (${Math.round(status.bridge.uptime_seconds)}s) at ${status.bridge.url ?? status.bridge.host + ":" + status.bridge.port}`,
    )

    const ce = status.cheat_engine ?? {}
    lines.push("")
    lines.push("Cheat Engine:")
    lines.push(`  connected agent : ${ce.agent_seen ? "yes" : "no"}`)
    lines.push(`  CE version      : ${ce.ce_version ?? "unknown"}`)
    lines.push(`  CE running      : ${ce.ce_running ? `yes (pid ${ce.ce_pid ?? "?"})` : "no"}`)
    lines.push(`  attached in CE  : ${ce.attached_pid ? `pid ${ce.attached_pid} ${ce.attached_name ?? ""}` : "nothing"}`)
    lines.push(`  agent installed : ${ce.agent_installed ? "yes" : "no (run ce_ce_install once as administrator)"}`)
    lines.push(`  address list    : ${ce.address_list_count ?? 0} entries`)
    if (ce.hint) lines.push(`  note            : ${ce.hint}`)

    lines.push("")
    lines.push("Target:")
    if (status.target) {
      const t = status.target
      lines.push(`  ${describeTarget(t)}`)
      lines.push(`  path            : ${t.path ?? "unknown"}`)
      lines.push(`  alive           : ${t.alive}`)
      lines.push(`  writes          : ${t.journal_entries} journaled, ${t.frozen} frozen, ${t.hooks} hooks`)
      if (t.active_scan) {
        lines.push(
          `  active scan     : ${t.active_scan.results} results, ${t.active_scan.value_type}, pass ${t.active_scan.pass}`,
        )
      }
    } else {
      lines.push("  none. Start the game, then attach to it in Cheat Engine.")
      if (status.next_step) lines.push(`  ${status.next_step}`)
    }

    if (status.events?.length) {
      lines.push("")
      lines.push("Recent events:")
      for (const e of status.events.slice(-6)) lines.push(`  ${e.at} ${e.event} ${e.pid ?? ""}`)
    }
    return lines.join("\n")
  },
})
