import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** List what is in Cheat Engine's address list. */
export default tool({
  description:
    "List the rows currently in Cheat Engine's address list, which is what the human " +
    "sees in the window. Use it to confirm a ce_ce_mirror landed.",
  args: {},
  async execute() {
    const r = await call("ce_addresses", {})
    if (!r.count) return "The Cheat Engine address list is empty."
    return (
      `${r.count} row(s):\n` +
      r.items
        .filter((i: any) => !i.is_header)
        .map(
          (i: any) =>
            `  ${String(i.index).padStart(3)}  ${(i.address ?? "").padEnd(24)} ` +
            `${(i.name ?? "").padEnd(24)} ${i.value ?? ""}`,
        )
        .join("\n")
    )
  },
})
