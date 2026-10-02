import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Read raw bytes at an address as a hex dump. */
export default tool({
  description:
    "Read raw bytes at an address and get a hex dump. Use this when a value is part of a " +
    "struct, a byte array, machine code, or anything the typed reader cannot interpret. " +
    "The dump prints ASCII alongside the hex, which is how you spot text in a buffer.",
  args: {
    address: tool.schema.string().describe("absolute address as hex"),
    size: tool.schema.number().optional().describe("how many bytes, default 64"),
  },
  async execute(args) {
    const result = await call("read_bytes", {
      address: args.address,
      size: args.size ?? 64,
      dump: true,
    })
    return `${result.address}  ${result.size} bytes\nhex: ${result.hex}\n\n${result.dump ?? ""}`
  },
})
