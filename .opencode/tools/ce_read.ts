import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

const TYPES = "i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 ptr bool bytes string"

/** Read a typed value, and learn which region and module it lives in. */
export default tool({
  description:
    "Read a value from the attached process. Give an absolute address (0x7ff6...), or a " +
    "module name plus an offset, which survives restarting the game. The reply also says " +
    "which region the address is in and which module owns it, which is how you find out " +
    "where a value actually came from. Use ce_read_bytes when the value is part of a " +
    "struct or a byte array.",
  args: {
    address: tool.schema
      .string()
      .optional()
      .describe("absolute address as hex, e.g. 0x7ff6237f9000"),
    module: tool.schema
      .string()
      .optional()
      .describe("module name to resolve the base from, e.g. game.exe"),
    offset: tool.schema
      .string()
      .optional()
      .describe("offset from the module base as hex, e.g. 0x94000"),
    type: tool.schema
      .string()
      .optional()
      .describe(`value type: ${TYPES} (default u32)`),
    count: tool.schema
      .number()
      .optional()
      .describe("how many values to read when the type has a fixed size"),
  },
  async execute(args) {
    const result = await call("read", {
      address: args.address,
      module: args.module,
      offset: args.offset,
      type: args.type ?? "u32",
      count: args.count ?? 1,
    })
    const region = result.region
    const lines = [`${result.address}  (${result.type})  =  ${JSON.stringify(result.value)}`]
    if (region) {
      lines.push(
        `  region ${region.base} +${region.size} ${region.state} ${region.protect} ${region.type}`,
      )
      if (region.module) {
        lines.push(
          `  module ${region.module}+${region.module_offset ?? "?"}` +
            `${region.section ? `  section ${region.section}` : ""}`,
        )
      }
      if (region.offset !== undefined) lines.push(`  offset in section ${region.offset}`)
    }
    return lines.join("\n")
  },
})
