import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/**
 * The scan flow, in the order you actually use it:
 *   ce_scan phase=start, unknown initial
 *   ...play, take damage...
 *   ce_scan phase=next, changed
 *   ...take damage again...
 *   ce_scan phase=next, decreased
 */

const SCAN_TYPES = "exact, unknown_initial, changed, unchanged, increased, decreased, fuzzy"

/** Scan the target's memory, in passes that narrow a candidate set. */
export default tool({
  description:
    "Scan the target's memory. phase=start begins a new search, phase=next narrows the " +
    "current one. The usual flow: put the game in the state you want to search for, then " +
    "start with scan_type=unknown_initial; after the value changes use changed; after it " +
    "changes again use increased or decreased; then pin it with exact and the value you " +
    "now know. Returns the running result count after every pass. Note the alignment: " +
    "most game values are 4-byte aligned, and setting alignment=4 makes a scan several " +
    "times faster and the results far cleaner.",
  args: {
    phase: tool.schema
      .enum(["start", "next"])
      .optional()
      .describe("start a new search, or narrow the current one"),
    scan_type: tool.schema
      .enum([
        "exact",
        "unknown_initial",
        "changed",
        "unchanged",
        "increased",
        "decreased",
        "fuzzy",
      ])
      .optional()
      .describe(`how to filter, default unknown_initial. one of: ${SCAN_TYPES}`),
    value: tool.schema
      .string()
      .optional()
      .describe("the value to look for, needed for exact and fuzzy"),
    type: tool.schema
      .string()
      .optional()
      .describe("value type: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 ptr bytes array"),
    alignment: tool.schema
      .number()
      .optional()
      .describe("only consider addresses on this boundary; 4 for aligned ints"),
    module: tool.schema
      .string()
      .optional()
      .describe("restrict the search to one module, which is much faster"),
    region_type: tool.schema
      .enum(["IMAGE", "PRIVATE", "MAPPED"])
      .optional()
      .describe("restrict to one kind of region"),
    writable_only: tool.schema
      .boolean()
      .optional()
      .describe("skip read-only regions, on by default"),
    executable_only: tool.schema.boolean().optional().describe("only executable regions"),
    max_results: tool.schema
      .number()
      .optional()
      .describe("cap on how many candidates to keep, default 4000000"),
    struct: tool.schema
      .string()
      .optional()
      .describe('for type=array, the struct layout, e.g. "int32 hp; float mp"'),
    values: tool.schema
      .record(tool.schema.string(), tool.schema.any())
      .optional()
      .describe("for type=array, the field values to match"),
    tolerance: tool.schema
      .number()
      .optional()
      .describe("relative tolerance for scan_type=fuzzy"),
  },
  async execute(args) {
    if ((args.phase ?? "next") === "start") {
      const result = await call("scan_start", {
        type: args.type ?? "u32",
        scan_type: args.scan_type ?? "unknown_initial",
        value: args.value,
        alignment: args.alignment ?? 1,
        module: args.module,
        region_type: args.region_type,
        writable_only: args.writable_only ?? true,
        executable_only: args.executable_only ?? false,
        max_results: args.max_results ?? 4000000,
        struct: args.struct,
        values: args.values,
        tolerance: args.tolerance ?? 0,
      })
      return (
        `Started: ${result.results} candidates (${result.value_type}, ${result.regions_scanned} regions, ` +
        `${result.scanned_bytes} bytes scanned).` +
        (result.truncated ? " Hit max_results, so the set is incomplete." : "") +
        `\nNow change the value in the game, then call ce_scan with phase=next scan_type=changed.`
      )
    }
    const result = await call("scan_next", {
      scan_type: args.scan_type ?? "changed",
      value: args.value,
      tolerance: args.tolerance ?? 0,
    })
    const history = result.history
      .map(
        (h: any) =>
          `  pass ${h.pass}: ${h.scan_type}` +
          `${h.value !== null && h.value !== undefined ? " " + h.value : ""} -> ${h.results}`,
      )
      .join("\n")
    return `Narrowed to ${result.results} result(s).\n${history}\n\nCall ce_scan_results to see them.`
  },
})
