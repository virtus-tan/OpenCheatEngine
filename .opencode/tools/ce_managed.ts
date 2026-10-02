import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Query the live managed runtime. */
export default tool({
  description:
    "Query the live managed runtime of the target: the loaded assemblies, the types in " +
    "one, the fields or methods of a type, a static field's current value, or the runtime " +
    "functions this build exports. For IL2CPP you also get each instance field's offset, " +
    "which turns a field name into a concrete address. Run ce_runtime first to see which " +
    "of these the target supports.",
  args: {
    action: tool.schema
      .enum(["assemblies", "types", "fields", "methods", "static", "exports"])
      .describe("which managed query to run"),
    assembly: tool.schema.string().optional().describe("assembly name, e.g. Assembly-CSharp"),
    type: tool.schema.string().optional().describe("full type name, e.g. Game.Player"),
    field: tool.schema.string().optional().describe("field name, for action=static"),
    filter: tool.schema.string().optional().describe("regex to filter type names"),
    pattern: tool.schema
      .string()
      .optional()
      .describe("substring to filter runtime exports, for action=exports"),
    value_type: tool.schema
      .string()
      .optional()
      .describe("how to read a static value: i32 f32 f64 ... (default f32)"),
    limit: tool.schema.number().optional().describe("how many rows"),
  },
  async execute(args) {
    switch (args.action) {
      case "assemblies": {
        const r = await call("managed_assemblies", {})
        return (
          `${r.count} assembly(s) loaded:\n` +
          r.assemblies.map((a: any) => `  ${a.name}  image ${a.image}`).join("\n")
        )
      }
      case "types": {
        if (!args.assembly) throw new Error("action=types needs an assembly name")
        const r = await call("managed_types", {
          assembly: args.assembly,
          filter: args.filter ?? "",
          limit: args.limit ?? 2000,
        })
        return (
          `${r.count} type(s) in ${args.assembly}:\n` +
          r.types.map((t: any) => `  ${t.full_name}  (${t.class})`).join("\n")
        )
      }
      case "fields": {
        if (!args.assembly || !args.type) throw new Error("action=fields needs assembly and type")
        const r = await call("managed_fields", { assembly: args.assembly, type: args.type })
        return (
          `${r.count} field(s) on ${args.type}:\n` +
          r.fields
            .map(
              (f: any) =>
                `  ${f.name.padEnd(28)} ${f.static ? "static " : "instance"}` +
                (f.offset ? `  offset ${f.offset}` : "            ") +
                `  ${f.field}`,
            )
            .join("\n")
        )
      }
      case "methods": {
        if (!args.assembly || !args.type) throw new Error("action=methods needs assembly and type")
        const r = await call("managed_methods", { assembly: args.assembly, type: args.type })
        return (
          `${r.count} method(s) on ${args.type}:\n` +
          r.methods
            .map(
              (m: any) =>
                `  ${m.name.padEnd(34)} ${m.parameters ?? "?"} parameter(s)  ${m.method}`,
            )
            .join("\n")
        )
      }
      case "static": {
        if (!args.assembly || !args.type || !args.field) {
          throw new Error("action=static needs assembly, type and field")
        }
        const r = await call("managed_static", {
          assembly: args.assembly,
          type: args.type,
          field: args.field,
          value_type: args.value_type ?? "f32",
        })
        return `${args.type}.${args.field} (${r.value_type}) = ${r.value}  raw ${r.raw}`
      }
      case "exports": {
        const r = await call("runtime_exports", { pattern: args.pattern ?? "", limit: 200 })
        return (
          `${r.count} export(s) matching ${args.pattern || "*"}:\n` +
          r.exports.map((e: any) => `  ${e.name.padEnd(48)} ${e.address}`).join("\n")
        )
      }
    }
  },
})
