import { tool } from "@opencode-ai/plugin"
import { call } from "../lib/bridge-client.ts"

/** Run raw machine code in the target. */
export default tool({
  description:
    "Write raw machine code into the target and run it on a new thread, returning the " +
    "thread exit code. Use it for a handful of instructions, not for anything " +
    "substantial: there is no error reporting beyond the exit code. Needs ce_unlock, " +
    "and is x64 only.",
  args: {
    code: tool.schema.string().describe('bytes as hex, e.g. "31 C0 C3" for xor eax,eax; ret'),
  },
  async execute(args) {
    const r = await call("exec_shellcode", { code: args.code })
    return `Ran ${r.bytes} byte(s) of shellcode; thread exit code 0x${r.thread_exit_code.toString(16)}.`
  },
})
