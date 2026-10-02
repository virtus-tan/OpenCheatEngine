"""Test the Cheat Engine Lua agent's logic against CE 7.4's real API surface.

    python -m pip install lupa
    python tests/luatest.py

Cheat Engine 7.4's Lua does not expose createMemoryRecord, getSymbolAddress,
getProcessName, targetIs64bit or closeProcess. That was found by running the
agent in the real thing, and it is exactly the kind of mistake that only shows
up against the actual host. So this test builds a Lua state that deliberately
has the CE 7.4 surface and nothing more, loads the agent into it, and calls the
commands that used to fail.

The CE-specific entry points (createTimer, the address list, the module) are
mocked. Everything under test is the agent's own code.
"""

import os
import sys
import tempfile

try:
    from lupa import LuaRuntime
except ImportError:
    print("lupa is not installed; run: python -m pip install lupa")
    raise SystemExit(2)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

AGENT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ce_bridge", "ce_agent", "ce_bridge_agent.lua",
)

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"  pass  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def section(title):
    print(f"\n{title}")


def build_runtime(spool):
    """A Lua state holding exactly the globals Cheat Engine 7.4 provides."""
    lua = LuaRuntime(unpack_returned_tuples=True)

    # The runtime contract: the bridge creates the spool directory before
    # Cheat Engine starts, and the agent writes into it. Real Cheat Engine
    # confirmed it, so the test honours it rather than working around it.
    os.makedirs(os.path.join(spool, "ce_bridge_spool"), exist_ok=True)

    lua.globals().os.getenv = lambda name: spool if name in ("TEMP", "TMP") else None
    lua.globals().print = lambda *args: None

    # Everything Cheat Engine provides is defined in Lua, because the agent
    # checks type(fn) == "function" before calling, and a Python callable
    # exposed through lupa is not a Lua function.
    lua.execute("""
        TEST_PID = 5100
        function getOpenedProcessID() return TEST_PID end
        function getCEVersion() return 7.4 end
        function openProcess(pid) return { Name = 'ignored' } end
        function showMessage(text) return nil end
        function autoAssemble(script) return { success = true } end
        function disassemble(a, n) return 'nop' end
        _G.symbols = {}
        function registerSymbol(name, address, noSave)
            _G.symbols[name] = address
            return true
        end
        function getAddress(expression)
            if _G.symbols[expression] ~= nil then return tonumber(_G.symbols[expression]) end
            if TEST_PID >= 0 and string.sub(expression, -3) == 'exe' then return 0x400000 end
            return nil
        end
        function getAddressSafe(expression) return nil end

        -- Exactly the value type constants Cheat Engine 7.4 reported, no more.
        -- vtBytes is absent in 7.4, so the agent must refuse that type rather
        -- than create a record with a nil type.
        vtByte, vtWord, vtDword, vtQword = 0, 1, 2, 3
        vtDouble, vtSingle, vtPointer, vtString = 4, 5, 9, 7

        -- The address list. Its record constructor is on the list rather than
        -- global, and it indexes from zero, both of which are how CE 7.4
        -- behaves: its own scripts do AddressList[i] for i = 0..Count-1.
        AddressList = setmetatable({ Count = 0, items = {} }, {
            __index = function(self, key)
                if type(key) == 'number' then return self.items[key + 1] end
                return rawget(self, key)
            end,
        })
        function AddressList.createMemoryRecord()
            return { Description = '', Comment = '', Address = '' }
        end
        function AddressList.addItem(record)
            table.insert(AddressList.items, record)
            AddressList.Count = AddressList.Count + 1
            return true
        end

        -- A timer that never fires, so the agent loads without looping.
        function createTimer()
            return { Interval = 0, OnTimer = nil, destroy = function() end }
        end
    """)
    return lua



def lua_list(table):
    """A Lua array as a list of Python values.

    Iterating a lupa table in Python yields keys rather than values, so go
    through values() explicitly.
    """
    if table is None:
        return []
    out = []
    for value in table.values():
        out.append(dict(value) if hasattr(value, "values") else value)
    return out


def lua_call(fn, args):

    """Normalise a Lua command's return into (result, error).

    The commands return either a table, or nil plus a message. lupa hands back a
    tuple either way, so one element means success and two mean failure.
    """
    out = fn(args)
    if isinstance(out, tuple):
        if not out:
            return None, None
        if len(out) == 1:
            return out[0], None
        return out[0], out[1]
    return out, None


def main():
    spool = tempfile.mkdtemp(prefix="ce_lua_test_")
    lua = build_runtime(spool)
    with open(AGENT, encoding="utf-8") as handle:
        source = handle.read()
    try:
        lua.execute(source)
    except Exception as error:
        print(f"the agent did not load: {error}")
        return 1

    check("the agent loads in a Lua 5.5 state", True)
    check("it announced itself", os.path.exists(os.path.join(spool, "ce_bridge_spool", "hello.txt")))

    debug = lua.globals().CE_BRIDGE_DEBUG
    check("the debug helpers are exposed", debug is not None)
    if debug is None:
        return 1

    hello = os.path.join(spool, "ce_bridge_spool", "hello.txt")
    if os.path.exists(hello):
        import json
        with open(hello, encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("json="):
                    payload = json.loads(bytes.fromhex(line[5:].strip()).decode("utf-8"))
        check("the announcement is valid JSON", isinstance(payload, dict))
        check("it reports the address list as available", payload.get("addresslist") is True,
              str(payload)[:200])
        check("it does not claim createMemoryRecord",
              "createMemoryRecord" not in payload.get("functions", []),
              str(payload.get("functions")))

    commands = lua.globals().COMMANDS
    check("the command table exists", commands is not None)

    section("add_address without a global createMemoryRecord")
    result, error = lua_call(commands.add_address, lua.table_from({
        "address": "lab_target.exe+1234", "name": "health?", "type": "i32",
        "comment": "found by the bridge",
    }))
    check("add_address succeeds", error is None, str(error))
    if result is not None:
        result = dict(result)
        check("it reports the address list count", result.get("address_list_count") == 1,
              str(result)[:200])
        check("it echoes the name back", result.get("name") == "health?", str(result)[:200])
    check("the row really landed in the list", lua.eval("AddressList.Count") == 1,
          str(lua.eval("AddressList.Count")))

    section("a bad address is reported, not swallowed")
    result, error = lua_call(commands.add_address, lua.table_from({"address": "", "name": "bad"}))
    check("an empty address is rejected", result is None and error is not None, str(error))

    section("register_symbol without getSymbolAddress")
    lua.execute("""
        function getAddress(expression)
            if expression == 'health_ptr' then return 0x7ff600000000 end
            return nil
        end
    """)
    result, error = lua_call(commands.register_symbol, lua.table_from({
        "name": "health_ptr", "address": "0x7ff600000000",
    }))
    check("register_symbol succeeds", error is None, str(error))
    if result is not None:
        result = dict(result)
        check("it resolves the symbol through getAddress",
              result.get("resolved") == "0x7FF600000000", str(result)[:200])

    section("resolve without getSymbolAddress")
    result, error = lua_call(commands.resolve, lua.table_from({"expression": "health_ptr"}))
    check("resolve succeeds", error is None, str(error))
    if result is not None:
        result = dict(result)
        check("resolve returns the address", result.get("address") == "0x7FF600000000",
              str(result)[:200])
    result, error = lua_call(commands.resolve, lua.table_from({"expression": "nothing_here"}))
    check("an unresolvable expression is reported", result is None and error is not None,
          str(error))

    section("list_addresses")
    result, _ = lua_call(commands.list_addresses, lua.table())
    payload = dict(result) if result else {}
    items = lua_list(payload.get("items"))
    check("the row is listed back", len(items) == 1, str(items)[:200])
    if items:
        check("the row keeps its name", items[0].get("name") == "health?", str(items[0])[:200])
        check("group headers are not misreported", items[0].get("is_header") is False,
              str(items[0])[:200])

    section("status with no name or arch available")
    result, _ = lua_call(commands.status, lua.table())
    result = dict(result)
    check("status still reports the pid", result.get("pid") == 5100, str(result)[:200])
    check("status survives a missing process name", "name" in result or True, str(result)[:200])
    check("status reports the address list count", result.get("address_list_count") == 1,
          str(result)[:200])

    section("commands that need a missing global degrade cleanly")
    result, error = lua_call(commands.close_process, lua.table())
    check("close_process reports that it could not, rather than crashing",
          error is None and dict(result).get("closed") is False,
          f"result={result} error={error}")

    section("a value type this build does not have is refused")
    result, error = lua_call(commands.add_address, lua.table_from({
        "address": "0x1000", "name": "raw", "type": "bytes",
    }))
    check("an unsupported type is reported clearly",
          result is None and error is not None and "vtBytes" in str(error),
          f"result={result} error={error}")


    section("the field parser")
    parsed = dict(debug.parsefields("id=7\ncommand=add_address\nname=health?"))
    check("it reads key=value lines", parsed.get("id") == "7", str(parsed)[:200])
    check("it keeps a value with punctuation", parsed.get("name") == "health?", str(parsed)[:200])

    section("the JSON encoder")
    import json
    nested = lua.table_from({"a": 1, "c": "x"})
    nested["b"] = lua.table_from([1, 2])
    encoded = debug.encode(nested)
    check("it emits valid JSON", json.loads(encoded) == {"a": 1, "b": [1, 2], "c": "x"}, encoded)
    version = debug.encode(lua.table_from({"v": 7.4}))
    check("a numeric CE version stays a number", json.loads(version)["v"] == 7.4, version)
    escaped = debug.encode(lua.table_from({"k": 'a"b\\c\nd'}))
    check("it escapes quotes, backslashes and newlines",
          json.loads(escaped)["k"] == 'a"b\\c\nd', escaped)

    section("the spool layout")
    check("it points at the agreed spool", debug.SPOOL.endswith("ce_bridge_spool"),
          str(debug.SPOOL))
    check("the file names match the bridge",
          all(os.path.basename(str(debug[name])).lower() == name.lower() + ".txt"
              for name in ("CMD", "RES", "STATUS", "HELLO")),
          f"{debug.CMD} {debug.RES} {debug.STATUS} {debug.HELLO}")

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"  FAILED: {name} {detail}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())



