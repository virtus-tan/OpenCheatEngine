--[[
  CE Bridge agent for the Cheat Engine Lua engine.

  Cheat Engine's Lua has no socket library, so the transport is a set of files
  in %TEMP%\ce_bridge_spool that both sides poll:

    hello.txt   written once at startup: what this CE build supports
    status.txt  rewritten on every tick: which process is attached
    cmd.txt     written by the bridge: one command, id=N key=value lines
    res.txt     written here: the reply to that command

  The bridge never picks a process. It only reports the PID that a human
  attached to inside Cheat Engine, and mirrors findings back into the address
  list so they are visible in the GUI.
]]

local SPOOL_NAME = "ce_bridge_spool"
local TICK_MS = 300
local VER = "1.0"

local function tempdir()
  return os.getenv("TEMP") or os.getenv("TMP") or "C:\\Windows\\Temp"
end

local SPOOL = tempdir() .. "\\" .. SPOOL_NAME
local CMD = SPOOL .. "\\cmd.txt"
local RES = SPOOL .. "\\res.txt"
local STATUS = SPOOL .. "\\status.txt"
local HELLO = SPOOL .. "\\hello.txt"

local function log(message)
  pcall(function() print("[ce-bridge] " .. tostring(message)) end)
end

local function hexencode(text)
  return (tostring(text):gsub(".", function(char)
    return string.format("%02x", string.byte(char))
  end))
end

local function hexdecode(text)
  return (tostring(text):gsub("%x%x", function(pair)
    return string.char(tonumber(pair, 16))
  end))
end

local function escape(text)
  local out = tostring(text or "")
  out = out:gsub("\\", "\\\\")
  out = out:gsub('"', '\\"')
  out = out:gsub("\r", "\\r")
  out = out:gsub("\n", "\\n")
  out = out:gsub("\t", "\\t")
  return out
end

local function encode(value)
  local kind = type(value)
  if value == nil then
    return "null"
  elseif kind == "boolean" then
    return tostring(value)
  elseif kind == "number" then
    if value ~= value or value == math.huge or value == -math.huge then
      return "null"
    end
    if math.floor(value) == value and math.abs(value) < 1e15 then
      return string.format("%d", value)
    end
    return string.format("%.14g", value)
  elseif kind == "string" then
    return '"' .. escape(value) .. '"'
  elseif kind == "table" then
    if value.__json_scalar then
      return encode(value.__json_scalar)
    end
    local is_array = true
    local count = 0
    for key in pairs(value) do
      count = count + 1
      if type(key) ~= "number" then
        is_array = false
        break
      end
    end
    local parts = {}
    if is_array then
      for index = 1, count do
        parts[#parts + 1] = encode(value[index])
      end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local keys = {}
    for key in pairs(value) do
      keys[#keys + 1] = key
    end
    table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
    for _, key in ipairs(keys) do
      -- value[key], not value[tostring(key)]: Lua does not coerce a string
      -- back to a number, so a numeric key would come back nil.
      parts[#parts + 1] = '"' .. escape(tostring(key)) .. '":' .. encode(value[key])
    end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return "null"
end

local function writefile(path, content)
  local temp = path .. ".tmp"
  local handle = io.open(temp, "wb")
  if not handle then
    return false
  end
  handle:write(content)
  handle:close()
  os.remove(path)
  local ok = os.rename(temp, path)
  if not ok then
    os.remove(path)
    return false
  end
  return true
end

local function readfile(path)
  local handle = io.open(path, "rb")
  if not handle then
    return nil
  end
  local content = handle:read("*a")
  handle:close()
  return content
end

local function parsefields(text)
  local fields = {}
  for line in text:gmatch("[^\r\n]+") do
    local key, value = line:match("^([^=]+)=(.*)$")
    if key then
      fields[key] = value
    end
  end
  return fields
end

local function exists(path)
  local handle = io.open(path, "rb")
  if handle then
    handle:close()
    return true
  end
  return false
end

local TYPE_CONSTANTS = {
  i8 = "vtByte", u8 = "vtByte", bool = "vtByte",
  i16 = "vtWord", u16 = "vtWord", word = "vtWord",
  i32 = "vtDword", u32 = "vtDword", dword = "vtDword", int = "vtDword",
  i64 = "vtQword", u64 = "vtQword", qword = "vtQword",
  f32 = "vtFloat", f64 = "vtDouble", float = "vtFloat", double = "vtDouble",
  ptr = "vtPointer", pointer = "vtPointer",
  bytes = "vtBytes", string = "vtString",
}

local function valuetype(name)
  local key = tostring(name or "f32"):lower()
  local constant = TYPE_CONSTANTS[key]
  if constant == nil then
    return nil, "unknown value type " .. tostring(name)
  end
  local value = _G[constant]
  if value == nil then
    return nil, "this Cheat Engine build has no " .. constant
  end
  return value
end

local function trycall(fn, ...)
  if type(fn) ~= "function" then
    return nil, "function not available"
  end
  local results = { pcall(fn, ...) }
  if not results[1] then
    return nil, tostring(results[2])
  end
  return results
end

local function openedpid()
  local results = trycall(getOpenedProcessID)
  if not results then
    return -1
  end
  local pid = tonumber(results[2])
  if pid == nil or pid < 0 then
    return -1
  end
  return pid
end

local function processname(pid)
  if pid == nil or pid <= 0 then
    return nil
  end
  for _, name in ipairs({ "getProcessName", "processFromID" }) do
    local results = trycall(_G[name], pid)
    if results and results[2] then
      return tostring(results[2])
    end
  end
  -- Cheat Engine 7.4 has neither, so this normally comes back empty and the
  -- bridge fills the name in from Windows instead.
  local object = trycall(openProcess, pid)
  if object and object[2] then
    local named = trycall(function() return object[2].Name end)
    if named and named[2] then
      return tostring(named[2])
    end
  end
  return nil
end

local function targetarch()
  for _, name in ipairs({ "targetIs64bit", "is64bit", "is64bitprocess" }) do
    local results = trycall(_G[name])
    if results and results[2] ~= nil then
      if results[2] == true or results[2] == 1 then
        return "x64"
      end
      return "x86"
    end
  end
  -- Not exposed in 7.4; the bridge derives this from Windows anyway.
  return nil
end

local function addresslistcount()
  local results = trycall(function() return AddressList.Count end)
  if results and results[2] then
    return tonumber(results[2])
  end
  return nil
end

local function newrecord()
  -- Cheat Engine 7.4 exposes no global createMemoryRecord; the constructor
  -- lives on the address list, which is what CE's own scripts use.
  local results = trycall(function() return AddressList.createMemoryRecord() end)
  if results and results[2] then
    return results[2]
  end
  results = trycall(createMemoryRecord)
  if results and results[2] then
    return results[2]
  end
  return nil
end

local function addtolist(record)
  if not record then
    return false, "could not create a memory record"
  end
  local results = trycall(function() return AddressList.addItem(record) end)
  if results == nil then
    results = trycall(function()
      table.insert(AddressList, record)
      return true
    end)
  end
  if results == nil then
    return false, "could not add the record to the address list"
  end
  return true
end

local function resolve(expression)
  -- getSymbolAddress does not exist in 7.4, but getAddress resolves a
  -- registered symbol just as well.
  local results = trycall(getAddress, expression)
  if results and results[2] then
    return tonumber(results[2])
  end
  local safe = trycall(getAddressSafe, expression)
  if safe and safe[2] then
    local value = tonumber(safe[2])
    if value and value > 0 then
      return value
    end
  end
  return nil
end

local function listcount()
  return addresslistcount() or 0
end

-- Global rather than local, so the command table can be poked from Cheat
-- Engine's own Lua console when something misbehaves.
COMMANDS = {}

function COMMANDS.status()
  local pid = openedpid()
  return {
    pid = pid,
    name = processname(pid),
    arch = targetarch(),
    address_list_count = listcount(),
    ce_version = (trycall(getCEVersion) or { false, "?" })[2],
  }
end

function COMMANDS.caps()
  local names = {
    "getOpenedProcessID", "getProcessName", "getAddress", "getAddressSafe",
    "getCEVersion", "openProcess", "closeProcess", "createMemoryRecord",
    "registerSymbol", "unregisterSymbol", "getSymbolAddress",
    "autoAssemble", "disassemble", "showMessage", "processFromID",
    "targetIs64bit", "is64bit", "readBytes", "writeBytes", "executeCodeLocal",
  }
  local available = {}
  for _, name in ipairs(names) do
    if _G[name] ~= nil then
      available[#available + 1] = name
    end
  end
  local constants = {}
  for _, constant in ipairs({ "vtByte", "vtWord", "vtDword", "vtQword", "vtFloat",
                              "vtDouble", "vtSingle", "vtPointer", "vtBytes", "vtString" }) do
    if _G[constant] ~= nil then
      constants[#constants + 1] = constant
    end
  end
  return {
    version = VER,
    spool = SPOOL,
    functions = available,
    type_constants = constants,
    addresslist = _G.AddressList ~= nil,
  }
end

function COMMANDS.add_address(fields)
  local address = fields.address
  if not address or address == "" then
    return nil, "address is required"
  end
  local record = newrecord()
  if not record then
    return nil, "createMemoryRecord is not available"
  end
  local kind, kindError = valuetype(fields.type)
  if kind == nil then
    return nil, kindError
  end
  pcall(function() record.Type = kind end)
  pcall(function() record.Address = address end)
  if fields.name and fields.name ~= "" then
    pcall(function() record.Description = fields.name end)
  end
  if fields.comment and fields.comment ~= "" then
    pcall(function() record.Comment = fields.comment end)
  end
  local ok, errorMessage = addtolist(record)
  if not ok then
    return nil, errorMessage
  end
  if fields.value and fields.value ~= "" then
    pcall(function() record.Value = tonumber(fields.value) end)
  end
  local resolved = nil
  pcall(function() resolved = getAddress(record.Address) end)
  return {
    address = fields.address,
    resolved = resolved and string.format("0x%X", resolved) or nil,
    name = fields.name,
    type = fields.type,
    address_list_count = listcount(),
  }
end

function COMMANDS.set_value(fields)
  local record = nil
  local results = trycall(function() return AddressList[tonumber(fields.index or 0)] end)
  if results and results[2] then
    record = results[2]
  end
  if not record then
    return nil, "no record at index " .. tostring(fields.index)
  end
  local applied = trycall(function()
    record.Value = tonumber(fields.value)
    return true
  end)
  if applied == nil then
    return nil, "could not set the value"
  end
  return { index = tonumber(fields.index or 0), value = tonumber(fields.value) }
end

function COMMANDS.set_comment(fields)
  local index = tonumber(fields.index or 0)
  local results = trycall(function() return AddressList[index] end)
  if not results or not results[2] then
    return nil, "no record at index " .. tostring(index)
  end
  trycall(function()
    results[2].Comment = fields.comment or ""
    return true
  end)
  return { index = index, comment = fields.comment }
end

function COMMANDS.list_addresses()
  local count = listcount()
  local items = {}
  for index = 0, count - 1 do
    local entry = trycall(function() return AddressList[index] end)
    if entry and entry[2] then
      local record = entry[2]
      local address, description, value, header
      pcall(function() address = tostring(record.Address) end)
      pcall(function() description = record.Description end)
      pcall(function() value = tostring(record.Value) end)
      pcall(function() header = record.IsAddressGroupHeader end)
      items[#items + 1] = {
        index = index,
        address = address,
        name = description,
        value = value,
        is_header = header and true or false,
      }
    end
  end
  return { count = count, items = items }
end

function COMMANDS.register_symbol(fields)
  if not fields.name or fields.name == "" then
    return nil, "name is required"
  end
  if not fields.address or fields.address == "" then
    return nil, "address is required"
  end
  local results = trycall(registerSymbol, fields.name, fields.address, true)
  if results == nil then
    return nil, "registerSymbol is not available"
  end
  local resolved = resolve(fields.name)
  return {
    name = fields.name,
    address = fields.address,
    resolved = resolved and string.format("0x%X", resolved) or nil,
  }
end

function COMMANDS.unregister_symbol(fields)
  local results = trycall(unregisterSymbol, fields.name)
  if results == nil then
    return nil, "unregisterSymbol is not available"
  end
  return { name = fields.name }
end

function COMMANDS.resolve(fields)
  local expression = fields.expression or fields.address
  if not expression or expression == "" then
    return nil, "expression is required"
  end
  local resolved = resolve(expression)
  if resolved == nil then
    return nil, "could not resolve " .. tostring(expression)
  end
  return { expression = expression, address = string.format("0x%X", resolved) }
end

function COMMANDS.disassemble(fields)
  local address = fields.address
  if not address or address == "" then
    return nil, "address is required"
  end
  local count = tonumber(fields.count or 12)
  local text = nil
  -- Some Cheat Engine builds take only the address, so fall back to that.
  local results = trycall(disassemble, address, count)
  if results and results[2] then
    text = tostring(results[2])
  else
    results = trycall(disassemble, address)
    if results and results[2] then
      text = tostring(results[2])
    end
  end
  if text == nil or text == "" then
    return nil, "disassemble produced nothing for " .. tostring(address)
  end
  return { address = address, count = count, text = text }
end

function COMMANDS.autoassemble(fields)
  local script = fields.script
  if not script or script == "" then
    return nil, "script is required"
  end
  local results = trycall(autoAssemble, script)
  if results == nil then
    return nil, "autoAssemble is not available"
  end
  local report = results[2]
  local ok = false
  local message = nil
  if type(report) == "table" then
    ok = report.success and true or false
    message = report.error
  elseif report == true then
    ok = true
  end
  return { success = ok, error = message }
end

function COMMANDS.show_message(fields)
  local text = fields.text or ""
  trycall(showMessage, text)
  return { shown = text }
end

function COMMANDS.open_process(fields)
  local pid = tonumber(fields.pid)
  if pid == nil then
    return nil, "pid is required"
  end
  local results = trycall(openProcess, pid)
  if results == nil then
    return nil, "openProcess is not available"
  end
  return { pid = pid, opened = openedpid() }
end

function COMMANDS.close_process()
  local results = trycall(closeProcess)
  return { closed = results ~= nil }
end

local function handle(fields)
  local name = fields.command
  if not name or name == "" then
    return nil, "no command"
  end
  local handler = COMMANDS[name]
  if handler == nil then
    return nil, "unknown command: " .. tostring(name)
  end
  local ok, result, errorMessage = pcall(handler, fields)
  if not ok then
    return nil, tostring(result)
  end
  if errorMessage then
    return nil, tostring(errorMessage)
  end
  return result or {}
end

local function tick()
  if exists(CMD) then
    local content = readfile(CMD)
    os.remove(CMD)
    if content and content ~= "" then
      local fields = parsefields(content)
      local id = fields.id or "0"
      local ok, result = handle(fields)
      local payload = {
        "id=" .. tostring(id),
        "ok=" .. (ok and "1" or "0"),
      }
      if ok then
        payload[#payload + 1] = "json=" .. hexencode(encode(result))
      else
        payload[#payload + 1] = "error=" .. tostring(result)
      end
      writefile(RES, table.concat(payload, "\n") .. "\n")
    end
  end

  local report = COMMANDS.status()
  writefile(STATUS, "json=" .. hexencode(encode(report)) .. "\n")
end

local function announce()
  local report = COMMANDS.caps()
  report.pid = openedpid()
  report.ce_version = (trycall(getCEVersion) or { false, "?" })[2]
  writefile(HELLO, "json=" .. hexencode(encode(report)) .. "\n")
  log("agent ready, spool " .. SPOOL)
end
announce()

-- The pure helpers, exposed so they can be exercised by tests and poked at
-- from Cheat Engine's Lua console. Nothing in here touches the target.
CE_BRIDGE_DEBUG = {
  parsefields = parsefields,
  encode = encode,
  hexencode = hexencode,
  hexdecode = hexdecode,
  writefile = writefile,
  readfile = readfile,
  exists = exists,
  SPOOL = SPOOL,
  CMD = CMD,
  RES = RES,
  STATUS = STATUS,
  HELLO = HELLO,
  handle = handle,
  tick = tick,
}


local timer = createTimer(nil)
if timer then
  timer.Interval = TICK_MS
  timer.OnTimer = function()
    pcall(tick)
  end
else
  log("createTimer is unavailable, the agent cannot run")
end

local mainform = _G.MainForm
if mainform and mainform.OnClose then
  local previous = mainform.OnClose
  mainform.OnClose = function(sender, args)
    pcall(function() if timer then timer.destroy() end end)
    pcall(function() os.remove(CMD) end)
    pcall(function() os.remove(RES) end)
    pcall(function() os.remove(HELLO) end)
    if previous then
      return previous(sender, args)
    end
    return args
  end
end
