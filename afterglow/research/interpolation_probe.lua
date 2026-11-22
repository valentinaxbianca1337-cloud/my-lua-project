-- Read-only Source 1 / GameSense networking snapshot.
-- No FFI, native patches, cvar setters, or user-command changes.
-- Load once, then use ag_interp_audit or ag_interp_help in the console.
local names = {
    "cl_interp", "cl_interp_ratio", "cl_updaterate", "cl_interpolate",
    "cl_extrapolate", "cl_extrapolate_amount",
    "sv_client_min_interp_ratio", "sv_client_max_interp_ratio",
    "sv_minupdaterate", "sv_maxupdaterate",
    "cl_lagcompensation", "sv_unlag", "sv_maxunlag",
    "cl_cmdrate", "rate", "sv_mincmdrate", "sv_maxcmdrate",
    "sv_minrate", "sv_maxrate",
    "cl_predict", "cl_predictweapons", "cl_pred_optimize",
    "cl_smooth", "cl_smoothtime", "cl_interp_all", "cl_interp_npcs",
    "cl_interp_threadmodeticks", "cl_interp_animationvars",
    "sv_clockcorrection_msecs", "sv_maxusrcmdprocessticks",
    "sv_lagcompensation_teleport_dist", "sv_unlag_fixstuck",
    "sv_lagflushbonecache", "cl_showerror", "net_graph",
    "sv_showlagcompensation"
}

local function safe(fn)
    local ok, value = pcall(fn)
    if ok then return value end
    return nil
end

local function printable(value)
    if value == nil then return "unavailable" end
    return (tostring(value):gsub("[\r\n]", " "))
end

local function dump()
    local lines, values = {}, {}
    local function add(line) lines[#lines + 1] = line end
    add("Afterglow: read-only interpolation/network audit")
    add("Snapshot values are not factory defaults or private GameSense state.")
    add("Some optional Source-branch cvars may be unavailable in this build.")
    add("map=" .. printable(safe(function() return globals.mapname() end)))
    add("tickinterval=" .. printable(safe(function() return globals.tickinterval() end)))
    add("client.latency=" .. printable(safe(function() return client.latency() end)))
    for i = 1, #names do
        local name = names[i]
        local ref = safe(function() return cvar[name] end)
        local number, raw
        if ref ~= nil then
            number = safe(function() return ref:get_float() end)
            raw = safe(function() return ref:get_string() end)
        end
        if type(number) == "number" and number == number
            and number ~= math.huge and number ~= -math.huge then
            values[name] = number
        end
        add(name .. " | get_float=" .. printable(number) .. " | get_string=" .. printable(raw))
    end
    local rate_value, ratio, interp = values.cl_updaterate, values.cl_interp_ratio, values.cl_interp
    if rate_value and rate_value > 0 and ratio and ratio >= 0 and interp and interp >= 0 then
        add("Reference max(interp, ratio/updaterate)=" .. printable(math.max(interp, ratio / rate_value)))
        add("Reference value only: getter/server bounds and private GameSense paths require separate verification.")
    else
        add("Reference lerp unavailable: missing or invalid input values.")
    end
    add("Use ag_interp_help for engine help/current/default/flags where supported.")
    local report = table.concat(lines, "\n") .. "\n"
    for i = 1, #lines do client.log(lines[i]) end
    if type(writefile) == "function" then
        local ok, result = pcall(writefile, "afterglow_interpolation_audit.txt", report)
        if ok and result ~= false then
            client.log("Saved afterglow_interpolation_audit.txt")
        else
            client.log("Could not save audit; values remain in the console.")
        end
    end
end

local function help()
    client.log("Querying engine help only; no cvar values are changed.")
    for i = 1, #names do client.exec("help " .. names[i]) end
end

local function on_console_input(text)
    if type(text) ~= "string" then return end
    local command = text:match("^%s*(.-)%s*$")
    if command == "ag_interp_audit" then dump(); return true end
    if command == "ag_interp_help" then help(); return true end
end

client.set_event_callback("console_input", on_console_input)
dump()
