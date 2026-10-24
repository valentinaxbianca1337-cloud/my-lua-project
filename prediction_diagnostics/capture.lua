-- GameSense legacy CS:GO: opt-in, read-only prediction diagnostics.
-- This records observations. It does not change aiming, entities, commands or cvars.
local SAMPLE_LIMIT, EVENT_LIMIT = 8192, 512
local OUTPUT = "skeet_prediction_trace.json"
local json_api = rawget(_G, "json") or require("json")
local enabled = ui.new_checkbox("LUA", "B", "Record prediction diagnostics")
local samples, events, latest, epochs, pending
local sequence, duplicates, invalid_samples, started
local cvar_names = {"cl_interp", "cl_interp_ratio", "cl_updaterate", "sv_minupdaterate",
    "sv_maxupdaterate", "sv_client_min_interp_ratio", "sv_client_max_interp_ratio",
    "sv_maxunlag", "sv_gravity"}

local function finite(value)
    return type(value) == "number" and value == value and value > -math.huge and value < math.huge
end
local function number_call(fn, ...)
    if type(fn) ~= "function" then return nil end
    local ok, value = pcall(fn, ...)
    if ok and finite(value) then return value end
end
local function clock(name)
    return number_call(globals[name])
end
local function ring(capacity)
    return {data = {}, head = 0, size = 0, capacity = capacity, dropped = 0}
end
local function push(buffer, value)
    buffer.head = buffer.head % buffer.capacity + 1
    local evicted = buffer.data[buffer.head]
    buffer.data[buffer.head] = value
    if buffer.size < buffer.capacity then buffer.size = buffer.size + 1
    else buffer.dropped = buffer.dropped + 1 end
    return evicted
end
local function ordered(buffer)
    local out = {}
    for i = 1, buffer.size do
        local index = (buffer.head - buffer.size + i - 1) % buffer.capacity + 1
        out[i] = buffer.data[index]
    end
    return out
end
local function reset()
    samples, events = ring(SAMPLE_LIMIT), ring(EVENT_LIMIT)
    latest, epochs, pending = {}, {}, {}
    sequence, duplicates, invalid_samples = 0, 0, 0
    started = clock("realtime")
end
local function next_sequence()
    sequence = sequence + 1
    return sequence
end
local function cvars()
    local out = {}
    for _, name in ipairs(cvar_names) do
        local var = cvar and cvar[name]
        if var then
            local ok, value = pcall(function() return var:get_float() end)
            if ok and finite(value) then out[name] = value end
        end
    end
    return out
end
local function context()
    return {receive_time = clock("realtime"), local_curtime = clock("curtime"),
        local_tick = clock("tickcount"), tick_interval = clock("tickinterval"),
        reported_latency = number_call(client.latency)}
end
local function prop(index, name)
    return number_call(entity.get_prop, index, name)
end
local function vector_prop(index, name)
    local ok, x, y, z = pcall(entity.get_prop, index, name)
    if ok and finite(x) and finite(y) and finite(z) then return {x, y, z} end
end
local function bool_call(fn, index)
    local ok, value = pcall(fn, index)
    if ok and type(value) == "boolean" then return value end
end
local function emit(kind, data)
    data = data or {}
    data.kind = kind
    data.sequence = next_sequence()
    data.context = context()
    local evicted = push(events, data)
    if evicted and evicted.kind == "aim_fire" and evicted.native.id ~= nil and
        pending[evicted.native.id] == evicted.sequence then pending[evicted.native.id] = nil end
    return data
end
local function advance_epoch(index)
    epochs[index] = (epochs[index] or 0) + 1
    latest[index] = nil
end
local function sample(index, frame)
    local alive = bool_call(entity.is_alive, index)
    local dormant = bool_call(entity.is_dormant, index)
    local old = latest[index]
    local active = alive == true and dormant == false
    if not active then
        if old and old.active then
            local record = {sequence = next_sequence(), entity = index,
                generation = epochs[index], active = false, alive = alive, dormant = dormant,
                receive_time = frame.receive_time, local_tick = frame.local_tick,
                tick_interval = frame.tick_interval}
            push(samples, record)
            latest[index] = record
        end
        return
    end
    local simulation_time = prop(index, "m_flSimulationTime")
    local origin = vector_prop(index, "m_vecOrigin")
    local velocity = vector_prop(index, "m_vecVelocity") or vector_prop(index, "m_vecVelocity[0]")
    if not simulation_time or not origin or not velocity or not frame.receive_time or
        not frame.tick_interval or frame.tick_interval <= 0 then
        invalid_samples = invalid_samples + 1
        return
    end
    if not old or not old.active or old.tick_interval ~= frame.tick_interval then
        advance_epoch(index)
        old = nil
    end
    local flags = prop(index, "m_fFlags")
    -- Do not discard changed duplicate-time snapshots or regressions: they are evidence.
    if old and old.simulation_time == simulation_time and old.flags == flags and
        old.origin[1] == origin[1] and old.origin[2] == origin[2] and old.origin[3] == origin[3] and
        old.velocity[1] == velocity[1] and old.velocity[2] == velocity[2] and old.velocity[3] == velocity[3] then
        duplicates = duplicates + 1
        return
    end
    local record = {sequence = next_sequence(), entity = index, generation = epochs[index],
        active = true, alive = alive, dormant = dormant, simulation_time = simulation_time,
        receive_time = frame.receive_time, local_tick = frame.local_tick,
        local_curtime = frame.local_curtime, tick_interval = frame.tick_interval,
        origin = origin, velocity = velocity, flags = flags, reported_latency = frame.reported_latency}
    push(samples, record)
    latest[index] = record
end
local function on_net_update()
    if not ui.get(enabled) then return end
    local frame, seen = context(), {}
    if not frame.receive_time or not frame.tick_interval or frame.tick_interval <= 0 then
        invalid_samples = invalid_samples + 1
        return
    end
    local players = entity.get_players(true) or {}
    for _, index in ipairs(players) do
        seen[index] = true
        sample(index, frame)
    end
    -- get_players may omit dormant/dead enemies; retain the transition explicitly.
    local missing = {}
    for index, previous in pairs(latest) do
        if previous.active and not seen[index] then missing[#missing + 1] = index end
    end
    for _, index in ipairs(missing) do sample(index, frame) end
end
local fire_fields = {"id", "target", "hit_chance", "hitchance", "hitgroup", "damage",
    "tick", "backtrack", "x", "y", "z", "boosted", "high_priority", "interpolated",
    "extrapolated", "teleported", "reason"}
local function copy_event(event)
    local out = {}
    for _, key in ipairs(fire_fields) do
        local value = event[key]
        if type(value) == "boolean" or type(value) == "string" or finite(value) then out[key] = value end
    end
    return out
end
local function on_fire(event)
    if not ui.get(enabled) or type(event) ~= "table" then return end
    local native = copy_event(event)
    local data = {native = native, cvars = cvars()}
    local previous = latest[native.target]
    if previous then
        data.target_sample_sequence = previous.sequence
        data.target_generation = previous.generation
        local now = clock("realtime")
        if now and previous.receive_time then data.sample_receive_age = now - previous.receive_time end
        if previous.simulation_time then data.target_simulation_time = previous.simulation_time end
    end
    local recorded = emit("aim_fire", data)
    if finite(native.id) then pending[native.id] = recorded.sequence end
end
local function on_outcome(kind, event)
    if not ui.get(enabled) or type(event) ~= "table" then return end
    local native = copy_event(event)
    emit(kind, {native = native, fire_sequence = pending[native.id]})
    if native.id ~= nil then pending[native.id] = nil end
end
local function on_player_reset(event)
    if not ui.get(enabled) or type(event) ~= "table" then return end
    local index = number_call(client.userid_to_entindex, event.userid)
    if index and index > 0 then
        advance_epoch(index)
        emit("entity_reset", {entity = index, generation = epochs[index]})
    end
end
local function on_round_reset()
    if not ui.get(enabled) then return end
    for index in pairs(epochs) do advance_epoch(index) end
    pending = {}
    emit("timeline_reset")
end
local function export_trace()
    local payload = {format = "skeet-prediction-diagnostics", version = 1,
        metadata = {started_receive_time = started, exported_context = context(), cvars = cvars(),
            sample_capacity = SAMPLE_LIMIT, event_capacity = EVENT_LIMIT,
            samples_dropped = samples.dropped, events_dropped = events.dropped,
            unchanged_samples_skipped = duplicates, invalid_samples_skipped = invalid_samples,
            integration_status = "not observable through the public Lua API"},
        samples = ordered(samples), events = ordered(events)}
    local ok, encoded = pcall(json_api.stringify, payload)
    if not ok or type(encoded) ~= "string" then
        client.log("Prediction diagnostics: JSON export failed.")
        return
    end
    local wrote, result = pcall(writefile, OUTPUT, encoded)
    local read_ok, stored = pcall(readfile, OUTPUT)
    if not wrote or result == false or not read_ok or stored ~= encoded then
        client.log("Prediction diagnostics: cannot verify " .. OUTPUT .. "; check writefile access.")
        return
    end
    client.log("Prediction diagnostics: exported " .. samples.size .. " samples, " .. events.size ..
        " events to " .. OUTPUT .. ". Aiming was not modified.")
end
reset()
ui.set(enabled, false)
ui.set_callback(enabled, function()
    if ui.get(enabled) then
        reset()
        client.log("Prediction diagnostics: recording; reproduce a few misses, then export the trace.")
    end
end)
ui.new_button("LUA", "B", "Export prediction trace", export_trace)
client.set_event_callback("net_update_end", on_net_update)
client.set_event_callback("aim_fire", on_fire)
client.set_event_callback("aim_hit", function(e) on_outcome("aim_hit", e) end)
client.set_event_callback("aim_miss", function(e) on_outcome("aim_miss", e) end)
client.set_event_callback("player_spawn", on_player_reset)
client.set_event_callback("player_death", on_player_reset)
client.set_event_callback("player_disconnect", on_player_reset)
client.set_event_callback("round_start", on_round_reset)
client.set_event_callback("level_init", on_round_reset)
