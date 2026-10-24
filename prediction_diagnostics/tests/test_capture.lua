-- Execute the actual recorder against an instrumented GameSense API fixture.
local callbacks, buttons, checkbox = {}, {}, nil
local output, exported, messages = {}, nil, {}
local time, tick, sim = 100, 3200, 50
local alive, dormant, players, bad_origin = true, false, {2}, false
local calls_to_mutators = 0
local function forbidden()
    calls_to_mutators = calls_to_mutators + 1
    error("Aiming/entity/cvar mutation is forbidden in this recorder")
end
ui = {
    new_checkbox = function(tab, container, name)
        assert(tab == "LUA" and container == "B")
        checkbox = {value = false}; return checkbox
    end,
    new_button = function(tab, container, name, callback) buttons[name] = callback end,
    set_callback = function(ref, callback) ref.callback = callback end,
    get = function(ref) return ref.value end,
    set = function(ref, value) ref.value = value; if ref.callback then ref.callback() end end,
    reference = forbidden
}
globals = {
    realtime = function() return time end, curtime = function() return sim end,
    tickcount = function() return tick end, tickinterval = function() return 1/64 end
}
client = {
    set_event_callback = function(name, callback) assert(not callbacks[name]); callbacks[name] = callback end,
    latency = function() return .100 end,
    userid_to_entindex = function(value) return value == 10 and 2 or 0 end,
    log = function(message) messages[#messages+1] = message end,
    exec = forbidden
}
entity = {
    get_players = function() return players end,
    is_alive = function() return alive end,
    is_dormant = function() return dormant end,
    get_prop = function(index, name)
        assert(index == 2)
        if name == "m_flSimulationTime" then return sim end
        if name == "m_vecOrigin" then return bad_origin and 0/0 or 0, 0, 0 end
        if name == "m_vecVelocity" then return 0, 0, 0 end
        if name == "m_fFlags" then return 1 end
    end,
    set_prop = forbidden
}
cvar = {}
for name, value in pairs({cl_interp=0,cl_interp_ratio=1,cl_updaterate=64,sv_gravity=800}) do
    local current = value
    cvar[name] = {get_float = function() return current end, set_float=forbidden, set_int=forbidden}
end
json = {stringify = function(value) exported = value; return "test-codec-output" end}
writefile = function(path, value) output[path] = value end
readfile = function(path) return output[path] end
local tests = 0
local function check(value) tests = tests + 1; assert(value, "check " .. tests) end
local function export()
    buttons["Export prediction trace"]()
    check(exported ~= nil)
    return exported
end
local function frame()
    callbacks.net_update_end()
end
local function advance(n)
    tick, sim, time = tick+n, sim+n/64, time+n/64
end
dofile(arg[1] or "prediction_diagnostics/capture.lua")
frame()
check(#export().samples == 0) -- Opt-in starts disabled.
ui.set(checkbox, true)
frame()
local a = export()
check(#a.samples == 1 and a.samples[1].origin[1] == 0 and a.samples[1].velocity[1] == 0)
local first_generation = a.samples[1].generation
frame()
a = export()
check(#a.samples == 1 and a.metadata.unchanged_samples_skipped == 1)
advance(1); frame()
callbacks.aim_fire({id=7,target=2,hit_chance=75,backtrack=.03125,x=0,y=0,z=64,extrapolated=false})
callbacks.aim_miss({id=7,target=2,reason="spread"})
a = export()
check(#a.events == 2)
check(a.events[1].native.extrapolated == false and a.events[1].native.interpolated == nil)
check(a.events[2].fire_sequence == a.events[1].sequence)
check(a.events[1].sample_receive_age == 0)
check(a.events[1].cvars.cl_interp == 0)
-- Missing identity must not invent a correlation.
callbacks.aim_miss({reason="?"})
a = export(); check(a.events[3].fire_sequence == nil)
-- Visibility transitions are recorded, then reset the entity history on reactivation.
dormant, players = true, {}
advance(1); frame()
a = export(); check(a.samples[#a.samples].active == false)
dormant, players = false, {2}
advance(1); frame()
a = export(); check(a.samples[#a.samples].generation > first_generation)
callbacks.player_spawn({userid=10})
advance(1); frame()
a = export(); check(a.events[#a.events].kind == "entity_reset")
-- Non-finite engine input never reaches JSON.
local before = #a.samples
bad_origin = true
advance(1); frame()
a = export(); check(#a.samples == before and a.metadata.invalid_samples_skipped == 1)
bad_origin = false
-- Changed records with regressed simulation timestamps remain observable.
sim = sim - 1
frame()
a = export(); check(a.samples[#a.samples].simulation_time < a.samples[#a.samples-1].simulation_time)
-- Bounded rolling history remains ordered after wraparound.
for i=1,8300 do advance(1); frame() end
a = export()
check(#a.samples == 8192 and a.metadata.samples_dropped > 0)
for i=2,#a.samples do check(a.samples[i].sequence > a.samples[i-1].sequence) end
for id=100,700 do callbacks.aim_fire({id=id,target=2,extrapolated=true}) end
callbacks.aim_miss({id=100,target=2,reason="prediction error"})
a = export()
check(#a.events == 512 and a.metadata.events_dropped > 0)
check(a.events[#a.events].fire_sequence == nil) -- Evicted pending fire was released.
ui.set(checkbox, false)
local count = #a.samples
advance(1); frame()
check(#export().samples == count)
check(calls_to_mutators == 0)
-- A failed write is reported instead of claiming success.
writefile = function() return false end
export()
check(messages[#messages]:find("cannot verify",1,true) ~= nil)
print("Recorder lifecycle, ring wrap, shot correlation, invalid input, disabled capture and read-only API checks passed (" .. tests .. " assertions).")
