local Backtrack = (function()
local M = {}
local MAX_RECORDS = 64
local function finite(v)
    return type(v) == 'number' and v == v and v ~= math.huge and v ~= -math.huge
end
local function method(object, name, ...)
    if object == nil then return nil end
    local ok, value = pcall(function(...) return object[name](object, ...) end, ...)
    if ok then return value end
end
local function prop(object, name)
    if object == nil then return nil end
    local ok, value = pcall(function() return object[name] end)
    if ok then return value end
end
local function cvalue(name, fallback)
    local value = method(cvar[name], 'float')
    return finite(value) and value or fallback
end
local function clamp(v, low, high) return math.max(low, math.min(high, v)) end
local function yaw_delta(a, b) return (a - b + 180) % 360 - 180 end
local function distance2(a, b)
    return (a.x-b.x)^2 + (a.y-b.y)^2 + (a.z-b.z)^2
end
local function context()
    local now, interval = globals.curtime, globals.tickinterval
    if not finite(now) or not finite(interval) or interval <= 0 or interval > .1 then return nil end
    local unlag = cvalue('sv_maxunlag', .2)
    if unlag <= 0 then return nil end
    unlag = math.min(unlag, 1)
    local interp = math.max(0, cvalue('cl_interp', 0))
    local ratio, rate = cvalue('cl_interp_ratio', 1), cvalue('cl_updaterate', 1/interval)
    if rate > 0 then interp = math.max(interp, math.max(ratio, 0)/rate) end
    local latency = 0
    if utils and type(utils.net_channel) == 'function' then
        local ok, value = pcall(function()
            local channel = utils.net_channel()
            if not channel then return 0 end
            local values = channel.latency
            local outgoing, incoming = values[0], values[1]
            return (finite(outgoing) and math.max(0, outgoing) or 0)
                + (finite(incoming) and math.max(0, incoming) or 0)
        end)
        if ok and finite(value) then latency = value end
    end
    return {now=now, interval=interval, unlag=unlag,
        correct=clamp(latency+interp, 0, unlag), tolerance=math.min(.2, unlag)}
end

function M.valid(record, ctx)
    if not finite(record.time) then return false end
    local age = ctx.now-record.time
    return age >= -ctx.interval and age <= ctx.unlag
        and math.abs(ctx.correct-age) <= ctx.tolerance
end

function M.push(track, sample, ctx)
    local previous = track.records[1]
    if previous and sample.time == previous.time then return end
    if previous and sample.time < previous.time then
        local rollback = previous.time-sample.time
        track.records = {}
        if rollback <= ctx.unlag+ctx.interval then
            track.defensive_until = ctx.now+clamp(rollback, 2*ctx.interval, .2)
        else track.defensive_until = nil end
        previous = nil
    end
    if previous and distance2(sample, previous) > 4096 then
        track.records = {}
        sample.broken = true
    end
    sample.shot = previous ~= nil and finite(sample.shot_time)
        and sample.shot_time > previous.time and sample.shot_time <= sample.time
    table.insert(track.records, 1, sample)
    while #track.records > MAX_RECORDS do table.remove(track.records) end
    while #track.records > 1 and ctx.now-track.records[#track.records].time > ctx.unlag do
        table.remove(track.records)
    end
end

function M.evaluate(track, ctx)
    if not track or not track.records[1] then return nil end
    local newest = track.records[1]
    local valid = 0
    for i = 1, #track.records do
        if M.valid(track.records[i], ctx) then valid = valid+1 end
    end
    local flips, previous_delta = 0, nil
    for i = 1, math.min(#track.records-1, 6) do
        local a, b = track.records[i], track.records[i+1]
        if not a.shot and not b.shot and finite(a.yaw) and finite(b.yaw) then
            local delta = yaw_delta(a.yaw, b.yaw)
            if math.abs(delta) >= 25 then
                if previous_delta and delta*previous_delta < 0 then flips = flips+1 end
                previous_delta = delta
            end
        end
    end
    local defensive = track.defensive_until ~= nil and ctx.now < track.defensive_until
    local risk = newest.broken == true or defensive or valid == 0
    return {delay=risk, safe=risk or flips >= 2, valid=valid,
        defensive=defensive, broken=newest.broken == true, jitter=flips >= 2}
end

function M.create(group, refs, running, decorate)
    local enabled = group:switch(decorate('Adaptive Backtrack'), false)
    local track, owned, stopped = nil, {}, false
    local function current(ref)
        local ok, value = pcall(function() return ref:get_override() end)
        return ok, value
    end
    local function set(ref, value)
        if value == nil then return pcall(function() ref:override() end) end
        return pcall(function() ref:override(value) end)
    end
    local function release()
        for ref, state in pairs(owned) do
            local ok, value = current(ref)
            if ok and value == state.applied then set(ref, state.before) end
        end
        owned = {}
    end
    local function apply(ref, value)
        if ref == nil then return end
        local ok, before = current(ref)
        if ok and set(ref, value) then owned[ref] = {before=before, applied=value} end
    end
    local function local_player()
        if globals.is_in_game == false then return nil end
        local me = entity.get_local_player()
        if me and method(me, 'is_alive') == true then return me end
    end
    local function threat()
        if type(entity.get_threat) ~= 'function' then return nil end
        local ok, target = pcall(entity.get_threat)
        if not ok or not target or method(target, 'is_alive') ~= true
            or method(target, 'is_dormant') == true then return nil end
        local enemy = method(target, 'is_enemy')
        if enemy == false then return nil end
        local index = method(target, 'get_index')
        if finite(index) and index >= 1 and index <= 64 then return target, index end
    end
    local object = {enabled=enabled}
    function object:collect()
        if stopped or not running() or not enabled:get() then return end
        if not local_player() then track = nil; release(); return end
        local target, index = threat()
        local ctx = context()
        if not target or not ctx then track = nil; release(); return end
        if not track or track.index ~= index or track.target ~= target then
            release()
            track = {index=index, target=target, records={}}
        end
        local sim = method(target, 'get_simulation_time')
        local time = prop(sim, 'current')
        if not finite(time) then time = prop(target, 'm_flSimulationTime') end
        local origin = method(target, 'get_origin')
        local x, y, z = prop(origin, 'x'), prop(origin, 'y'), prop(origin, 'z')
        if not finite(time) or not finite(x) or not finite(y) or not finite(z) then
            track = nil; release(); return
        end
        local angles = prop(target, 'm_angEyeAngles') or method(target, 'get_angles')
        local yaw = prop(angles, 'y')
        local weapon = method(target, 'get_player_weapon')
        M.push(track, {time=time, x=x, y=y, z=z, yaw=yaw,
            shot_time=prop(weapon, 'm_fLastShotTime')}, ctx)
    end
    function object:after_base()
        owned = {}
        if stopped or not running() or not enabled:get() then return end
        if not local_player() then track = nil; return end
        local target, index = threat()
        if not track or track.index ~= index or track.target ~= target then return end
        local ctx = context()
        if not ctx then return end
        local decision = M.evaluate(track, ctx)
        if not decision then return end
        if decision.delay then apply(refs.delay_shot, true) end
        if decision.safe then apply(refs.safe_points, 'Force') end
    end
    enabled:set_callback(function()
        release()
        track = nil
        if enabled:get() and (not refs.delay_shot or not refs.safe_points) then
            enabled:set(false)
            print('Bianca Utils: Safe Points / Delay Shot references unavailable')
        end
    end)
    function object:reset() track = nil; release() end
    function object:shutdown()
        stopped = true
        self:reset()
    end
    return object
end

return M

end)()

local ffi = require("ffi")
local pui = require("neverlose/pui")

pcall(function()
    ui.sidebar("\a{Link Active}Bianca\aDEFAULT Utils", "heart")
end)

local ICON_MAP = {
    force_shoot = "bolt",
    backtrack = "clock",
    ragebot = "crosshairs",
    performance = "gauge-high",
    fps_booster = "gauge-high",
    reflex = "bolt-lightning",
}

local function icon_of(key)
    local name = ICON_MAP[key]
    if not name then
        return nil
    end

    local ok, glyph = pcall(pui.get_icon, name)
    if ok and glyph and glyph ~= "" then
        return glyph
    end

    return nil
end

local function with_icon(key, text)
    local glyph = icon_of(key)
    local prefix = glyph and (glyph .. "  ") or ""
    return "\a{Link Active}" .. prefix .. text .. "\aDEFAULT"
end

local function ref(...)
    local ok, item = pcall(pui.find, ...)
    if ok then
        return item
    end
end

local function override(item, value)
    if item == nil then
        return
    end

    if value == nil then
        pcall(function()
            item:override()
        end)
    else
        pcall(function()
            item:override(value)
        end)
    end
end

local refs = {
    hit_chance = ref("Aimbot", "Ragebot", "Selection", "Hit Chance"),
    safe_points = ref("Aimbot", "Ragebot", "Safety", "Safe Points"),
    delay_shot = ref("Aimbot", "Ragebot", "Selection", "Min. Damage", "Delay Shot"),
    mp_head = ref("Aimbot", "Ragebot", "Selection", "Multipoint", "Head Scale"),
    mp_body = ref("Aimbot", "Ragebot", "Selection", "Multipoint", "Body Scale"),
}

local function lp()
    local me = entity.get_local_player()
    if me == nil or not me:is_alive() then
        return nil
    end

    return me
end

local tab_aimbot = pui.create("Bianca Utils", with_icon("ragebot", "Ragebot"), 2)

local menu = {}

menu.force_shoot = tab_aimbot:switch(
    with_icon("force_shoot", "Force Shot"),
    false
)

local backtrack_running = true
local backtrack = Backtrack.create(tab_aimbot, refs, function() return backtrack_running end,
    function(text) return with_icon("backtrack", text) end)
events.net_update_end:set(function()
    backtrack:collect()
end)
events.round_prestart:set(function()
    backtrack:reset()
end)
events.shutdown:set(function()
    backtrack_running = false
    backtrack:shutdown()
end)

local performance_tab = pui.create("Bianca Utils", with_icon("performance", "Performance"), 1)

menu.fps_booster = performance_tab:switch(
    with_icon("fps_booster", "FPS Booster"),
    false
)

menu.reflex = performance_tab:switch(
    with_icon("reflex", "Reflex"),
    false
)

local fps_cvars = {
    mod_forcedata = 1,
    cl_disable_ragdolls = 1,
    cl_csm_world_shadows_in_viewmodelcascade = 0,
    gameinstructor_enable = 0,
    fog_enable_water_fog = 0,
    cl_disablehtmlmotd = 1,
    cl_autohelp = 0,
    cl_showhelp = 0,
    cl_freezecameffects_showholiday = 0,
    cl_freezecampanel_position_dynamic = 0,
    cl_disablefreezecam = 1,
    cl_csm_sprite_shadows = 0,
    cl_csm_rope_shadows = 0,
    cl_csm_viewmodel_shadows = 0,
    cl_foot_contact_shadows = 0,
    cl_csm_world_shadows = 0,
    cl_csm_shadows = 0,
    cl_csm_static_prop_shadows = 0,
    r_shadows = 0,
    r_3dsky = 0,
    func_break_max_pieces = 0,
    r_dynamic = 0,
    r_dynamiclighting = 0,
    r_eyemove = 0,
    r_eyegloss = 0,
    cl_showerror = 0,
    mat_disable_bloom = 1,
    dsp_slow_cpu = 1,
    r_drawsprites = 0,
    r_drawropes = 0,
    r_drawrain = 0,
    r_drawdecals = 0,
    violence_hblood = 0,
    cl_csm_entity_shadows = 0,
    cl_csm_translucent_shadows = 0
}

local fps_original = {}

local function fps_booster_apply(enabled)
    if enabled then
        for name, value in pairs(fps_cvars) do
            local variable = cvar[name]

            if variable ~= nil then
                if fps_original[name] == nil then
                    local ok, original = pcall(function()
                        return variable:int()
                    end)

                    if ok and type(original) == "number" then
                        fps_original[name] = original
                    end
                end

                if fps_original[name] ~= nil then
                    pcall(function()
                        variable:int(value)
                    end)
                end
            end
        end
    else
        for name, original in pairs(fps_original) do
            local variable = cvar[name]

            if variable ~= nil then
                pcall(function()
                    variable:int(original)
                end)
            end
        end

        fps_original = {}
    end
end

menu.fps_booster:set_callback(function(item)
    fps_booster_apply(item:get() == true)
end, true)

pcall(ffi.cdef, [[
    void* __stdcall GetCurrentThread(void);
    int __stdcall GetThreadPriority(void*);
    int __stdcall SetThreadPriority(void*, int);
]])

local reflex_thread

pcall(function()
    reflex_thread = ffi.C.GetCurrentThread()
end)

local reflex_enabled = false
local reflex_last = 0
local reflex_original_priority

local function reflex_apply()
    if reflex_thread == nil then
        return
    end

    if reflex_original_priority == nil then
        local ok, priority = pcall(function()
            return tonumber(ffi.C.GetThreadPriority(reflex_thread))
        end)

        if ok and priority ~= 2147483647 then
            reflex_original_priority = priority
        else
            reflex_original_priority = 0
        end
    end

    pcall(function()
        ffi.C.SetThreadPriority(reflex_thread, 2)
    end)
end

local function reflex_restore()
    if reflex_thread ~= nil and reflex_original_priority ~= nil then
        pcall(function()
            ffi.C.SetThreadPriority(reflex_thread, reflex_original_priority)
        end)
    end

    reflex_original_priority = nil
    reflex_last = 0
end

local function reflex_set(enabled)
    enabled = enabled == true

    if enabled == reflex_enabled then
        return
    end

    reflex_enabled = enabled

    if enabled then
        reflex_apply()
        reflex_last = globals.realtime
    else
        reflex_restore()
    end
end

local function reflex_tick()
    if reflex_thread == nil then
        return
    end

    local now = globals.realtime

    if now - reflex_last <= 0.5 then
        return
    end

    reflex_last = now
    reflex_apply()
end

menu.reflex:set_callback(function(item)
    reflex_set(item:get() == true)
end, true)

events.render:set(function()
    if reflex_enabled then
        reflex_tick()
    end
end)

local function is_number(value)
    return type(value) == "number"
        and value == value
        and value ~= math.huge
        and value ~= -math.huge
end

local function read_number(object, key)
    if object == nil then
        return nil
    end

    local ok, value = pcall(function()
        return object[key]
    end)

    if ok and is_number(value) then
        return value
    end

    return nil
end

local function call_method(object, name)
    if object == nil then
        return nil
    end

    local ok, value = pcall(function()
        local method = object[name]
        if type(method) ~= "function" then
            return nil
        end

        return method(object)
    end)

    if ok then
        return value
    end

    return nil
end

local function min_info(a, b)
    if is_number(a) and is_number(b) then
        return math.min(a, b)
    end

    if is_number(a) then
        return a
    end

    if is_number(b) then
        return b
    end

    return nil
end

local function clamp(value, min_value, max_value)
    return math.max(min_value, math.min(max_value, value))
end

local function auto_hitchance(player, weapon, info)
    local velocity = player.m_vecVelocity
    if velocity == nil then
        return nil
    end

    local vx = read_number(velocity, "x")
    local vy = read_number(velocity, "y")

    if vx == nil or vy == nil then
        return nil
    end

    local flags = read_number(player, "m_fFlags") or 0
    local crouching = bit.band(math.floor(flags), 2) ~= 0

    local speed = math.sqrt(vx * vx + vy * vy)

    local max_speed = call_method(weapon, "get_max_speed")
    if not is_number(max_speed) or max_speed <= 0 then
        max_speed = min_info(
            read_number(info, "max_player_speed"),
            read_number(info, "max_player_speed_alt")
        )
    end

    if not is_number(max_speed) or max_speed <= 0 then
        return nil
    end

    local base_inaccuracy
    if crouching then
        base_inaccuracy = min_info(
            read_number(info, "inaccuracy_crouch"),
            read_number(info, "inaccuracy_crouch_alt")
        )
    else
        base_inaccuracy = min_info(
            read_number(info, "inaccuracy_stand"),
            read_number(info, "inaccuracy_stand_alt")
        )
    end

    local move_inaccuracy = min_info(
        read_number(info, "inaccuracy_move"),
        read_number(info, "inaccuracy_move_alt")
    )

    if not is_number(base_inaccuracy) or not is_number(move_inaccuracy) then
        return nil
    end

    local movement_factor = math.min(speed, max_speed * 0.5) / max_speed
    local expected_inaccuracy = base_inaccuracy
        + (move_inaccuracy - base_inaccuracy) * movement_factor

    local current_inaccuracy = call_method(weapon, "get_inaccuracy")
    if not is_number(current_inaccuracy) or current_inaccuracy < 0 then
        return nil
    end

    if current_inaccuracy > expected_inaccuracy + 0.000001 then
        return nil
    end

    local spread = call_method(weapon, "get_spread")
    if not is_number(spread) or spread < 0 then
        spread = read_number(info, "spread") or 0
    end

    local current_dispersion = math.sqrt(
        current_inaccuracy * current_inaccuracy + spread * spread
    )

    local expected_dispersion = math.sqrt(
        expected_inaccuracy * expected_inaccuracy + spread * spread
    )

    local accuracy_ratio = current_dispersion / math.max(expected_dispersion, 0.000001)
    local accuracy_quality = clamp(1 - accuracy_ratio, 0, 1)

    return clamp(
        math.floor(1 + accuracy_quality * 19 + 0.5),
        1,
        20
    )
end

local function reset_overrides()
    override(refs.hit_chance, nil)
    override(refs.safe_points, nil)
    override(refs.delay_shot, nil)
    override(refs.mp_head, nil)
    override(refs.mp_body, nil)
end

events.createmove:set(function()
    local active = false

    if menu.force_shoot:get() then
        local player = lp()

        if player then
            local weapon = player:get_player_weapon()

            if weapon then
                local info = weapon:get_weapon_info()
                local classname = call_method(weapon, "get_classname")
                local weapon_type = read_number(info, "weapon_type")

                local skip_weapon = weapon_type == 9
                    or weapon_type == 0
                    or classname == "CWeaponTaser"
                    or classname == "CKnife"
                    or (type(classname) == "string" and classname:find("Knife", 1, true) ~= nil)

                if info ~= nil and not skip_weapon then
                    local hitchance = auto_hitchance(player, weapon, info)

                    if hitchance ~= nil then
                        active = true

                        override(refs.hit_chance, hitchance)
                        override(refs.safe_points, "Default")
                        override(refs.delay_shot, false)
                        override(refs.mp_head, 100)
                        override(refs.mp_body, 100)
                    end
                end
            end
        end
    end

    if not active then
        reset_overrides()
    end
    backtrack:after_base()
end)



events.shutdown:set(function()
    fps_booster_apply(false)
    reflex_enabled = false
    reflex_restore()
    reset_overrides()
end)
