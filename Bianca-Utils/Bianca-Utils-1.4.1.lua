local ffi = require("ffi")
local pui = require("neverlose/pui")

pcall(function()
    ui.sidebar("\a{Link Active}Bianca\aDEFAULT Utils", "heart")
end)

local ICON_MAP = {
    force_shoot = "bolt",
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
end)



events.shutdown:set(function()
    fps_booster_apply(false)
    reflex_enabled = false
    reflex_restore()
    reset_overrides()
end)
