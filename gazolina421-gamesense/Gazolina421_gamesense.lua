-- Gazolina 421 | GameSense CS:GO port
-- Original input: Gazolina421.lua (Neverlose v3 / CS:GO).
-- Menu: AA -> Anti-aimbot angles. LuaJIT 5.1.
-- No Neverlose modules, downloads, signature scans or remote code are used.
-- See Gazolina421_gamesense_README.txt for API differences and validation limits.

local G = {
    version = 1, controls = {}, order = {}, profiles = {}, profile_schema = {},
    loading = true, refs = {}, overrides = {}, cv_cache = {}, shots = {},
    states = {"Standing", "Running", "Slowing", "Crouching", "Sneaking", "Air", "Air Crouching", "Manuals", "Safe Head"},
    teams = {"T", "CT"}, editor_team = "T", editor_state = "Standing",
    runtime = {side = false, sent = 0, last_flip = 0, warmup_offset = 0,
        brute_until = 0, brute_offset = 0, brute_tick = -1, last_weapon = nil,
        unlock_command = 0, locked = nil, hit_until = -100, world_until = -100,
        scope_alpha = 0, arrow_alpha = 0, last_manual = "Disabled", manual_keys = {}},
    db_key = "gazolina421_gamesense_v1", preset_names = {},
}

function G.copy(v)
    if type(v) ~= "table" then return v end
    local out = {}; for k, x in pairs(v) do out[k] = G.copy(x) end; return out
end
function G.clamp(v, lo, hi) return math.max(lo, math.min(hi, v)) end
function G.yaw(v) return (v + 180) % 360 - 180 end
function G.random(a, b) return client.random_int(math.min(a, b), math.max(a, b)) end
function G.has(t, v)
    for _, x in ipairs(t or {}) do if x == v then return true end end
    return false
end
function G.prop(ent, name, default, index)
    if not ent then return default end
    local value = entity.get_prop(ent, name, index)
    if value == nil then return default end
    return value
end
function G.optional(name)
    local ok, lib = pcall(require, name); if ok then return lib end
end
G.clipboard = G.optional("gamesense/clipboard")
G.trace_lib = G.optional("gamesense/trace")
G.vector_lib = G.optional("vector")
G.entity_lib = G.optional("gamesense/entity")
G.weapons = G.optional("gamesense/csgo_weapons")

function G.log(text, bad)
    local c = G.controls.log_prefix and G.get("log_prefix") or {222, 137, 137, 255}
    client.color_log(c[1], c[2], c[3], "[Gazolina] \0")
    c = bad and {255, 95, 95} or (G.controls.log_main and G.get("log_main") or {150, 176, 186})
    client.color_log(c[1], c[2], c[3], tostring(text))
end
function G.find(key, tab, container, name, required)
    local result = {pcall(ui.reference, tab, container, name)}
    if not result[1] then
        if required then error("[Gazolina] Missing GameSense control: " .. tab .. " / " .. container .. " / " .. name) end
        G.refs[key] = {}; return
    end
    table.remove(result, 1); G.refs[key] = result
end
G.find("enabled", "AA", "Anti-aimbot angles", "Enabled", true)
G.find("pitch", "AA", "Anti-aimbot angles", "Pitch", true)
G.find("yaw_base", "AA", "Anti-aimbot angles", "Yaw base", true)
G.find("yaw", "AA", "Anti-aimbot angles", "Yaw", true)
G.find("jitter", "AA", "Anti-aimbot angles", "Yaw jitter", true)
G.find("body", "AA", "Anti-aimbot angles", "Body yaw", true)
G.find("fs_body", "AA", "Anti-aimbot angles", "Freestanding body yaw")
G.find("freestanding", "AA", "Anti-aimbot angles", "Freestanding")
G.find("fake_limit", "AA", "Anti-aimbot angles", "Fake yaw limit")
G.find("edge", "AA", "Anti-aimbot angles", "Edge yaw")
G.find("slow", "AA", "Other", "Slow motion")
G.find("duck", "RAGE", "Other", "Duck peek assist")
G.find("legs", "AA", "Other", "Leg movement")
G.find("dt", "RAGE", "Aimbot", "Double tap")
G.find("dt_fl", "RAGE", "Aimbot", "Double tap fake lag limit")
G.find("hs", "AA", "Other", "On shot anti-aim")
G.find("scope", "VISUALS", "Effects", "Remove scope overlay")
G.find("ping", "MISC", "Miscellaneous", "Ping spike")
G.find("shared", "VISUALS", "Player ESP", "Shared ESP")
G.find("strafe", "MISC", "Movement", "Air strafe")
G.find("bhop", "MISC", "Movement", "Bunny hop")
G.find("quick_stop", "MISC", "Movement", "Fast walk")

function G.active_ref(key)
    local refs = G.refs[key] or {}
    if not refs[1] then return false end
    local v = ui.get(refs[1])
    if type(v) == "boolean" and not v then return false end
    if refs[2] then return ui.get(refs[2]) == true end
    return v == true
end
function G.override(key, index, value, kind)
    local ref = (G.refs[key] or {})[index or 1]; if not ref then return end
    if not G.overrides[ref] then
        local previous = {ui.get(ref)}
        -- Hotkeys: ui.get returns active, mode, key. Only change/restore their mode.
        G.overrides[ref] = {values = previous, kind = kind}
    end
    if kind == "multi" then ui.set(ref, value)
    else ui.set(ref, value) end
end
function G.release(key)
    for _, ref in ipairs(G.refs[key] or {}) do
        local old = G.overrides[ref]
        if old then
            if old.kind == "hotkey" then
                local modes = {[0] = "Always on", [1] = "On hotkey", [2] = "Toggle", [3] = "Off hotkey"}
                ui.set(ref, modes[old.values[2]] or "On hotkey")
            else ui.set(ref, unpack(old.values)) end
            G.overrides[ref] = nil
        end
    end
end
function G.restore_refs()
    for key in pairs(G.refs) do G.release(key) end
end
function G.cv(name, value)
    local cv = cvar[name]; if not cv then return end
    if not G.cv_cache[name] then G.cv_cache[name] = {cv = cv, value = cv:get_float()} end
    cv:set_raw_float(value)
    cv:set_raw_int(math.floor(value))
end
function G.release_cv(name)
    local old = G.cv_cache[name]
    if old then old.cv:set_raw_float(old.value); old.cv:set_raw_int(math.floor(old.value)); G.cv_cache[name] = nil end
end
function G.restore_cvars()
    local names = {}; for name in pairs(G.cv_cache) do names[#names + 1] = name end
    for _, name in ipairs(names) do G.release_cv(name) end
end

-- Native controls are shared by the selected state. All 18 profiles live in
-- G.profiles; switching Team/State never overwrites another profile.
function G.add(key, kind, label, page, part, opts, default, predicate, profile)
    local name = label .. "\nGazolina421_" .. key
    if kind == "slider" then default = G.clamp(math.floor(default or opts[1]), opts[1], opts[2]) end
    local ref, color_label
    if kind == "check" then ref = ui.new_checkbox("AA", "Anti-aimbot angles", name)
    elseif kind == "combo" then ref = ui.new_combobox("AA", "Anti-aimbot angles", name, unpack(opts))
    elseif kind == "multi" then ref = ui.new_multiselect("AA", "Anti-aimbot angles", name, unpack(opts))
    elseif kind == "slider" then
        ref = ui.new_slider("AA", "Anti-aimbot angles", name, opts[1], opts[2], default or opts[1], true, opts.unit or "", opts.scale or 1, opts.tips)
    elseif kind == "color" then
        color_label = ui.new_label("AA", "Anti-aimbot angles", label)
        ref = ui.new_color_picker("AA", "Anti-aimbot angles", name, unpack(default))
    elseif kind == "text" then ref = ui.new_textbox("AA", "Anti-aimbot angles", name)
    elseif kind == "label" then ref = ui.new_label("AA", "Anti-aimbot angles", label)
    elseif kind == "button" then ref = ui.new_button("AA", "Anti-aimbot angles", name, function() if G.actions and G.actions[key] then G.actions[key]() end end)
    elseif kind == "list" then ref = ui.new_listbox("AA", "Anti-aimbot angles", name, opts)
    elseif kind == "hotkey" then ref = ui.new_hotkey("AA", "Anti-aimbot angles", name, false)
    end
    local item = {ref = ref, color_label = color_label, kind = kind, page = page, part = part, opts = opts, default = G.copy(default), predicate = predicate, profile = profile}
    G.controls[key] = item; G.order[#G.order + 1] = key
    if profile then G.profile_schema[#G.profile_schema + 1] = key end
    if default ~= nil and kind ~= "slider" and kind ~= "label" and kind ~= "button" then
        if kind == "color" then ui.set(ref, unpack(default)) else ui.set(ref, default) end
    end
    return ref
end
function G.get(key)
    local item = G.controls[key]
    if item.kind == "color" then return {ui.get(item.ref)} end
    return ui.get(item.ref)
end
function G.set(key, v)
    local item = G.controls[key]
    if item.kind == "color" then ui.set(item.ref, unpack(v)) else ui.set(item.ref, v) end
end
function G.profile() return G.profiles[G.editor_team][G.editor_state] end
function G.is_enabled() return G.get("master") and G.get("activation") end
function G.profile_default()
    local p = {}; for _, k in ipairs(G.profile_schema) do p[k] = G.copy(G.controls[k].default) end; return p
end
function G.save_editor()
    if G.loading then return end
    local p = G.profile()
    for _, key in ipairs(G.profile_schema) do p[key] = G.copy(G.get(key)) end
end
function G.load_editor()
    local old = G.loading; G.loading = true
    local p = G.profile()
    for _, key in ipairs(G.profile_schema) do G.set(key, p[key]) end
    G.loading = old
end
function G.visibility()
    local enabled = G.get("master")
    local page = G.get("page")
    for _, key in ipairs(G.order) do
        local c = G.controls[key]
        local visible = true
        if c.page then visible = enabled and (c.page == "*" or c.page == page) end
        if visible and c.part then
            visible = c.part == G.get(page == "Angles" and "angles_page" or "other_page")
        end
        if visible and c.predicate then visible = c.predicate() end
        ui.set_visible(c.ref, visible)
        if c.color_label then ui.set_visible(c.color_label, visible) end
    end
end
function G.profile_control(key, kind, name, opts, default, predicate, part)
    return G.add(key, kind, name, "Angles", part or "Builder", opts, default, predicate, true)
end

G.add("title", "label", "\a9CA7E1FFGazolina 421  |  GameSense")
G.add("master", "check", "Enable Gazolina", nil, nil, nil, false)
G.add("toggle", "button", "Toggle Gazolina")
G.add("activation", "hotkey", "Gazolina activation", "*")
ui.set(G.controls.activation.ref, "Always on")
G.add("page", "combo", "Gazolina", "*", nil, {"Presets", "Angles", "Other"}, "Angles")
G.add("angles_page", "combo", "Angles", "Angles", nil, {"Builder", "Tickbase", "Hotkeys", "Options"}, "Builder")
G.add("team", "combo", "Team", "Angles", nil, G.teams, "T", function() return G.get("angles_page") == "Builder" or G.get("angles_page") == "Tickbase" end)
G.add("state", "combo", "State", "Angles", nil, G.states, "Standing", function() return G.get("angles_page") == "Builder" or G.get("angles_page") == "Tickbase" end)
G.add("copy", "button", "Copy", "Angles", "Builder")
G.add("paste", "button", "Paste", "Angles", "Builder")
G.add("opposite", "button", "Send to opposite team", "Angles", "Builder")
G.add("yaw_header", "label", "\a9CA7E1FFYaw", "Angles", "Builder")
G.profile_control("yaw", "slider", "Mode", {0, 1, tips = {[0] = "Off", [1] = "Dual"}}, 0, function() return G.get("state") ~= "Safe Head" end)
G.profile_control("yaw_offset", "slider", "Yaw Offset", {-180, 180}, 0, function() return G.get("yaw") == 0 and G.get("state") ~= "Safe Head" end)
G.profile_control("left_yaw", "slider", "Left Yaw", {-180, 180}, 0, function() return G.get("yaw") == 1 and G.get("state") ~= "Safe Head" end)
G.profile_control("right_yaw", "slider", "Right Yaw", {-180, 180}, 0, function() return G.get("yaw") == 1 and G.get("state") ~= "Safe Head" end)
G.profile_control("apply_delay", "check", "Apply Delay", nil, false, function() return G.get("yaw") == 1 and G.get("state") ~= "Safe Head" end)
G.profile_control("delay_method", "combo", "Method", {"Default", "Random", "Ways"}, "Default", function() return G.get("yaw") == 1 and G.get("apply_delay") end)
G.profile_control("delay_default", "slider", "Timing", {1, 22}, 1, function() return G.get("yaw") == 1 and G.get("apply_delay") and G.get("delay_method") == "Default" end)
G.profile_control("delay_random_min", "slider", "[1]", {1, 22}, 1, function() return G.get("yaw") == 1 and G.get("apply_delay") and G.get("delay_method") == "Random" end)
G.profile_control("delay_random_max", "slider", "[2]", {1, 22}, 1, function() return G.get("yaw") == 1 and G.get("apply_delay") and G.get("delay_method") == "Random" end)
G.profile_control("delay_custom_sliders", "slider", "Ways", {1, 10}, 2, function() return G.get("yaw") == 1 and G.get("apply_delay") and G.get("delay_method") == "Ways" end)
for i = 1, 10 do
    G.profile_control("delay_" .. i, "slider", "Timing " .. i, {1, 22}, 1, function() return G.get("yaw") == 1 and G.get("apply_delay") and G.get("delay_method") == "Ways" and G.get("delay_custom_sliders") >= i end)
end
G.add("shuffle_delay", "button", "Shuffle", "Angles", "Builder", nil, nil, function() return G.get("yaw") == 1 and G.get("apply_delay") and G.get("delay_method") == "Ways" end)
G.add("modifier_header", "label", "\a9CA7E1FFYaw Modifier", "Angles", "Builder")
G.profile_control("yaw_modifier", "combo", "Type", {"Disabled", "Center", "Offset", "Random", "Spin", "3-Way", "5-Way"}, "Disabled")
G.profile_control("modifier_offset", "slider", "Offset", {-180, 180}, 0, function() return G.get("yaw_modifier") ~= "Disabled" and not G.get("randomize_modifier") end)
G.profile_control("randomize_modifier", "check", "Randomize", nil, false, function() return G.get("yaw_modifier") ~= "Disabled" end)
G.profile_control("randomize_mode", "combo", "Method", {"Default", "Ways"}, "Default", function() return G.get("yaw_modifier") ~= "Disabled" and G.get("randomize_modifier") end)
G.profile_control("randomize_min", "slider", "Min. Offset", {-180, 180}, 0, function() return G.get("yaw_modifier") ~= "Disabled" and G.get("randomize_modifier") and G.get("randomize_mode") == "Default" end)
G.profile_control("randomize_max", "slider", "Max. Offset", {-180, 180}, 0, function() return G.get("yaw_modifier") ~= "Disabled" and G.get("randomize_modifier") and G.get("randomize_mode") == "Default" end)
G.profile_control("randomize_custom_sliders", "slider", "Ways", {2, 10}, 2, function() return G.get("yaw_modifier") ~= "Disabled" and G.get("randomize_modifier") and G.get("randomize_mode") == "Ways" end)
for i = 1, 10 do
    G.profile_control("randomize_" .. i, "slider", "Offset " .. i, {-180, 180}, 0, function() return G.get("yaw_modifier") ~= "Disabled" and G.get("randomize_modifier") and G.get("randomize_mode") == "Ways" and G.get("randomize_custom_sliders") >= i end)
end
G.add("shuffle_modifier", "button", "Shuffle", "Angles", "Builder", nil, nil, function() return G.get("yaw_modifier") ~= "Disabled" and G.get("randomize_modifier") and G.get("randomize_mode") == "Ways" end)
G.add("body_header", "label", "\a9CA7E1FFBody Yaw", "Angles", "Builder")
G.profile_control("body_yaw", "check", "Body Yaw", nil, false)
G.profile_control("body_jitter", "check", "Jitter", nil, true, function() return G.get("body_yaw") and not G.get("apply_delay") end)
G.profile_control("inverter", "check", "Inverter", nil, false, function() return G.get("body_yaw") and not G.get("apply_delay") and not G.get("body_jitter") end)
G.profile_control("mode", "combo", "Mode", {"Static", "Ticks", "Random"}, "Static", function() return G.get("body_yaw") end)
G.profile_control("mode_ticks", "slider", "Ticks", {4, 16, unit = "t"}, 4, function() return G.get("body_yaw") and G.get("mode") == "Ticks" end)
G.profile_control("mode_random", "slider", "Random Ticks", {4, 16, unit = "x"}, 4, function() return G.get("body_yaw") and G.get("mode") == "Random" end)
G.profile_control("limit_mode", "combo", "Limit Mode", {"Default", "Switch", "Random"}, "Default", function() return G.get("body_yaw") end)
G.profile_control("left_limit", "slider", "Left Limit", {0, 60}, 60, function() return G.get("body_yaw") and G.get("limit_mode") == "Default" end)
G.profile_control("right_limit", "slider", "Right Limit", {0, 60}, 60, function() return G.get("body_yaw") and G.get("limit_mode") == "Default" end)
G.profile_control("from_limit", "slider", "From", {0, 60}, 60, function() return G.get("body_yaw") and G.get("limit_mode") ~= "Default" end)
G.profile_control("to_limit", "slider", "To", {0, 60}, 60, function() return G.get("body_yaw") and G.get("limit_mode") ~= "Default" end)

G.add("break_lc", "multi", "Break LC", "Angles", "Tickbase", G.states, {})
G.add("break_triggers", "multi", "Action Triggers", "Angles", "Tickbase", {"Weapon Swap", "Weapon Reload"}, {})
G.add("hide_shots", "combo", "Hide Shots", "Angles", "Tickbase", {"Favor Fire Rate", "Favor Fake Lag", "Break LC"}, "Favor Fire Rate")
G.add("tickbase_note", "label", "GameSense defensive timing is an approximation.", "Angles", "Tickbase")
G.profile_control("defensive_choke", "combo", "Mode", {"Default", "Custom"}, "Default", nil, "Tickbase")
G.profile_control("random_choke", "check", "Randomize", nil, false, function() return G.get("defensive_choke") == "Custom" end, "Tickbase")
G.profile_control("choke_slider", "slider", "Choke", {1, 32}, 16, function() return G.get("defensive_choke") == "Custom" and not G.get("random_choke") end, "Tickbase")
G.profile_control("choke_method", "combo", "Method", {"Default", "Custom"}, "Default", function() return G.get("defensive_choke") == "Custom" and G.get("random_choke") end, "Tickbase")
G.profile_control("choke_from", "slider", "[1]", {1, 32}, 32, function() return G.get("defensive_choke") == "Custom" and G.get("random_choke") and G.get("choke_method") == "Default" end, "Tickbase")
G.profile_control("choke_to", "slider", "[2]", {1, 32}, 32, function() return G.get("defensive_choke") == "Custom" and G.get("random_choke") and G.get("choke_method") == "Default" end, "Tickbase")
G.profile_control("choke_sliders", "slider", "Sliders", {2, 10}, 2, function() return G.get("defensive_choke") == "Custom" and G.get("random_choke") and G.get("choke_method") == "Custom" end, "Tickbase")
for i = 1, 10 do
    G.profile_control("choke1_" .. i, "slider", "Choke " .. i, {1, 32}, 1, function() return G.get("defensive_choke") == "Custom" and G.get("random_choke") and G.get("choke_method") == "Custom" and G.get("choke_sliders") >= i end, "Tickbase")
end
G.add("shuffle_choke", "button", "Shuffle", "Angles", "Tickbase", nil, nil, function() return G.get("defensive_choke") == "Custom" and G.get("random_choke") and G.get("choke_method") == "Custom" end)

G.add("freestanding", "check", "Freestanding", "Angles", "Hotkeys", nil, false)
G.add("fs_key", "hotkey", "Freestanding key", "Angles", "Hotkeys")
ui.set(G.controls.fs_key.ref, "Always on")
G.add("prefer_manual", "check", "Prefer Manual", "Angles", "Hotkeys", nil, false)
G.add("fs_disablers", "multi", "Disablers", "Angles", "Hotkeys", G.states, {})
G.add("fs_modifiers", "check", "Disable Yaw Modifiers", "Angles", "Hotkeys", nil, false)
G.add("fs_body", "check", "Body Freestanding", "Angles", "Hotkeys", nil, false)
G.add("manual_yaw", "combo", "Manual Yaw", "Angles", "Hotkeys", {"Disabled", "Left", "Right", "Forward"}, "Disabled")
G.add("manual_base", "combo", "Yaw Base", "Angles", "Hotkeys", {"Local View", "At Target"}, "Local View")
G.add("manual_left", "hotkey", "Manual Left", "Angles", "Hotkeys")
G.add("manual_right", "hotkey", "Manual Right", "Angles", "Hotkeys")
G.add("manual_forward", "hotkey", "Manual Forward", "Angles", "Hotkeys")
G.add("manual_reset", "hotkey", "Reset Manuals", "Angles", "Hotkeys")
G.add("manual_note", "label", "Direction keys: press once to set, again to reset.", "Angles", "Hotkeys")
G.add("anti_bruteforce", "check", "Anti-Bruteforce", "Angles", "Options", nil, false)
G.add("brute_states", "multi", "Conditions", "Angles", "Options", G.states, {}, function() return G.get("anti_bruteforce") end)
G.add("brute_mode", "combo", "Mode", "Angles", "Options", {"Increasing", "Decreasing", "Meta"}, "Increasing", function() return G.get("anti_bruteforce") end)
G.add("safe_head", "check", "Safe Head", "Angles", "Options", nil, false)
G.add("safe_conditions", "multi", "Conditions", "Angles", "Options", {"Air Crouch", "Crouching", "Taser", "Knife", "Height Advantage"}, {}, function() return G.get("safe_head") end)
G.add("safe_height", "slider", "Height Difference", "Angles", "Options", {-200, 200}, 25, function() return G.get("safe_head") and G.has(G.get("safe_conditions"), "Height Advantage") end)
G.add("warmup", "check", "Warmup AA", "Angles", "Options", nil, false)
G.add("warmup_pitch", "combo", "Pitch", "Angles", "Options", {"Disabled", "Down", "Fake Up", "Fake Down", "Random"}, "Disabled", function() return G.get("warmup") end)
G.add("warmup_yaw", "combo", "Yaw", "Angles", "Options", {"Spin", "Distortion", "L&R"}, "Spin", function() return G.get("warmup") end)
G.add("warmup_range", "slider", "Range", "Angles", "Options", {0, 360}, 360, function() return G.get("warmup") and G.get("warmup_yaw") ~= "L&R" end)
G.add("warmup_speed", "slider", "Speed", "Angles", "Options", {0, 100, unit = "%"}, 50, function() return G.get("warmup") and G.get("warmup_yaw") ~= "L&R" end)
G.add("warmup_left", "slider", "Left", "Angles", "Options", {-180, 180}, 0, function() return G.get("warmup") and G.get("warmup_yaw") == "L&R" end)
G.add("warmup_right", "slider", "Right", "Angles", "Options", {-180, 180}, 0, function() return G.get("warmup") and G.get("warmup_yaw") == "L&R" end)

G.add("other_page", "combo", "Other", "Other", nil, {"Animations", "Movement", "Visuals", "Log Events", "Shared ESP"}, "Visuals")
G.add("move_lean", "slider", "Move Lean", "Other", "Animations", {-1, 100, tips = {[-1] = "Disabled"}, unit = "%"}, 0)
G.add("jitter_legs", "check", "Jitter Legs", "Other", "Animations", nil, false)
G.add("animation_note", "label", "Move Lean needs gamesense/entity.", "Other", "Animations", nil, nil, function() return not G.entity_lib end)
G.add("fast_ladder", "check", "Fast Ladder", "Other", "Movement", nil, false)
G.add("no_fall_damage", "check", "No Fall Damage", "Other", "Movement", nil, false)
G.add("grenade_release", "check", "Grenade Release", "Other", "Movement", nil, false)
G.add("grenade_damage", "slider", "Damage", "Other", "Movement", {1, 50}, 33, function() return G.get("grenade_release") end)
G.add("increase_speed", "check", "Increase speed", "Other", "Movement", nil, false)
G.add("movement_note", "label", "No Fall Damage / Grenade Release need gamesense/trace.", "Other", "Movement", nil, nil, function() return not (G.trace_lib and G.vector_lib) end)
G.add("viewmodel_header", "label", "\a9CA7E1FFViewmodel", "Other", "Visuals")
G.add("vm_fov", "slider", "Field of View", "Other", "Visuals", {0, 1000, scale = .1}, math.floor(cvar.viewmodel_fov:get_float() * 10))
G.add("vm_x", "slider", "Offset X", "Other", "Visuals", {-100, 100, scale = .1}, math.floor(cvar.viewmodel_offset_x:get_float() * 10))
G.add("vm_y", "slider", "Offset Y", "Other", "Visuals", {-100, 100, scale = .1}, math.floor(cvar.viewmodel_offset_y:get_float() * 10))
G.add("vm_z", "slider", "Offset Z", "Other", "Visuals", {-100, 100, scale = .1}, math.floor(cvar.viewmodel_offset_z:get_float() * 10))
G.add("knife_hand", "check", "Opposite Knife Hand", "Other", "Visuals", nil, false)
G.add("aspect", "slider", "Aspect Ratio", "Other", "Visuals", {1, 200, scale = .01}, 133)
G.add("scope_overlay", "check", "Scope Overlay", "Other", "Visuals", nil, false)
G.add("scope_type", "combo", "Color", "Other", "Visuals", {"Simple", "Double"}, "Simple", function() return G.get("scope_overlay") end)
G.add("scope_simple", "color", "Simple", "Other", "Visuals", nil, {255, 255, 255, 155}, function() return G.get("scope_overlay") and G.get("scope_type") == "Simple" end)
G.add("scope_a", "color", "Double [1]", "Other", "Visuals", nil, {255, 255, 255, 255}, function() return G.get("scope_overlay") and G.get("scope_type") == "Double" end)
G.add("scope_b", "color", "Double [2]", "Other", "Visuals", nil, {0, 0, 0, 0}, function() return G.get("scope_overlay") and G.get("scope_type") == "Double" end)
G.add("scope_length", "slider", "Length", "Other", "Visuals", {5, 300}, 180, function() return G.get("scope_overlay") end)
G.add("scope_offset", "slider", "Offset", "Other", "Visuals", {1, 100}, 5, function() return G.get("scope_overlay") end)
G.add("hit_marker", "multi", "Hit Marker", "Other", "Visuals", {"Crosshair", "3D"}, {})
G.add("crosshair_time", "slider", "Crosshair Time", "Other", "Visuals", {3, 100, scale = .1, unit = "s", tips = {[3] = "GameSense"}}, 3, function() return G.has(G.get("hit_marker"), "Crosshair") end)
G.add("world_time", "slider", "3D Time", "Other", "Visuals", {3, 100, scale = .1, unit = "s"}, 20, function() return G.has(G.get("hit_marker"), "3D") end)
G.add("world_color", "color", "3D Color", "Other", "Visuals", nil, {255, 255, 255, 255}, function() return G.has(G.get("hit_marker"), "3D") end)
G.add("manual_arrows", "check", "Manual Arrows", "Other", "Visuals", nil, false)
G.add("arrows_font", "combo", "Font", "Other", "Visuals", {"Default", "Small", "Console", "Bold"}, "Default", function() return G.get("manual_arrows") end)
G.add("left_symbol", "text", "Left Symbol", "Other", "Visuals", nil, "<", function() return G.get("manual_arrows") end)
G.add("right_symbol", "text", "Right Symbol", "Other", "Visuals", nil, ">", function() return G.get("manual_arrows") end)
G.add("forward_symbol", "text", "Forward Symbol", "Other", "Visuals", nil, "^", function() return G.get("manual_arrows") end)
G.add("arrows_offset", "slider", "Offset", "Other", "Visuals", {0, 120}, 60, function() return G.get("manual_arrows") end)
G.add("arrows_color", "color", "Arrow Color", "Other", "Visuals", nil, {255, 255, 255, 255}, function() return G.get("manual_arrows") end)
G.add("keep_transparency", "check", "Keep Model Transparency", "Other", "Visuals", nil, false)
G.add("transparency_note", "label", "Model alpha approximation; chams can override it.", "Other", "Visuals", nil, nil, function() return G.get("keep_transparency") end)
G.add("extended_ping", "check", "Extended Ping Spike", "Other", "Visuals", nil, false)
G.add("fake_latency", "slider", "Fake Latency", "Other", "Visuals", {0, 200, unit = "ms"}, 0, function() return G.get("extended_ping") end)
G.add("ping_key", "hotkey", "Fake Latency key", "Other", "Visuals", nil, nil, function() return G.get("extended_ping") end)
ui.set(G.controls.ping_key.ref, "Always on")
G.add("log_prefix", "color", "Prefix", "Other", "Log Events", nil, {222, 137, 137, 255})
G.add("log_main", "color", "Main", "Other", "Log Events", nil, {150, 176, 186, 255})
G.add("purchases", "check", "Purchases", "Other", "Log Events", nil, false)
G.add("damage_dealt", "check", "Damage Dealt", "Other", "Log Events", nil, false)
G.add("shared_esp", "check", "Shared ESP", "Other", "Shared ESP", nil, false, function() return (G.refs.shared or {})[1] ~= nil end)
G.add("shared_note", "label", "Uses native GameSense Shared ESP when available.", "Other", "Shared ESP")
G.add("shared_note2", "label", "Gazolina voice packets have no public GameSense API.", "Other", "Shared ESP")
G.add("shared_note3", "label", "Apply GS Shared ESP is handled by GameSense itself.", "Other", "Shared ESP")

G.add("presets_header", "label", "\a9CA7E1FFPresets", "Presets")
G.add("preset_export", "button", "Export", "Presets")
G.add("preset_import", "button", "Import", "Presets")
G.add("preset_new", "button", "New", "Presets")
G.add("preset_sort", "button", "Sort", "Presets")
G.add("preset_search", "text", "Search", "Presets", nil, nil, "")
G.add("preset_list", "list", "Configs", "Presets", nil, {"(empty)"})
G.add("preset_name", "text", "Name", "Presets", nil, nil, "")
G.add("preset_save", "button", "Save", "Presets")
G.add("preset_load", "button", "Load", "Presets")
G.add("preset_delete", "button", "Delete", "Presets")
G.add("preset_info", "label", "Author: -\nUpdated: -", "Presets")
G.add("preset_note", "label", "Clipboard actions need gamesense/clipboard.", "Presets", nil, nil, nil, function() return not G.clipboard end)
G.storage = ui.new_string("Gazolina421_profiles_v1", "")

for _, team in ipairs(G.teams) do
    G.profiles[team] = {}
    for _, state in ipairs(G.states) do G.profiles[team][state] = G.profile_default() end
end

-- Versioned, validated JSON presets; no eval/loadstring is used on imports.
G.non_setting = {title=true, master=true, activation=true, page=true, angles_page=true,
    other_page=true, team=true, state=true, preset_search=true, preset_name=true,
    preset_list=true, manual_yaw=false}
function G.setting(c, key)
    return not c.profile and not G.non_setting[key] and
        c.kind ~= "label" and c.kind ~= "button" and c.kind ~= "hotkey" and c.kind ~= "list"
end
function G.validate_value(key, value)
    local c = G.controls[key]
    if c.kind == "check" then
        if type(value) ~= "boolean" then error("Invalid checkbox: " .. key) end
        return value
    end
    if c.kind == "slider" then
        if type(value) ~= "number" or value ~= value or value == math.huge or value == -math.huge then error("Invalid number: " .. key) end
        return G.clamp(math.floor(value + .5), c.opts[1], c.opts[2])
    end
    if c.kind == "combo" then
        if not G.has(c.opts, value) then error("Invalid selection: " .. key) end
        return value
    end
    if c.kind == "multi" then
        if type(value) ~= "table" then error("Invalid selection list: " .. key) end
        local result = {}
        for _, option in ipairs(c.opts) do if G.has(value, option) then result[#result+1] = option end end
        return result
    end
    if c.kind == "color" then
        if type(value) ~= "table" or #value ~= 4 then error("Invalid color: " .. key) end
        local out = {}
        for i=1,4 do
            if type(value[i]) ~= "number" or value[i] ~= value[i] then error("Invalid color: " .. key) end
            out[i] = G.clamp(math.floor(value[i]), 0, 255)
        end
        return out
    end
    if c.kind == "text" then
        if type(value) ~= "string" or #value > 256 then error("Invalid text: " .. key) end
        return value
    end
    error("Invalid setting: " .. key)
end
function G.valid_profile(input)
    if type(input) ~= "table" then error("Invalid state profile") end
    local p = G.profile_default()
    for _, key in ipairs(G.profile_schema) do
        if input[key] ~= nil then p[key] = G.validate_value(key, input[key]) end
    end
    return p
end
function G.snapshot()
    G.save_editor()
    local config = {format="gazolina-gamesense", version=G.version, profiles=G.copy(G.profiles), settings={}}
    for key, c in pairs(G.controls) do if G.setting(c, key) then config.settings[key] = G.copy(G.get(key)) end end
    return config
end
function G.apply_snapshot(input)
    if type(input) ~= "table" or input.format ~= "gazolina-gamesense" or input.version ~= G.version then
        error("Unsupported preset. Use a Gazolina GameSense v1 preset; Neverlose presets use a different format.")
    end
    if type(input.profiles) ~= "table" or type(input.settings) ~= "table" then error("Incomplete preset") end
    local profiles, settings = {}, {}
    for _, team in ipairs(G.teams) do
        if type(input.profiles[team]) ~= "table" then error("Missing team " .. team) end
        profiles[team] = {}
        for _, state in ipairs(G.states) do profiles[team][state] = G.valid_profile(input.profiles[team][state]) end
    end
    for key, c in pairs(G.controls) do
        if G.setting(c, key) and input.settings[key] ~= nil then settings[key] = G.validate_value(key, input.settings[key]) end
    end
    -- Validation completes before mutating any live setting.
    local old = G.loading; G.loading = true
    G.profiles = profiles
    for key, value in pairs(settings) do G.set(key, value) end
    G.load_editor(); G.loading = old
    G.restore_refs(); G.restore_cvars()
    G.runtime.brute_until = 0; G.runtime.unlock_command = 0; G.runtime.locked = nil
    G.runtime.last_manual = G.get("manual_yaw")
    G.visibility()
end
function G.decode(text)
    if type(text) ~= "string" or #text > 524288 then error("Invalid or oversized preset") end
    text = text:gsub("^GAZOLINA_GS1:", "")
    local input = json.parse(text)
    if type(input) ~= "table" then error("Invalid JSON preset") end
    return input
end
function G.guarded(fn)
    local ok, err = pcall(fn)
    if not ok then G.log(err, true) end
    return ok
end
function G.clip_get()
    if not G.clipboard then error("Install gamesense/clipboard for clipboard actions") end
    return G.clipboard.get()
end
function G.clip_set(text)
    if not G.clipboard then error("Install gamesense/clipboard for clipboard actions") end
    G.clipboard.set(text)
end
G.presets = database.read(G.db_key .. "_presets") or {}
if type(G.presets) ~= "table" then G.presets = {} end
function G.date()
    local h, m, s = client.system_time()
    return string.format("%02d:%02d:%02d (%s)", h, m, s, tostring(client.unix_time()))
end
function G.selected_preset() return G.preset_names[G.get("preset_list") + 1] end
function G.preset_info()
    local name = G.selected_preset()
    local p = name and G.presets[name]
    G.set("preset_info", p and ("Author: " .. tostring(p.author) .. "\nUpdated: " .. tostring(p.date)) or "Author: -\nUpdated: -")
end
function G.update_presets()
    local names, search = {}, G.get("preset_search"):lower()
    for name in pairs(G.presets) do
        if name:lower():find(search, 1, true) then names[#names+1] = name end
    end
    table.sort(names, function(a,b) if G.sort_desc then return a:lower() > b:lower() end; return a:lower() < b:lower() end)
    G.preset_names = names
    ui.update(G.controls.preset_list.ref, #names > 0 and names or {"(empty)"})
    G.preset_info()
end
function G.persist()
    local data = G.snapshot()
    ui.set(G.storage, json.stringify(data))
    database.write(G.db_key .. "_current", data)
    database.write(G.db_key .. "_presets", G.presets)
end
function G.save_preset()
    local name = G.get("preset_name"):match("^%s*(.-)%s*$")
    if name == "" or #name > 64 then error("Failed to save config. (Invalid name)") end
    local me = entity.get_local_player()
    G.presets[name] = {author=me and entity.get_player_name(me) or "local", date=G.date(), config=G.snapshot()}
    database.write(G.db_key .. "_presets", G.presets)
    G.update_presets()
    for i, n in ipairs(G.preset_names) do if n == name then G.set("preset_list", i-1) end end
    G.preset_info(); G.log("Successfully saved config (" .. name .. ")")
end
G.actions = {
    toggle = function() G.set("master", not G.get("master")) end,
    copy = function() G.guarded(function()
        G.save_editor(); G.clip_set("GAZOLINA_STATE1:" .. json.stringify(G.profile())); G.log("Copied current state into clipboard.")
    end) end,
    paste = function() G.guarded(function()
        local data = G.clip_get()
        if type(data) ~= "string" or not data:find("^GAZOLINA_STATE1:") or #data > 32768 then error("Invalid state clipboard data") end
        local p = G.valid_profile(json.parse(data:sub(17)))
        G.profiles[G.editor_team][G.editor_state] = p; G.load_editor(); G.visibility()
        G.log("Imported data into selected state.")
    end) end,
    opposite = function()
        G.save_editor(); local other = G.editor_team == "T" and "CT" or "T"
        G.profiles[other][G.editor_state] = G.copy(G.profile())
        G.log("Sent " .. G.editor_state .. " settings to " .. other)
    end,
    shuffle_delay = function() for i=1,G.get("delay_custom_sliders") do G.set("delay_" .. i, G.random(1,10)) end end,
    shuffle_modifier = function() for i=1,G.get("randomize_custom_sliders") do G.set("randomize_" .. i, G.random(-30,30)) end end,
    shuffle_choke = function() for i=1,G.get("choke_sliders") do G.set("choke1_" .. i, G.random(1,32)) end end,
    preset_new = function() G.guarded(G.save_preset) end,
    preset_save = function() G.guarded(G.save_preset) end,
    preset_load = function() G.guarded(function()
        local name = G.selected_preset(); if not name then error("No preset selected") end
        G.apply_snapshot(G.presets[name].config); G.log("Successfully loaded config (" .. name .. ")")
    end) end,
    preset_delete = function() G.guarded(function()
        local name = G.selected_preset(); if not name then error("No preset selected") end
        G.presets[name] = nil; database.write(G.db_key .. "_presets", G.presets)
        G.update_presets(); G.log("Successfully deleted config (" .. name .. ")")
    end) end,
    preset_export = function() G.guarded(function()
        local name = G.selected_preset(); if not name then error("No preset selected") end
        G.clip_set("GAZOLINA_GS1:" .. json.stringify(G.presets[name].config))
        G.log("Successfully exported config (" .. name .. ")")
    end) end,
    preset_import = function() G.guarded(function()
        G.apply_snapshot(G.decode(G.clip_get())); G.log("Successfully imported preset. Use Save to keep a named copy.")
    end) end,
    preset_sort = function() G.sort_desc = not G.sort_desc; G.update_presets() end,
}

-- Minimal vector helpers for public GameSense entity/trace API calls.
function G.vec(x,y,z) return {x=x or 0, y=y or 0, z=z or 0} end
function G.pos(ent) local x,y,z=entity.get_origin(ent); if x then return G.vec(x,y,z) end end
function G.vel(ent) return G.vec(entity.get_prop(ent, "m_vecVelocity")) end
function G.addv(a,b) return G.vec(a.x+b.x,a.y+b.y,a.z+b.z) end
function G.subv(a,b) return G.vec(a.x-b.x,a.y-b.y,a.z-b.z) end
function G.mulv(a,b) return G.vec(a.x*b,a.y*b,a.z*b) end
function G.dot(a,b) return a.x*b.x+a.y*b.y+a.z*b.z end
function G.length(a) return math.sqrt(G.dot(a,a)) end
function G.eye(ent)
    local p = G.pos(ent); if not p then return end
    return G.addv(p,G.vec(entity.get_prop(ent,"m_vecViewOffset")))
end
function G.trace_hull(a,b,mins,maxs,skip,mask)
    if not (G.trace_lib and G.vector_lib) then return end
    local v = G.vector_lib
    local tr = G.trace_lib.hull(v(a.x,a.y,a.z),v(b.x,b.y,b.z),v(mins.x,mins.y,mins.z),v(maxs.x,maxs.y,maxs.z),{skip=skip,mask=mask})
    if not tr then return end
    local n = tr.plane and tr.plane.normal or G.vec(0,0,1)
    local ep = tr.end_pos or G.addv(a,G.mulv(G.subv(b,a),tr.fraction))
    return {fraction=tr.fraction,end_pos=G.vec(ep.x,ep.y,ep.z),normal=G.vec(n.x,n.y,n.z),
        start_solid=tr.start_solid or tr.startsolid,all_solid=tr.all_solid or tr.allsolid,entity=tr.entity or tr.entindex}
end
function G.trace_line(a,b,skip)
    local f, ent = client.trace_line(skip or -1,a.x,a.y,a.z,b.x,b.y,b.z)
    return {fraction=f,entity=ent,end_pos=G.addv(a,G.mulv(G.subv(b,a),f))}
end
function G.weapon_info(weapon)
    if not weapon then return {} end
    local id=bit.band(G.prop(weapon,"m_iItemDefinitionIndex",0),65535)
    if G.weapons then return G.weapons[id] or {} end
    return {}
end
function G.threat(me)
    if client.current_threat then local p=client.current_threat(); if p then return p end end
    local best,dist; local origin=G.pos(me); if not origin then return end
    for _,p in ipairs(entity.get_players(true)) do
        local pos=G.pos(p)
        if pos then local d=G.length(G.subv(pos,origin)); if not dist or d<dist then best,dist=p,d end end
    end
    return best
end
function G.update_manual()
    local r=G.runtime
    local keys={manual_left="Left",manual_right="Right",manual_forward="Forward",manual_reset="Disabled"}
    for key,dir in pairs(keys) do
        local down=G.get(key)
        if down and not r.manual_keys[key] then
            G.set("manual_yaw",G.get("manual_yaw")==dir and "Disabled" or dir)
        end
        r.manual_keys[key]=down
    end
    r.last_manual=G.get("manual_yaw")
end
function G.current_state(me,cmd)
    local duck=G.prop(me,"m_flDuckAmount",0)
    local on_ground=bit.band(G.prop(me,"m_fFlags",0),1)~=0 and cmd.in_jump~=1
    if G.get("manual_yaw")~="Disabled" then return "Manuals" end
    if G.get("safe_head") then
        local conditions=G.get("safe_conditions")
        local weapon=entity.get_player_weapon(me)
        local class=weapon and entity.get_classname(weapon) or ""
        local safe=(not on_ground and duck>0 and G.has(conditions,"Air Crouch")) or
            (on_ground and duck>0 and G.has(conditions,"Crouching")) or
            (class=="CWeaponTaser" and G.has(conditions,"Taser")) or
            ((class=="CKnife" or class=="CKnifeGG") and G.has(conditions,"Knife"))
        if not safe and G.has(conditions,"Height Advantage") then
            local threat=G.threat(me); local a=G.pos(me); local b=threat and G.pos(threat)
            safe=a and b and a.z-b.z>=G.get("safe_height")
        end
        if safe then return "Safe Head" end
    end
    if not on_ground then return duck>0 and "Air Crouching" or "Air" end
    if G.active_ref("slow") then return "Slowing" end
    local v=G.vel(me); local speed=math.sqrt(v.x*v.x+v.y*v.y)
    if speed<5 then return duck>0 and "Crouching" or "Standing" end
    return duck>0 and "Sneaking" or "Running"
end
function G.is_warmup()
    if not G.get("warmup") then return false end
    local rules=entity.get_game_rules()
    if rules and G.prop(rules,"m_bWarmupPeriod",0)==1 then return true end
    return #entity.get_players(true)==0
end
function G.anti_backstab(me,ctx)
    local origin=G.pos(me); if not origin then return end
    for _,enemy in ipairs(entity.get_players(true)) do
        local weapon=entity.get_player_weapon(enemy)
        local class=weapon and entity.get_classname(weapon)
        local pos=G.pos(enemy)
        if pos and (class=="CKnife" or class=="CKnifeGG") and G.length(G.subv(pos,origin))<180 then
            ctx.yaw_base="At targets"; ctx.offset=180; ctx.modifier="Disabled"; ctx.freestanding=false; return
        end
    end
end
function G.aa(me,cmd)
    local r=G.runtime
    local state=G.current_state(me,cmd)
    local team=G.prop(me,"m_iTeamNum",0)==2 and "T" or "CT"
    local p=G.profiles[team][state]
    local sent=cmd.chokedcommands==0
    if sent then r.sent=r.sent+1 end
    local ctx={pitch="Down",yaw_base="At targets",offset=0,modifier=p.yaw_modifier,
        modifier_offset=p.modifier_offset,body=p.body_yaw,freestanding=false}
    if p.yaw==1 then
        if p.apply_delay then
            if sent then
                local delay=p.delay_default
                if p.delay_method=="Random" then delay=G.random(p.delay_random_min,p.delay_random_max)
                elseif p.delay_method=="Ways" then delay=p["delay_"..G.random(1,p.delay_custom_sliders)] end
                if r.sent-r.last_flip>=delay then r.side=not r.side; r.last_flip=r.sent end
            end
            ctx.offset=r.side and p.left_yaw or p.right_yaw
            if G.active_ref("duck") then ctx.offset=ctx.offset/2 end
        else
            r.side=(G.prop(me,"m_flPoseParameter",.5,11)*120-60)>0
            ctx.offset=r.side and p.left_yaw or p.right_yaw
        end
    else ctx.offset=p.yaw_offset end
    if p.randomize_modifier then
        ctx.modifier_offset=p.randomize_mode=="Ways" and p["randomize_"..G.random(1,p.randomize_custom_sliders)] or G.random(p.randomize_min,p.randomize_max)
    end
    if not G.active_ref("duck") and p.body_yaw then
        if p.mode=="Ticks" then ctx.body=globals.tickcount()%p.mode_ticks>1
        elseif p.mode=="Random" then ctx.body=G.random(0,p.mode_random)==p.mode_random end
    end
    if not p.apply_delay then
        if p.body_jitter then if sent then r.side=not r.side end
        else r.side=p.inverter end
    end
    local left,right=p.left_limit,p.right_limit
    if p.limit_mode=="Switch" then left=globals.tickcount()%4>1 and p.from_limit or p.to_limit; right=left
    elseif p.limit_mode=="Random" then left=G.random(0,1)==1 and p.from_limit or p.to_limit; right=G.random(0,1)==1 and p.from_limit or p.to_limit end
    ctx.limit=r.side and left or right
    ctx.side=r.side
    if G.is_warmup() then
        local pitch=G.get("warmup_pitch")
        if pitch=="Random" then pitch=({"Disabled","Down","Fake Up","Fake Down"})[G.random(1,4)] end
        ctx.pitch=pitch; ctx.body=false; ctx.modifier="Disabled"; ctx.modifier_offset=0
        local mode=G.get("warmup_yaw"); local speed=G.get("warmup_speed"); local range=G.get("warmup_range")
        if mode=="L&R" then ctx.offset=r.side and G.get("warmup_left") or G.get("warmup_right")
        elseif mode=="Distortion" then r.warmup_offset=r.warmup_offset+globals.tickinterval()*speed; ctx.offset=math.sin(r.warmup_offset)*range
        else r.warmup_offset=r.warmup_offset+speed/100*14; ctx.offset=range>0 and r.warmup_offset%range or 0 end
        G.release("dt_fl")
    else
        if G.get("anti_bruteforce") and G.has(G.get("brute_states"),state) and globals.realtime()<r.brute_until then
            ctx.offset=ctx.offset+(r.side and r.brute_offset or -r.brute_offset)
        end
        G.defensive(me,cmd,p,state)
        local fs=G.get("freestanding") and G.get("fs_key") and not G.has(G.get("fs_disablers"),state)
        ctx.freestanding=fs
        if fs and G.get("fs_modifiers") then ctx.modifier="Disabled" end
        if state=="Manuals" then
            ctx.offset=({Left=-90,Right=90,Forward=180})[G.get("manual_yaw")] or 0
            ctx.yaw_base=G.get("manual_base")=="At Target" and "At targets" or "Local view"
            if G.get("prefer_manual") then ctx.freestanding=false end
        end
    end
    G.anti_backstab(me,ctx)
    G.apply_aa(ctx,cmd)
end
function G.defensive(me,cmd,p,state)
    local r=G.runtime; local weapon=entity.get_player_weapon(me)
    if not weapon or not G.has(G.get("break_lc"),state) or G.prop(weapon,"m_fThrowTime",0)~=0 then G.release("dt_fl"); r.last_weapon=weapon; return end
    local force=false
    if p.defensive_choke=="Default" then force=true
    else
        local interval=p.choke_slider
        if p.random_choke then
            interval=p.choke_method=="Custom" and p["choke1_"..G.random(1,p.choke_sliders)] or G.random(p.choke_from,p.choke_to)
        end
        force=globals.tickcount()%math.max(1,interval)==0
    end
    local triggers=G.get("break_triggers")
    if G.has(triggers,"Weapon Swap") and r.last_weapon and weapon~=r.last_weapon then force=true end
    local reload=G.prop(weapon,"m_bInReload",0)==1 or (cmd.in_reload==1)
    if G.has(triggers,"Weapon Reload") and reload then force=true end
    r.last_weapon=weapon
    -- GameSense exposes the force_defensive usercmd flag; it cannot reproduce
    -- Neverlose's internal exploit charge or its three Hide Shots policies.
    if G.active_ref("dt") or G.active_ref("hs") then
        cmd.force_defensive=force
        local policy=G.get("hide_shots")
        if policy=="Favor Fake Lag" then G.override("dt_fl",1,2)
        elseif policy=="Break LC" then cmd.force_defensive=true; G.override("dt_fl",1,1)
        else G.release("dt_fl") end
    else G.release("dt_fl") end
end
function G.apply_aa(ctx,cmd)
    local offset=ctx.offset
    local modifier=ctx.modifier
    local tick=G.runtime.sent
    if modifier=="3-Way" or modifier=="5-Way" then
        local count=modifier=="3-Way" and 3 or 5
        offset=offset+((tick%count)/(count-1)-.5)*ctx.modifier_offset
        modifier="Disabled"
    elseif modifier=="Spin" then
        offset=offset+(globals.curtime()*ctx.modifier_offset*8)%360
        modifier="Disabled"
    end
    G.override("enabled",1,true)
    local pitches={Disabled="Off",Down="Down",["Fake Up"]="Up",["Fake Down"]="Down"}
    G.override("pitch",1,pitches[ctx.pitch] or "Down")
    G.override("yaw_base",1,ctx.yaw_base)
    G.override("yaw",1,"180")
    G.override("yaw",2,G.yaw(offset))
    local modifiers={Disabled="Off",Center="Center",Offset="Offset",Random="Random"}
    G.override("jitter",1,modifiers[modifier] or "Off")
    G.override("jitter",2,ctx.modifier_offset)
    -- NL limits are 0..60; GS body-yaw offsets are 0..180. The fake-yaw
    -- limit is set separately when exposed by the running GS build.
    G.override("body",1,ctx.body and "Static" or "Off")
    G.override("body",2,ctx.body and (ctx.side and -1 or 1)*math.floor(ctx.limit*3) or 0)
    G.override("fake_limit",1,G.clamp(math.floor(ctx.limit),0,60))
    G.override("fs_body",1,ctx.freestanding and G.get("fs_body") or false)
    if (G.refs.freestanding or {})[1] then
        if type(ui.get(G.refs.freestanding[1]))=="boolean" then G.override("freestanding",1,ctx.freestanding)
        else G.override("freestanding",1,ctx.freestanding and {"Default"} or {},"multi") end
    end
    if (G.refs.freestanding or {})[2] then
        G.override("freestanding",2,ctx.freestanding and "Always on" or "On hotkey","hotkey")
    end
end

function G.fast_ladder(me,cmd)
    if not G.get("fast_ladder") or cmd.in_use==1 or G.prop(me,"m_MoveType",0)~=9 then return end
    local weapon=entity.get_player_weapon(me)
    if weapon and G.prop(weapon,"m_fThrowTime",0)~=0 then return end
    local x,y=entity.get_prop(me,"m_vecLadderNormal")
    if not x or not y then return end
    local normal_yaw=math.deg(math.atan2(y,x))
    local angle=G.yaw(normal_yaw-cmd.yaw)
    if angle>-60 and angle<60 then
        if cmd.forwardmove~=0 then
            local back=cmd.forwardmove<0
            cmd.in_back=back and 1 or 0; cmd.in_forward=back and 0 or 1
            cmd.in_moveleft=back and 1 or 0; cmd.in_moveright=back and 0 or 1
            cmd.pitch=89; cmd.yaw=G.yaw(normal_yaw+90)
        end
    else
        cmd.yaw=math.floor(cmd.yaw+.5)
        if cmd.forwardmove>0 then
            cmd.pitch=89; cmd.in_moveright=0; cmd.in_moveleft=1; cmd.in_forward=0; cmd.in_back=1
            cmd.yaw=G.yaw(cmd.yaw-(cmd.sidemove==0 and 90 or (cmd.sidemove<0 and 30 or 150)))
        elseif cmd.forwardmove<0 then
            cmd.pitch=89; cmd.in_moveleft=0; cmd.in_moveright=1; cmd.in_forward=1; cmd.in_back=0
            cmd.yaw=G.yaw(cmd.yaw-(cmd.sidemove==0 and 90 or (cmd.sidemove>0 and 30 or 150)))
        end
    end
end
function G.no_fall_damage(me,cmd)
    if not G.get("no_fall_damage") or not (G.trace_lib and G.vector_lib) then return end
    if bit.band(G.prop(me,"m_fFlags",0),1)~=0 or G.prop(me,"m_MoveType",0)~=2 then return end
    local v=G.vel(me); if v.z>=0 then return end
    local pos=G.pos(me); if not pos then return end
    if bit.band(G.prop(me,"m_fFlags",0),2)==0 then pos.z=pos.z+9 end
    local mins=G.vec(entity.get_prop(me,"m_vecMins"))
    local maxs=G.vec(entity.get_prop(me,"m_vecMaxs")); maxs.z=54
    local tr=G.trace_hull(pos,G.subv(pos,G.vec(0,0,1000)),mins,maxs,me,1)
    if not tr or tr.fraction>=1 or tr.start_solid or tr.all_solid or tr.normal.z<.7 then return end
    local distance=tr.fraction*1000
    if distance>=11 then
        local height,velocity=distance,v.z
        local dt=globals.tickinterval(); local gravity=cvar.sv_gravity:get_float()*dt*.5
        -- Bounded simulation also handles unusual server gravity values.
        for _=1,512 do
            if height<=11 then break end
            velocity=velocity-gravity; height=height+dt*velocity
        end
        if velocity<=-580 and height>=9 and height<=11 then cmd.in_duck=1; cmd.in_jump=0 end
    elseif v.z<-580 and distance>9 then cmd.in_jump=1; cmd.in_duck=0 end
end
function G.fakeduck_speed(me,cmd)
    if not G.get("increase_speed") or not G.active_ref("duck") then return end
    local weapon=entity.get_player_weapon(me); if not weapon then return end
    local info=G.weapon_info(weapon)
    local speed=math.sqrt(cmd.forwardmove^2+cmd.sidemove^2)
    local limit=(info.max_player_speed_alt or info.max_player_speed or 240)*.5
    if speed>3 then local factor=math.min(1,limit/speed); cmd.forwardmove=cmd.forwardmove*factor; cmd.sidemove=cmd.sidemove*factor end
end

-- Grenade Release: Source-style projectile simulation using gamesense/trace.
-- Player extrapolation approximates Neverlose simulate_movement; no native
-- prediction context or jitter_move field is exposed by public GameSense.
function G.near_fire(from,to)
    local delta=G.subv(from,to)
    if delta.z<=-64 or delta.z>=120 then return false end
    local limit=10000
    if delta.z>72 then limit=limit-5.42534722222*(delta.z-72)^2
    elseif delta.z<18 then limit=limit-.90957763236*(18-delta.z)^2 end
    return delta.x^2+delta.y^2<=limit
end
function G.grenade_start(me,weapon,cmd,delay)
    local dt=globals.tickinterval(); local origin=G.pos(me); if not origin then return end
    local velocity=G.vel(me)
    local mins=G.vec(entity.get_prop(me,"m_vecMins")); local maxs=G.vec(entity.get_prop(me,"m_vecMaxs"))
    local on_ground=bit.band(G.prop(me,"m_fFlags",0),1)~=0
    for _=1,delay do
        if not on_ground then velocity.z=velocity.z-cvar.sv_gravity:get_float()*dt end
        local next_pos=G.addv(origin,G.mulv(velocity,dt))
        local tr=G.trace_hull(origin,next_pos,mins,maxs,me,0x200400B)
        if tr then
            origin=tr.end_pos
            if tr.fraction<1 then
                velocity=G.subv(velocity,G.mulv(tr.normal,G.dot(velocity,tr.normal)))
                if tr.normal.z>.7 then on_ground=true end
            end
        else origin=next_pos end
    end
    local strength=G.clamp(G.prop(weapon,"m_flThrowStrength",1),0,1)
    local pitch=G.yaw(cmd.pitch)
    pitch=pitch-(90-math.abs(pitch))*10/90
    local p,y=math.rad(pitch),math.rad(cmd.yaw)
    local fwd=G.vec(math.cos(p)*math.cos(y),math.cos(p)*math.sin(y),-math.sin(p))
    origin.z=origin.z+G.prop(me,"m_vecViewOffset[2]",G.prop(me,"m_flDuckAmount",0)>.5 and 46 or 64)+strength*12-12
    local tr=G.trace_hull(origin,G.addv(origin,G.mulv(fwd,22)),G.vec(-2,-2,-2),G.vec(2,2,2),me,33570827)
    if not tr then return end
    local pos=G.subv(tr.end_pos,G.mulv(fwd,6))
    local info=G.weapon_info(weapon)
    local throw_speed=G.clamp((info.throw_velocity or 750)*.9,15,750)
    local vel=G.addv(G.mulv(fwd,throw_speed*(strength*.7+.3)),G.mulv(velocity,1.25))
    return pos,vel
end
function G.grenade_predict(pos,velocity,id,me)
    local dt=globals.tickinterval(); local gravity=cvar.sv_gravity:get_float()*.4
    local detonate=cvar.molotov_throw_detonate_time and cvar.molotov_throw_detonate_time:get_float() or 3.5
    local slope=cvar.weapon_molotov_maxdetonateslope and cvar.weapon_molotov_maxdetonateslope:get_float() or 30
    local ground=id~=46
    for tick=0,256 do
        if G.length(velocity)<.1 then break end
        local move=G.vec(velocity.x*dt,velocity.y*dt,(velocity.z-gravity*dt*.5)*dt)
        velocity.z=velocity.z-gravity*dt
        local tr=G.trace_hull(pos,G.addv(pos,move),G.vec(-2,-2,-2),G.vec(2,2,2),me,0x4600400B)
        if not tr then return end
        if tr.start_solid or tr.all_solid then return end
        pos=tr.end_pos
        if tr.fraction<1 then
            if id==46 and tr.normal.z>math.cos(math.rad(slope)) then return pos,true,tick end
            local elasticity=.45
            local hit=tr.entity
            if type(hit)=="number" and hit>0 and entity.get_classname(hit)=="CCSPlayer" then elasticity=elasticity*.3; velocity=G.mulv(velocity,.2) end
            velocity=G.mulv(G.subv(velocity,G.mulv(tr.normal,G.dot(velocity,tr.normal)*2)),elasticity)
            if math.abs(velocity.x)<.1 then velocity.x=0 end
            if math.abs(velocity.y)<.1 then velocity.y=0 end
            if math.abs(velocity.z)<.1 then velocity.z=0 end
            local speed=G.dot(velocity,velocity)
            if tr.normal.z>.7 then
                if speed>96000 then
                    local dot=G.dot(G.mulv(velocity,1/math.sqrt(speed)),tr.normal)
                    if dot>.5 then velocity=G.mulv(velocity,1.5-dot) end
                end
                if speed<400 then velocity=G.vec() end
            end
            if speed>=400 then
                local rest=G.trace_hull(pos,G.addv(pos,G.mulv(velocity,(1-tr.fraction)*dt)),G.vec(-2,-2,-2),G.vec(2,2,2),me,0x4600400B)
                if rest then pos=rest.end_pos end
            end
        end
        if (id==44 and (tick-1)*dt>1.5 and tick%math.max(1,math.floor(.2/dt+.5))==0) or (id==46 and (tick-1)*dt>detonate) then break end
    end
    local distance=({[44]=24,[45]=0,[46]=128})[id] or 0
    if distance>0 then
        local tr=G.trace_line(pos,G.subv(pos,G.vec(0,0,distance)),me)
        if tr.fraction<1 then pos=tr.end_pos; ground=true end
    end
    return pos,ground,0
end
function G.grenade_impact(pos,id,me)
    if id==45 then
        for _,fire in ipairs(entity.get_all("CInferno")) do local p=G.pos(fire); if p and G.near_fire(p,pos) then return true end end
        return false
    end
    if id==46 then
        for _,smoke in ipairs(entity.get_all("CSmokeGrenadeProjectile")) do
            local p=G.pos(smoke)
            if p and G.prop(smoke,"m_bDidSmokeEffect",0)==1 then
                local d=G.subv(pos,p)
                if d.z>=-64 and d.z<=120 then
                    local radius=22500
                    if d.z>72 then radius=radius-12500*G.clamp((d.z-72)/48,0,1)^2
                    elseif d.z<18 then radius=radius-6116*G.clamp((18-d.z)/82,0,1)^2 end
                    if d.x^2+d.y^2<=radius then return false end
                end
            end
        end
    end
    for _,enemy in ipairs(entity.get_players(true)) do
        local origin=G.pos(enemy); local eye=G.eye(enemy)
        if origin and eye then
            if id==46 and G.length(G.subv(origin,pos))<=75 then return true end
            local distance=G.length(G.subv(eye,pos))
            if id==44 and distance<=350 then
                local head=G.vec(entity.hitbox_position(enemy,0))
                local _,ey=entity.get_prop(enemy,"m_angEyeAngles")
                local angle=math.rad((ey or 0)+90)
                local right=G.vec(math.cos(angle)*16,math.sin(angle)*16,0)
                local points={head,eye,G.subv(eye,right),G.addv(eye,right),origin}
                local weights={.2,.4,.1,.1,.2}; local exposure=0
                for i,p in ipairs(points) do
                    local tr=G.trace_line(G.addv(pos,G.vec(0,0,1)),p,me)
                    if tr.fraction==1 or tr.entity==enemy then exposure=exposure+weights[i] end
                end
                local damage=math.exp(-distance^2/(165*165))*100*exposure
                local armor=G.prop(enemy,"m_ArmorValue",0)
                if armor>0 then local after=damage*.6; if armor<(damage-after)*.5 then after=damage-armor*2 end; damage=after end
                if G.get("grenade_damage")*(armor==0 and 1.5 or 1)<=damage then return true end
            end
        end
    end
    return false
end
function G.unlock_movement()
    G.runtime.locked=nil; G.runtime.unlock_command=0
    G.release("strafe"); G.release("quick_stop"); G.release("slow")
end
function G.grenade_release(me,cmd)
    local r=G.runtime
    if not G.get("grenade_release") or not (G.trace_lib and G.vector_lib) then G.unlock_movement(); return end
    if r.locked then
        if cmd.command_number>=r.unlock_command then G.unlock_movement()
        else
            G.override("strafe",1,false); G.override("quick_stop",1,false)
            cmd.in_attack=0; cmd.in_attack2=0
            cmd.in_moveleft=0; cmd.in_moveright=0; cmd.in_forward=0; cmd.in_back=0
            for key,value in pairs(r.locked) do cmd[key]=value end
            return
        end
    end
    if cmd.in_use==1 or (cmd.in_attack~=1 and cmd.in_attack2~=1) then return end
    local weapon=entity.get_player_weapon(me)
    if not weapon or G.prop(weapon,"m_bPinPulled",0)~=1 then return end
    local id=bit.band(G.prop(weapon,"m_iItemDefinitionIndex",0),65535)
    id=id==48 and 46 or id
    if id~=44 and id~=45 and id~=46 then return end
    -- Avoid running the full simulation on choked commands.
    if cmd.chokedcommands~=0 then return end
    local delay=G.active_ref("dt") and 2 or 8
    local pos,vel=G.grenade_start(me,weapon,cmd,delay)
    if not pos then return end
    local impact,ground=G.grenade_predict(pos,vel,id,me)
    if not impact or not ground or not G.grenade_impact(impact,id,me) then return end
    r.locked={}
    for _,key in ipairs({"pitch","yaw","move_yaw","forwardmove","sidemove","in_jump","in_duck","in_speed","in_left","in_right","in_bullrush"}) do
        if cmd[key]~=nil then r.locked[key]=cmd[key] end
    end
    r.unlock_command=cmd.command_number+delay
    G.override("strafe",1,false); G.override("quick_stop",1,false)
    cmd.in_attack=0; cmd.in_attack2=0
end

function G.visual_cvars(me)
    G.cv("viewmodel_fov",G.get("vm_fov")*.1)
    G.cv("viewmodel_offset_x",G.get("vm_x")*.1)
    G.cv("viewmodel_offset_y",G.get("vm_y")*.1)
    G.cv("viewmodel_offset_z",G.get("vm_z")*.1)
    G.cv("r_aspectratio",G.get("aspect")*.01)
    local weapon=me and entity.get_player_weapon(me)
    local class=weapon and entity.get_classname(weapon) or ""
    if G.get("knife_hand") and (class=="CKnife" or class=="CKnifeGG") then
        if not G.cv_cache.cl_righthand then G.cv_cache.cl_righthand={cv=cvar.cl_righthand,value=cvar.cl_righthand:get_int()} end
        G.cv("cl_righthand",G.cv_cache.cl_righthand.value==1 and 0 or 1)
    else G.release_cv("cl_righthand") end
    if G.get("extended_ping") and G.get("ping_key") and G.get("fake_latency")>0 then
        G.cv("sv_maxunlag",.2)
        if (G.refs.ping or {})[1] then
            -- Ping spike returns enabled checkbox, hotkey, amount slider.
            G.override("ping",1,true)
            if G.refs.ping[2] then G.override("ping",2,"Always on","hotkey") end
            if G.refs.ping[3] then G.override("ping",3,G.get("fake_latency")) end
        end
    else G.release("ping"); G.release_cv("sv_maxunlag") end
    if G.get("shared_esp") then G.override("shared",1,true) else G.release("shared") end
end
function G.restore_model()
    local old=G.runtime.model_color
    if old then
        if entity.get_local_player()==old.entity then entity.set_prop(old.entity,"m_clrRender",old.color) end
        G.runtime.model_color=nil
    end
end
function G.pre_render()
    if not G.is_enabled() then return end
    local me=entity.get_local_player(); if not me or not entity.is_alive(me) then return end
    if G.get("jitter_legs") then
        G.override("legs",1,"Always slide")
        if bit.band(globals.tickcount(),3)>1 then
            G.runtime.pose_backup={entity=me,[0]=G.prop(me,"m_flPoseParameter",0,0),[1]=G.prop(me,"m_flPoseParameter",0,1)}
            entity.set_prop(me,"m_flPoseParameter",1,0); entity.set_prop(me,"m_flPoseParameter",1,1)
        end
    else G.release("legs") end
    if G.entity_lib and G.get("move_lean")~=-1 then
        local ent=G.entity_lib.get_local_player()
        local v=G.vel(me)
        if ent and G.length(v)>=5 then
            local layer=ent:get_anim_overlay(12)
            if layer then
                G.runtime.lean_backup={entity=me,layer=layer,weight=layer.weight}
                layer.weight=G.get("move_lean")*.01
            end
        end
    end
    if G.get("keep_transparency") then
        local value=G.prop(me,"m_clrRender",nil)
        if value then
            G.runtime.model_color={entity=me,color=value}
            local alpha=bit.band(bit.rshift(value,24),255)
            local weapon=entity.get_player_weapon(me)
            local id=weapon and bit.band(G.prop(weapon,"m_iItemDefinitionIndex",0),65535) or 0
            if G.prop(me,"m_bIsScoped",0)==1 or G.prop(me,"m_bResumeZoom",0)==1 or (id>=43 and id<=48) then alpha=59 end
            entity.set_prop(me,"m_clrRender",bit.bor(bit.band(value,0xffffff),bit.lshift(alpha,24)))
        end
    end
end
function G.post_render()
    G.restore_model()
    local pose=G.runtime.pose_backup
    if pose then
        if entity.get_local_player()==pose.entity then
            entity.set_prop(pose.entity,"m_flPoseParameter",pose[0],0); entity.set_prop(pose.entity,"m_flPoseParameter",pose[1],1)
        end
        G.runtime.pose_backup=nil
    end
    local lean=G.runtime.lean_backup
    if lean then
        if entity.get_local_player()==lean.entity and entity.is_alive(lean.entity) then lean.layer.weight=lean.weight end
        G.runtime.lean_backup=nil
    end
end
function G.hit_lines(x,y,size,color)
    local gap=size; local length=size*2
    for _,v in ipairs({{-1,-1},{-1,1},{1,-1},{1,1}}) do
        renderer.line(x+v[1]*length,y+v[2]*length,x+v[1]*gap,y+v[2]*gap,unpack(color))
    end
end
function G.paint()
    if not G.is_enabled() then return end
    local r=G.runtime; local me=entity.get_local_player()
    if not me or not entity.is_alive(me) then G.release("scope"); return end
    local w,h=client.screen_size(); local x,y=w*.5,h*.5; local now=globals.realtime()
    local dt=math.min(.1,globals.frametime())
    local scoped=G.get("scope_overlay") and G.prop(me,"m_bIsScoped",0)==1
    r.scope_alpha=r.scope_alpha+((scoped and 1 or 0)-r.scope_alpha)*math.min(1,dt*20)
    if G.get("scope_overlay") then
        G.override("scope",1,true)
        if r.scope_alpha>.001 then
            local a=G.get("scope_type")=="Simple" and G.get("scope_simple") or G.get("scope_a")
            local b=G.get("scope_type")=="Simple" and G.copy(a) or G.get("scope_b")
            a[4]=math.floor(a[4]*r.scope_alpha); b[4]=math.floor(b[4]*r.scope_alpha)
            local offset=G.get("scope_offset"); local length=G.get("scope_length")
            local size=math.max(0,length-offset)
            if size>0 then
                renderer.gradient(x-length,y,size,1,b[1],b[2],b[3],b[4],a[1],a[2],a[3],a[4],true)
                renderer.gradient(x+offset,y,size,1,a[1],a[2],a[3],a[4],b[1],b[2],b[3],b[4],true)
                renderer.gradient(x,y-length,1,size,b[1],b[2],b[3],b[4],a[1],a[2],a[3],a[4],false)
                renderer.gradient(x,y+offset,1,size,a[1],a[2],a[3],a[4],b[1],b[2],b[3],b[4],false)
            end
        end
    else G.release("scope") end
    r.arrow_alpha=r.arrow_alpha+((G.get("manual_arrows") and 1 or 0)-r.arrow_alpha)*math.min(1,dt*10)
    if r.arrow_alpha>.001 then
        local dir=G.get("manual_yaw"); local offset=G.get("arrows_offset")
        local flags=({Default="c",Small="c-",Console="c",Bold="cb"})[G.get("arrows_font")]
        local color=G.get("arrows_color"); color[4]=math.floor(color[4]*r.arrow_alpha)
        local px,py,text=x,y-2,nil
        if dir=="Left" then px=x-offset; text=G.get("left_symbol")
        elseif dir=="Right" then px=x+offset; text=G.get("right_symbol")
        elseif dir=="Forward" then py=y-2-offset; text=G.get("forward_symbol") end
        if text then renderer.text(px,py,color[1],color[2],color[3],color[4],flags,0,text) end
    end
    if G.has(G.get("hit_marker"),"Crosshair") then
        local alpha=1-G.clamp((now-r.hit_until)*2.5,0,1)^3
        if alpha>.001 then G.hit_lines(x,y,5,{255,255,255,math.floor(alpha*255)}) end
    end
    if G.has(G.get("hit_marker"),"3D") and r.world_pos then
        local alpha=1-G.clamp((now-r.world_until)*2.5,0,1)^3
        local p=r.world_pos; local sx,sy=renderer.world_to_screen(p.x,p.y,p.z)
        if sx and alpha>.001 then
            local c=G.get("world_color"); c[4]=math.floor(c[4]*alpha)
            renderer.line(sx-5,sy,sx+5,sy,unpack(c)); renderer.line(sx,sy-5,sx,sy+5,unpack(c))
        end
    end
end

function G.bullet_impact(e)
    if not G.is_enabled() or not G.get("anti_bruteforce") then return end
    local me=entity.get_local_player(); local attacker=client.userid_to_entindex(e.userid)
    if not me or not entity.is_alive(me) or not attacker or not entity.is_enemy(attacker) then return end
    local state=G.current_state(me,{in_jump=0})
    if not G.has(G.get("brute_states"),state) or G.runtime.brute_tick==globals.tickcount() then return end
    local x,y,z=entity.hitbox_position(me,0); local start=G.eye(attacker)
    if not x or not start then return end
    local head=G.vec(x,y,z); local delta=G.subv(G.vec(e.x,e.y,e.z),start)
    local len=G.dot(delta,delta); if len<=.0001 then return end
    local t=G.clamp(G.dot(G.subv(head,start),delta)/len,0,1)
    local distance=G.length(G.subv(G.addv(start,G.mulv(delta,t)),head))
    if distance>40 then return end
    local mode=G.get("brute_mode")
    G.runtime.brute_offset=mode=="Increasing" and G.random(-5,10) or (mode=="Decreasing" and 5 or G.random(-15,15))
    G.runtime.brute_tick=globals.tickcount(); G.runtime.brute_until=globals.realtime()+3
    G.log(string.format("%s attacked from distance %sm",entity.get_player_name(attacker),math.floor(distance)))
end
G.hitgroups={[0]="generic","head","chest","stomach","left arm","right arm","left leg","right leg","neck","generic","gear"}
function G.aim_fire(e)
    if not G.is_enabled() then return end
    local now=globals.realtime()
    for id,s in pairs(G.shots) do if now-s.time>10 then G.shots[id]=nil end end
    G.shots[e.id]={target=e.target,hitgroup=e.hitgroup,damage=e.damage,hitchance=e.hit_chance,
        backtrack=e.backtrack or 0,tick=globals.tickcount(),time=now,x=e.x,y=e.y,z=e.z}
end
function G.aim_hit(e)
    if not G.is_enabled() then return end
    local shot=G.shots[e.id] or {}; G.shots[e.id]=nil
    if G.has(G.get("hit_marker"),"3D") then
        local p=shot.x and G.vec(shot.x,shot.y,shot.z)
        if not p and e.target then local x,y,z=entity.hitbox_position(e.target,0); if x then p=G.vec(x,y,z) end end
        if p then G.runtime.world_pos=p; G.runtime.world_until=globals.realtime()+G.get("world_time")*.1 end
    end
    if not G.get("damage_dealt") then return end
    local name=entity.get_player_name(e.target)
    if #name>16 then name=name:sub(1,16).."..." end
    local group=G.hitgroups[e.hitgroup] or "gear"
    local wanted=G.hitgroups[shot.hitgroup] or group
    local mismatch=group~=wanted and ("("..wanted..")") or ""
    local difference=shot.damage and shot.damage~=e.damage and ("("..shot.damage..")") or ""
    local backtrack=math.floor((shot.backtrack or 0)/globals.tickinterval()+.5)
    G.log(string.format("Hit %s in the %s%s for %s%s damage (%s health left) (hc: %s%% · bt: %st · delay: %st)",
        name,group,mismatch,e.damage,difference,G.prop(e.target,"m_iHealth",0),e.hit_chance or shot.hitchance or 0,
        backtrack,math.max(-2,globals.tickcount()-(shot.tick or globals.tickcount())-1)))
end
function G.aim_miss(e)
    local shot=G.shots[e.id] or {}; G.shots[e.id]=nil
    if not G.is_enabled() or not G.get("damage_dealt") then return end
    G.log(string.format("Missed shot due to %s (hitbox: %s · hitchance: %s%% · damage: %s · bt: %st)",
        e.reason or "?",G.hitgroups[shot.hitgroup or e.hitgroup] or "gear",e.hit_chance or shot.hitchance or 0,
        shot.damage or 0,math.floor((shot.backtrack or 0)/globals.tickinterval()+.5)),true)
end
function G.player_hurt(e)
    if not G.is_enabled() then return end
    local me=entity.get_local_player(); if not me then return end
    local attacker=client.userid_to_entindex(e.attacker); local target=client.userid_to_entindex(e.userid)
    if attacker==me and target~=me then G.runtime.hit_until=globals.realtime()+G.get("crosshair_time")*.1 end
    if G.get("damage_dealt") and target==me and attacker then
        local verb=({inferno="Molly",hegrenade="Frag",knife="Knife"})[e.weapon]
        if verb then G.log(string.format("Got hurt by %s with %s for %s damage (%s health left)",entity.get_player_name(attacker),verb,e.dmg_health,e.health),true) end
    end
end
function G.item_purchase(e)
    if not G.is_enabled() or not G.get("purchases") or e.weapon=="weapon_unknown" then return end
    local buyer=client.userid_to_entindex(e.userid)
    if buyer then G.log(entity.get_player_name(buyer).." bought "..tostring(e.weapon)) end
end
function G.release_angles()
    for _,key in ipairs({"enabled","pitch","yaw_base","yaw","jitter","body","fs_body","freestanding","fake_limit","dt_fl"}) do G.release(key) end
end
function G.stop()
    G.post_render(); G.restore_refs(); G.restore_cvars()
    local r=G.runtime
    r.running=false; r.brute_until=0; r.last_weapon=nil; r.unlock_command=0; r.locked=nil
    r.hit_until=-100; r.world_until=-100; r.world_pos=nil
    r.scope_alpha=0; r.arrow_alpha=0; r.manual_keys={}
    G.shots={}
end
function G.setup_command(cmd)
    if not G.is_enabled() then if G.runtime.running then G.stop() end; return end
    G.runtime.running=true
    G.update_manual()
    local me=entity.get_local_player()
    if not me or not entity.is_alive(me) then G.release_angles(); G.unlock_movement(); return end
    local team=G.prop(me,"m_iTeamNum",0)
    if team~=2 and team~=3 then G.release_angles(); return end
    G.aa(me,cmd)
    G.fast_ladder(me,cmd)
    G.no_fall_damage(me,cmd)
    G.fakeduck_speed(me,cmd)
    G.grenade_release(me,cmd)
end
function G.paint_ui()
    if not G.is_enabled() then if G.runtime.running then G.stop() end; return end
    G.runtime.running=true
    G.visual_cvars(entity.get_local_player())
end

-- Event errors disable the port and release borrowed settings immediately.
function G.listen(name, fn)
    client.set_event_callback(name,function(...)
        local ok,err=pcall(fn,...)
        if not ok then
            pcall(G.stop)
            G.set("master",false)
            G.log("Disabled after "..name.." error: "..tostring(err),true)
        end
    end)
end
for _,key in ipairs(G.order) do
    local c=G.controls[key]
    if c.kind~="label" and c.kind~="button" then
        ui.set_callback(c.ref,function()
            if G.loading then return end
            if key=="team" or key=="state" then
                G.save_editor(); G.editor_team=G.get("team"); G.editor_state=G.get("state"); G.load_editor()
            elseif c.profile then G.save_editor()
            elseif key=="master" or key=="activation" then if not G.is_enabled() then G.stop() end
            elseif key=="anti_bruteforce" and not G.get("anti_bruteforce") then G.runtime.brute_until=0
            elseif key=="preset_search" then G.update_presets()
            elseif key=="preset_list" then
                local name=G.selected_preset(); if name then G.set("preset_name",name) end; G.preset_info()
            elseif key=="scope_overlay" and not G.get("scope_overlay") then G.release("scope")
            elseif key=="jitter_legs" and not G.get("jitter_legs") then G.release("legs")
            elseif key=="extended_ping" and not G.get("extended_ping") then G.release("ping"); G.release_cv("sv_maxunlag")
            elseif key=="shared_esp" and not G.get("shared_esp") then G.release("shared")
            elseif key=="grenade_release" and not G.get("grenade_release") then G.unlock_movement() end
            G.visibility()
        end)
    end
end
G.loading=false
local saved=database.read(G.db_key.."_current")
if saved then G.guarded(function() G.apply_snapshot(saved) end) else G.load_editor() end
G.editor_team=G.get("team"); G.editor_state=G.get("state"); G.load_editor()
G.update_presets(); G.visibility()
G.listen("setup_command",G.setup_command)
G.listen("paint_ui",G.paint_ui)
G.listen("paint",G.paint)
G.listen("pre_render",G.pre_render)
G.listen("post_render",G.post_render)
G.listen("bullet_impact",G.bullet_impact)
G.listen("aim_fire",G.aim_fire)
G.listen("aim_hit",G.aim_hit)
G.listen("aim_miss",G.aim_miss)
G.listen("player_hurt",G.player_hurt)
G.listen("item_purchase",G.item_purchase)
G.listen("round_start",function() G.stop() end)
G.listen("level_init",function() G.stop() end)
G.listen("cs_game_disconnected",function() G.stop() end)
G.listen("player_spawn",function(e)
    if client.userid_to_entindex(e.userid)==entity.get_local_player() then G.stop() end
end)
G.listen("pre_config_save",function() G.persist(); G.stop() end)
G.listen("post_config_save",function() G.visibility() end)
G.listen("pre_config_load",function() G.stop(); G.loading=true end)
G.listen("post_config_load",function()
    G.loading=false
    G.editor_team=G.get("team"); G.editor_state=G.get("state")
    local data=ui.get(G.storage)
    if data and data~="" then G.guarded(function() G.apply_snapshot(G.decode(data)) end)
    else G.load_editor() end
    G.visibility()
end)
client.set_event_callback("shutdown",function()
    pcall(G.persist); G.stop()
end)
G.log("Loaded. AA > Anti-aimbot angles > Enable Gazolina")
