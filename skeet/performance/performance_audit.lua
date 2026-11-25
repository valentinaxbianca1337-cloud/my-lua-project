-- Read-only GameSense frame-time recorder. No FFI, hooks or gameplay writes.
-- Close the menu after Start. Output: csgo/performance_audit.json.
local FILE, VERSION = "performance_audit.json", "1.0"
local refs, runs, active = {}, {}, nil
local function pack(...) return { n = select("#", ...), ... } end
local function number(x) return type(x) == "number" and x == x and x > -math.huge and x < math.huge end
local function now() return client.timestamp() end
local function log(s) client.log("[performance audit] " .. s) end
local function stats(values)
    if #values == 0 then return { samples = 0 } end
    local sorted, sum, squares = {}, 0, 0
    for i, v in ipairs(values) do sorted[i], sum, squares = v, sum + v, squares + v*v end
    table.sort(sorted)
    local function p(q) return sorted[math.max(1, math.ceil(#sorted*q))] end
    local avg, slow16, slow33 = sum/#values, 0, 0
    for _, v in ipairs(values) do
        if v > 16.667 then slow16 = slow16 + 1 end
        if v > 33.333 then slow33 = slow33 + 1 end
    end
    return { samples = #values, total_ms = sum, mean_ms = avg,
        fps_from_mean = avg > 0 and 1000/avg or nil, median_ms = p(.5), p95_ms = p(.95), p99_ms = p(.99),
        minimum_ms = sorted[1], maximum_ms = sorted[#sorted],
        stddev_ms = math.sqrt(math.max(0, squares/#values-avg*avg)),
        frames_over_16_667ms = slow16, frames_over_33_333ms = slow33 }
end
local definitions = {
    {"rage", "RAGE", "Aimbot", "Enabled"},
    {"hitboxes", "RAGE", "Aimbot", "Target hitbox"},
    {"multipoint", "RAGE", "Aimbot", "Multi-point"},
    {"multipoint_scale", "RAGE", "Aimbot", "Multi-point scale"},
    {"hit_chance", "RAGE", "Aimbot", "Minimum hit chance"},
    {"minimum_damage", "RAGE", "Aimbot", "Minimum damage"},
    {"accuracy_boost", "RAGE", "Other", "Accuracy boost"},
    {"low_fps_mitigations", "RAGE", "Other", "Low FPS mitigations"},
}
for _, d in ipairs(definitions) do
    local result = pack(pcall(ui.reference, d[2], d[3], d[4]))
    local handles = {}
    if result[1] then for i = 2, result.n do handles[#handles+1] = result[i] end end
    refs[d[1]] = handles
end
local function read(handles)
    local values = {}
    for _, handle in ipairs(handles or {}) do
        local result = pack(pcall(ui.get, handle))
        if result[1] then
            if result.n == 2 then values[#values+1] = result[2]
            else
                local row = {}; for i = 2, result.n do row[#row+1] = result[i] end
                values[#values+1] = row
            end
        end
    end
    return values
end
local function settings()
    local result = {}
    for key, handles in pairs(refs) do result[key] = read(handles) end
    return result
end
local function equal(a,b)
    if type(a)~=type(b) then return false end
    if type(a)~="table" then return a==b end
    for k,v in pairs(a) do if not equal(v,b[k]) then return false end end
    for k in pairs(b) do if a[k]==nil then return false end end
    return true
end
local function position(index)
    if not index then return nil end
    local x,y,z = entity.get_prop(index, "m_vecOrigin")
    if number(x) and number(y) and number(z) then return {x=x,y=y,z=z} end
end
local function snapshot()
    local result = { map = globals.mapname(), tick = globals.tickcount(), settings = settings() }
    local me = entity.get_local_player()
    result.local_player_alive = me and entity.is_alive(me) or false
    result.position = position(me)
    if client.camera_angles then
        local ok, p, y = pcall(client.camera_angles)
        if ok then result.camera = {pitch=p,yaw=y} end
    end
    if client.screen_size then
        local ok, w, h = pcall(client.screen_size)
        if ok then result.resolution = {width=w,height=h} end
    end
    if globals.tickinterval then result.tickinterval = globals.tickinterval() end
    local weapon = me and entity.get_player_weapon(me)
    if weapon then result.weapon_class = entity.get_classname(weapon) end
    result.enemies = {}
    for _, index in ipairs(entity.get_players(true) or {}) do
        if entity.is_alive(index) and not entity.is_dormant(index) then
            result.enemies[#result.enemies+1] = { index=index, position=position(index) }
        end
    end
    result.cvars = {}
    for _, name in ipairs({"fps_max","mat_vsync","mat_queue_mode"}) do
        local ok, value = pcall(function() return cvar[name]:get_string() end)
        if ok then result.cvars[name] = value end
    end
    return result
end
local label = ui.new_textbox("LUA", "B", "Performance sample label")
local length = ui.new_slider("LUA", "B", "Performance sample length", 5, 20, 10, true, "s")
local function save()
    local payload = { version=VERSION, runs=runs,
        scope="render callback intervals; not a native-function CPU/GPU profiler",
        gameplay_writes=false, modules_or_native_points_not_observable=true }
    local ok, encoded = pcall(json.stringify, payload)
    if not ok then log("JSON encoding failed: " .. tostring(encoded)); return false end
    local written, err = pcall(writefile, FILE, encoded)
    if not written or err == false then log("Could not write " .. FILE); return false end
    return true
end
local function finish(valid, reason)
    local s = active
    if not s then return end
    active = nil
    local ended = now()
    local r = { label=s.label, valid=valid, reason=reason,
        started_client_timestamp_ms=s.started, ended_client_timestamp_ms=ended,
        requested_seconds=s.duration/1000, start=s.start, finish=snapshot(),
        frames=stats(s.frames), engine_absolute_frames=stats(s.engine_frames),
        sampler_callback_ms=stats(s.costs), settings_changed=s.changed,
        events=s.events, invalid_frame_samples=s.invalid }
    if s.started then r.wall_seconds=(ended-s.started)/1000 end
    if s.changed then r.valid=false; r.reason="native Rage controls changed during the sample" end
    runs[#runs+1] = r
    if #runs > 24 then table.remove(runs, 1) end
    local saved=save()
    local destination=saved and (" Saved " .. FILE) or " Report could not be written."
    if r.frames.samples > 0 then
        log(string.format("%s: %.1f FPS, mean %.2fms, p95 %.2fms, p99 %.2fms (%s).%s",
            r.label,r.frames.fps_from_mean,r.frames.mean_ms,r.frames.p95_ms,r.frames.p99_ms,
            r.valid and "valid" or r.reason,destination))
    else log("No complete sample: " .. tostring(r.reason) .. "." .. destination) end
end
local function start()
    if active then log("A sample is already active; cancel it first."); return end
    if not globals.mapname() then log("Join a map before starting."); return end
    local name = ui.get(label)
    if not name or name == "" then name = "sample " .. tostring(#runs+1) end
    active = { label=name, duration=ui.get(length)*1000, phase="menu", queued=now(),
        map=globals.mapname(), frames={},engine_frames={},costs={},events={},invalid=0 }
    log("Close the menu. Recording starts after 2 seconds; keep the scene unchanged.")
end
ui.new_button("LUA", "B", "Start performance sample", start)
ui.new_button("LUA", "B", "Cancel performance sample", function() finish(false,"cancelled") end)
ui.new_button("LUA", "B", "Save performance report", function() if save() then log("Saved " .. FILE) end end)
local function sample()
    local s=active
    if not s then return end
    local entered=now()
    if globals.mapname() ~= s.map then finish(false,"map changed"); return end
    if s.phase == "menu" then
        if entered-s.queued > 60000 then finish(false,"menu remained open"); return end
        if not ui.is_menu_open() then s.phase="warmup";s.ready=entered+2000 end
        return
    end
    if s.phase == "warmup" then
        if ui.is_menu_open() then s.phase="menu";s.queued=entered;return end
        if entered < s.ready then return end
        s.phase="record";s.start=snapshot();s.started=entered;s.last=entered
        s.check=entered;s.rage=read(refs.rage);return
    end
    if ui.is_menu_open() then finish(false,"menu opened during sample");return end
    local delta=entered-s.last;s.last=entered
    if number(delta) and delta > 0 and delta <= 10000 then s.frames[#s.frames+1]=delta
    else s.invalid=s.invalid+1 end
    if globals.absoluteframetime then
        local frame=globals.absoluteframetime()*1000
        if number(frame) and frame>0 then s.engine_frames[#s.engine_frames+1]=frame end
    end
    if entered-s.check >= 250 then
        local current=read(refs.rage)
        if not equal(current,s.rage) then s.changed=true end
        s.check=entered
    end
    s.costs[#s.costs+1]=math.max(0,now()-entered)
    if #s.frames>=100000 then finish(false,"sample capacity reached");return end
    if entered-s.started>=s.duration then
        finish(#s.frames>=30 and s.invalid==0, #s.frames<30 and "too few frames" or s.invalid>0 and "invalid frame samples" or "complete")
    end
end
client.set_event_callback("paint_ui",sample)
for _, event in ipairs({"setup_command","run_command","net_update_end","aim_fire"}) do
    local name=event
    client.set_event_callback(name,function()
        if active and active.phase=="record" then active.events[name]=(active.events[name]or 0)+1 end
    end)
end
client.set_event_callback("shutdown",function() finish(false,"script unloaded") end)
return {stats=stats}
