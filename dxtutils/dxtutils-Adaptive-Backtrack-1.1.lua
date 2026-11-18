local NativeRuntime = (function()
local M = {}
function M.native_api()
    local ffi = require("ffi")
    assert(ffi.os == "Windows" and ffi.abi("32bit"), "Requires Windows / x86 Neverlose CS:GO")
    local kernel = ffi.load("kernel32")
    local function bootstrap(name, declaration, signature)
        local ok, fn = pcall(function() return kernel[name] end)
        if not ok then ffi.cdef(declaration); fn = kernel[name] end
        return ffi.cast(signature, ffi.cast("void*", fn))
    end
    local get_module = bootstrap("GetModuleHandleA", "void* __stdcall GetModuleHandleA(const char*);",
        "void*(__stdcall*)(const char*)")
    local get_proc = bootstrap("GetProcAddress", "void* __stdcall GetProcAddress(void*, const char*);",
        "void*(__stdcall*)(void*, const char*)")
    local handle = get_module("kernel32.dll")
    local function export(name, signature)
        local address = get_proc(handle, name)
        assert(address ~= nil, "Missing Windows API: " .. name)
        return ffi.cast(signature, address)
    end
    local query = export("VirtualQuery", "size_t(__stdcall*)(const void*, void*, size_t)")
    local alloc = export("VirtualAlloc", "void*(__stdcall*)(void*, size_t, unsigned long, unsigned long)")
    local protect = export("VirtualProtect", "int(__stdcall*)(void*, size_t, unsigned long, unsigned long*)")
    local flush = export("FlushInstructionCache", "int(__stdcall*)(void*, const void*, size_t)")
    local process = export("GetCurrentProcess", "void*(__stdcall*)()")()
    return { ffi = ffi, query = query, alloc = alloc, protect = protect,
        flush = flush, process = process }
end

function M.controller(factory, menu)
    local state = { backend = nil, message = "Extra points: disabled" }
    local function time() return globals and globals.realtime or 0 end
    function state:update(wanted)
        if not wanted then self.pending, self.search_started = nil, nil end
        if wanted and not self.backend then
            if not menu() then
                self.pending, self.search_started = nil, nil
                self.message = "Extra points: enable once in the main menu"
                return
            end
            if not self.pending then
                local result = factory()
                assert(type(result) == "table", "Native constructor did not return a backend or search job")
                if type(result.step) == "function" then
                    self.pending, self.search_started = result, time()
                else self.backend = result end
            end
            if self.pending then
                if time() < self.search_started or time() - self.search_started >= 2 then
                    self.pending, self.search_started = nil, nil
                    error("Build search timed out after 2 seconds; native hooks were not installed")
                end
                local ok, result, message = pcall(self.pending.step, self.pending)
                if not ok then
                    self.pending, self.search_started = nil, nil
                    error(result)
                end
                if not result then
                    self.message = type(message) == "string" and message or "Extra points: checking build"
                    return
                end
                self.pending, self.search_started = nil, nil
                assert(type(result) == "table", "Native search did not return a backend")
                self.backend = result
            end
        end
        local backend = self.backend
        if not backend then self.message = "Extra points: disabled"; return end
        if wanted then
            if not backend.installed then
                if not menu() then self.message = "Extra points: attachment pending main menu"; return end
                backend:attach()
            end
            backend:set_enabled(true)
            self.message = "Extra points added: " .. backend:count()
        else
            backend:set_enabled(false)
            if backend.installed and menu() then backend:detach() end
            self.message = backend.installed and "Extra points: off; detach in main menu" or "Extra points: disabled"
        end
    end
    function state:shutdown()
        self.pending, self.search_started = nil, nil
        if self.backend then self.backend:shutdown() end
    end
    return state
end

return M
end)()

local Backtrack = (function()
local M = {}
local TEMPLATE = "803d44332211000f84380100009c6083ec200f1114240f115c24100f2ec00f8a130100000f2ec90f8a0a01000085f60f840201000066f780b00000001c080f85f30000008b5a0885db0f84e80000004b235f0c8b4a048b0c9985c90f84d60000008b99840000002b988400000083fb010f8ec1000000f30f1050240f57db0f2ed30f86b00000000f8aaa0000000f2e51240f83a00000000f8a9a000000f30f1010f30f5c11f30f59d2f30f105804f30f5c5904f30f59dbf30f58d3f30f105808f30f5c5908f30f59dbf30f58d30f2e158877665577617a5ff30f105068f30f5c51680f2e15aa9988777a4c7608f30f5c15896745230f2e15785634127308f30f5815896745230f57dbf30f5cdaf30f5fd30f2e1599887766771d7a1bf0ff05554433220f1014240f105c241083c420619dff25665544330f1014240f105c241083c420619d0f2ec87606ff2566554433ff2577665544"
local SLOTS = {
    enabled = { 2 },
    counter = { 287 },
    select = { 307, 332 },
    skip = { 338 },
    distance = { 208 },
    angle = { 276 },
    positive180 = { 229 },
    negative180 = { 248 },
    full360 = { 241, 258 },
}

local function pack32(value)
    value = value % 4294967296
    local out = {}
    for i = 1, 4 do out[i] = string.char(value % 256); value = math.floor(value / 256) end
    return table.concat(out)
end
local function unhex(value)
    return (value:gsub('..', function(pair) return string.char(tonumber(pair, 16)) end))
end
function M.materialize(data)
    local result = unhex(TEMPLATE)
    local values = { enabled = data, counter = data + 8, select = data + 0x10,
        skip = data + 0x14, distance = data + 0x20, angle = data + 0x24,
        positive180 = data + 0x28, negative180 = data + 0x2C, full360 = data + 0x30 }
    for key, offsets in pairs(SLOTS) do
        for _, offset in ipairs(offsets) do
            result = result:sub(1, offset) .. pack32(values[key]) .. result:sub(offset + 5)
        end
    end
    return result
end

function M.backend(api)
    local ffi = api.ffi
    local function pointer(n) return ffi.cast('void*', n) end
    local function number(p) return tonumber(ffi.cast('uintptr_t', p)) end
    local function get32(n) return tonumber(ffi.cast('uint32_t*', n)[0]) end
    local function put32(n, v) ffi.cast('uint32_t*', n)[0] = v end
    local function region(n)
        local info = ffi.new('uint32_t[7]')
        if api.query(pointer(n), info, 28) ~= 28 then return nil end
        return { first = tonumber(info[0]), allocation = tonumber(info[1]),
            size = tonumber(info[3]), state = tonumber(info[4]), protection = tonumber(info[5]) }
    end
    local perms = { [2]=true, [4]=true, [8]=true, [0x20]=true, [0x40]=true, [0x80]=true }
    local function readable(n, size)
        if n < 0x10000 or n + size > 0xFFFFFFFF then return false end
        local last = n + size
        while n < last do
            local r = region(n)
            if not r or r.state ~= 0x1000 or not perms[r.protection % 256]
                or math.floor(r.protection / 256) % 2 == 1 or r.first + r.size <= n then return false end
            n = r.first + r.size
        end
        return true
    end
    local function read(n, size)
        assert(readable(n, size), 'Backtrack memory unavailable')
        return ffi.string(pointer(n), size)
    end
    local function jump(n, target) return '\233' .. pack32(target - n - 5) end
    local target_rva = 0x1EF4B9
    local original = unhex('0f2ec87669')
    local checks = {
        {0x1EF180, '5553575683ec108b4c2424'},
        {0x1EF3EC, 'e8ff17f7ff'},
        {0x160BF0, '53575683ec1489ce8b7c242c'},
        {0x1EF441, 'e88aa0f6ff84c00f84cf030000'},
        {0x1EF460, '8b42048b4a084921d98b04888b4c2430'},
        {0x1EF4A1, 'f30f58c20fc6d255f30f58d00f57c0f30f51c2f30f100c24'},
        {0x1EF4BE, '89c60f28c8eb62'},
        {0x1EF4E1, 'f681b000000008f30f100c240f85930200008b048780b8a4000000008b7c24087524e9da020000'},
        {0x1EF527, '0fb780b0000000a908080000750f43'},
    }
    local function matches(base)
        if base < 0x10000 then return false end
        for _, check in ipairs(checks) do
            local bytes = unhex(check[2])
            if not readable(base+check[1], #bytes) or read(base+check[1], #bytes) ~= bytes then return false end
        end
        return true
    end
    local function owned(base)
        local target = base + target_rva
        if not readable(target, 5) or read(target, 1) ~= '\233' then return nil end
        local delta = tonumber(ffi.cast('int32_t*', target+1)[0])
        local code = (target+5+delta-0x100) % 4294967296
        if readable(code, 0x50) and read(code, 8) == 'DXBT0001' then return code end
    end
    local preferred = 0x412A0000
    local search = { address=0x10000, checked=0, candidates=0, seen={} }
    local function locate()
        if not search.started then
            search.started = true; search.seen[preferred] = true
            if matches(preferred) and (owned(preferred) or read(preferred+target_rva, 5) == original) then return preferred end
        end
        local regions, candidates = 0, 0
        while search.address < 0xFFF00000 and regions < 32 and candidates < 4 do
            search.checked, regions = search.checked+1, regions+1
            assert(search.checked <= 4096, 'Backtrack build search limit reached')
            local r = region(search.address)
            assert(r and r.size > 0 and r.first+r.size > search.address, 'No supported backtrack image')
            local permission = r.protection % 256
            local executable = permission == 0x20 or permission == 0x40 or permission == 0x80
            if r.state == 0x1000 and executable and math.floor(r.protection / 256) % 2 == 0
                and r.allocation >= 0x10000 and not search.seen[r.allocation] then
                local base = r.allocation
                search.seen[base] = true
                candidates, search.candidates = candidates+1, search.candidates+1
                assert(search.candidates <= 256, 'Backtrack image limit reached')
                if matches(base) and (owned(base) or read(base+target_rva, 5) == original) then return base end
            end
            search.address = r.first+r.size
        end
        assert(search.address < 0xFFF00000, 'No supported backtrack image; build differs or conflicting patch is loaded')
    end
    local function main_menu()
        return globals.is_in_game == false and entity.get_local_player() == nil
    end
    local function initialize(base)
        assert(main_menu(), 'Backtrack install requires main menu')
        local target = base+target_rva
        local code = owned(base)
        local data
        local backend = { installed = code ~= nil }
        if code then
            assert(get32(code+8) == 1 and get32(code+0xC) == base, 'Unknown backtrack owner header')
            data = get32(code+0x10)
            assert(readable(data, 0x40) and get32(data+4) == 0, 'Another backtrack session is still loaded')
            local r = region(data)
            assert(r.protection % 256 == 4, 'Backtrack data protection differs')
        else
            assert(read(target, 5) == original, 'Conflicting backtrack hook')
            local cp = api.alloc(nil, 4096, 0x3000, 4)
            local dp = api.alloc(nil, 4096, 0x3000, 4)
            assert(cp ~= nil and dp ~= nil, 'Backtrack allocation failed')
            code, data = number(cp), number(dp)
            ffi.fill(cp, 4096, 0xCC); ffi.fill(dp, 4096, 0)
            ffi.copy(cp, 'DXBT0001', 8)
            put32(code+8, 1); put32(code+0xC, base); put32(code+0x10, data)
            ffi.copy(pointer(code+0x40), original, 5)
            put32(data+0x10, base+0x1EF4BE); put32(data+0x14, base+0x1EF527)
            local constants = { [0x20]=64, [0x24]=8, [0x28]=180, [0x2C]=-180, [0x30]=360 }
            for offset, value in pairs(constants) do ffi.cast('float*', data+offset)[0] = value end
            local bytes = M.materialize(data)
            ffi.copy(pointer(code+0x100), bytes, #bytes)
            local old = ffi.new('unsigned long[1]')
            assert(api.protect(cp, 4096, 0x20, old) ~= 0, 'Cannot protect backtrack wrapper')
            assert(api.flush(api.process, cp, 4096) ~= 0, 'Cannot flush backtrack wrapper')
        end
        assert(read(code+0x40, 5) == original, 'Backtrack original bytes differ')
        assert(read(code+0x100, #M.materialize(data)) == M.materialize(data), 'Backtrack wrapper differs')
        assert(get32(data+0x10) == base+0x1EF4BE and get32(data+0x14) == base+0x1EF527, 'Backtrack continuations differ')
        assert(read(data+0x20, 20) == unhex('000080420000004100003443000034c30000b443'), 'Backtrack constants differ')
        local installed = jump(target, code+0x100)
        assert(read(target, 5) == (backend.installed and installed or original), 'Backtrack patch differs')
        put32(data+4, 1)
        function backend:set_enabled(value) ffi.cast('uint8_t*', data)[0] = value and 1 or 0 end
        function backend:count() return get32(data+8) end
        local protection
        local function write(bytes)
            local old = ffi.new('unsigned long[1]')
            assert(api.protect(pointer(target), 5, 0x40, old) ~= 0, 'Cannot change backtrack protection')
            protection = protection or tonumber(old[0])
            ffi.copy(pointer(target), bytes, 5)
            assert(api.protect(pointer(target), 5, protection, old) ~= 0, 'Cannot restore backtrack protection')
            assert(api.flush(api.process, pointer(target), 5) ~= 0, 'Cannot flush backtrack patch')
        end
        local function transaction(wanted)
            assert(main_menu(), 'Backtrack patch changes require main menu')
            backend:set_enabled(false)
            local before, after = wanted and original or installed, wanted and installed or original
            assert(matches(base) and read(target, 5) == before, 'Conflicting backtrack patch')
            local ok, err = pcall(write, after)
            if not ok then
                local restored = pcall(write, before)
                error(tostring(err) .. (restored and '' or '; rollback failed; native flag disabled'))
            end
            backend.installed = wanted
        end
        function backend:attach() if not self.installed then transaction(true) end end
        function backend:detach() if self.installed then transaction(false) end end
        function backend:shutdown()
            self:set_enabled(false)
            if main_menu() then self:detach() end
            put32(data+4, 0)
        end
        backend.code, backend.data, backend.base = code, data, base
        return backend
    end
    return { step = function()
        local base = locate()
        if base then return initialize(base) end
        return nil, 'Backtrack: checking build'
    end }
end

function M.create(group, native, running)
    local enabled = group:switch('Adaptive backtrack', false)
    enabled:tooltip('Приоритет старых записей при смещении до 8 units и изменении угла до 8°. Штатные проверки времени и lag compensation сохраняются. Первое включение — в главном меню. Не включай одновременно с патчами выбора записей Viera.')
    local status = enabled:create():label('Backtrack: disabled')
    local error_status = group:label('Backtrack status')
    error_status:visibility(false)
    local controller = native.controller(function() return M.backend(native.native_api()) end,
        function() return globals.is_in_game == false and entity.get_local_player() == nil end)
    local object, fault, updating = {enabled=enabled}, nil, false
    function object:update()
        if not running() or updating then return end
        updating = true
        if enabled:get() then fault = nil end
        local ok, err = pcall(controller.update, controller, enabled:get())
        if not ok then
            if controller.backend then pcall(controller.backend.set_enabled, controller.backend, false) end
            local detail = tostring(err)
            local changed = fault ~= detail
            fault = detail
            enabled:set(false)
            if changed then print('dxtutils backtrack: '..fault) end
        end
        local message = controller.message:gsub('Extra points added: ', 'Backtrack candidates preferred: '):gsub('Extra points:', 'Backtrack:')
        status:name(fault and 'Backtrack: unavailable (see console)' or message)
        if fault then status:tooltip(fault) end
        error_status:visibility(fault ~= nil)
        if fault then
            local reason = 'Unavailable; open console'
            if fault:find('supported backtrack image', 1, true) then reason = 'Unsupported build or Viera conflict'
            elseif fault:find('still loaded', 1, true) then reason = 'Another backtrack Lua is loaded'
            elseif fault:find('Windows / x86', 1, true) then reason = 'Requires Win32 CS:GO'
            elseif fault:find('timed out', 1, true) then reason = 'Build search timed out' end
            error_status:name('Backtrack: '..reason)
            error_status:tooltip(fault)
        end
        updating = false
    end
    enabled:set_callback(function(item) if not item:get() then object:update() end end)
    function object:shutdown()
        local ok, err = pcall(controller.shutdown, controller)
        if not ok then print('dxtutils backtrack cleanup: '..tostring(err)) end
    end
    return object
end

return M

end)()

local ffi = require("ffi")
local pui = require("neverlose/pui")

local lagrecord
local lagrecord_loaded = pcall(function()
    local module = require("neverlose/lagrecord")
    lagrecord = module ^ module.SIGNED
end)

if not lagrecord_loaded then
    lagrecord = nil
end

pcall(function()
    ui.sidebar("dxtutils", "burger-cheese")
end)

local ICON_MAP = {
    force_shoot = "bolt",
    dormant_aimbot = "crosshairs",
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
    if glyph then
        return "\v" .. glyph .. "     " .. text
    end

    return text
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

local tab_aimbot = pui.create("dxtutils", "Ragebot", 2)

local menu = {}

menu.force_shoot = tab_aimbot:switch(
    with_icon("force_shoot", "Force Shot"),
    false
)

local backtrack_running = true
local backtrack = Backtrack.create(tab_aimbot, NativeRuntime, function() return backtrack_running end)
events.render:set(function()
    backtrack:update()
end)
events.shutdown:set(function()
    backtrack_running = false
    backtrack:shutdown()
end)

local performance_tab = pui.create("dxtutils", "Performance", 1)

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


local dormant_dot = "• "
local dormant_min_damage = ref("Aimbot", "Ragebot", "Selection", "Min. Damage")
local dormant_esp_ref = ref("Visuals", "Player ESP", "Dormant")

local DORMANT_WEAPONS = {
    "Auto Snipers",
    "Desert Eagle",
    "Revolver R8",
    "Pistols",
    "Scout",
    "AWP"
}

local DORMANT_HITBOXES = {
    "Head",
    "Chest",
    "Stomach",
    "Legs"
}

local DORMANT_OPTIONS = {
    "Accurate history",
    "Log shots",
    "Indicator",
    "Draw position"
}

local dormant_store = {}
local dormant_last_seen = {}
local dormant_target_cursor = 1
local dormant_round_lock = 0
local dormant_target_found = false
local dormant_has_targets = false
local dormant_pending_shot = nil
local dormant_esp_overridden = false

menu.dormant_aimbot = tab_aimbot:switch(
    with_icon("dormant_aimbot", "Dormant Aimbot"),
    false,
    function(gear)
        return {
            weapon = gear:combo(dormant_dot .. "Weapon", DORMANT_WEAPONS),
            accuracy = gear:slider(dormant_dot .. "Accuracy", 50, 100, 90, 1, "%"),
            hitboxes = gear:selectable(dormant_dot .. "Hitboxes", DORMANT_HITBOXES),
            options = gear:selectable(dormant_dot .. "Options", DORMANT_OPTIONS),
            lastseen_color = gear:color_picker(dormant_dot .. "Position Color", color(255, 255, 255, 255)),
            lagrecords = gear:switch("🕒 LagRecords", lagrecord ~= nil),
            record_age = gear:slider(dormant_dot .. "Max Record Age", 50, 200, 200, 10, "ms")
        }
    end
)

local dormant_controls = menu.dormant_aimbot

menu.dormant_aimbot:tooltip("Right-click the switch to assign a hotkey, just like Force Shot.")
dormant_controls.lagrecords:tooltip("Use recent valid records captured while the enemy was networked.")

local function dormant_call(object, name, ...)
    if object == nil then
        return nil
    end

    local ok, method = pcall(function()
        return object[name]
    end)

    if not ok or type(method) ~= "function" then
        return nil
    end

    local result = { pcall(method, object, ...) }
    if not result[1] then
        return nil
    end

    return unpack(result, 2)
end

local function dormant_value(object, name)
    if object == nil then
        return nil
    end

    local ok, value = pcall(function()
        return object[name]
    end)

    if ok then
        return value
    end

    return nil
end

local function dormant_is_selected(item, name)
    if item == nil then
        return false
    end

    local ok, value = pcall(function()
        return item:get(name)
    end)

    return ok and value == true
end

local function dormant_default_config()
    return {
        accuracy = 90,
        hitboxes = {
            "Head",
            "Chest",
            "Stomach",
            "Legs"
        }
    }
end

local function dormant_get_config()
    local weapon_name = dormant_controls.weapon:get()
    if weapon_name == nil then
        return nil
    end

    local config = dormant_store[weapon_name]
    if config == nil then
        config = dormant_default_config()
        dormant_store[weapon_name] = config
    end

    return config
end

dormant_controls.accuracy:set_callback(function(item)
    local config = dormant_get_config()
    if config ~= nil then
        config.accuracy = item:get()
    end
end)

dormant_controls.hitboxes:set_callback(function(item)
    local config = dormant_get_config()
    if config ~= nil then
        local selected = {}

        for i = 1, #DORMANT_HITBOXES do
            local name = DORMANT_HITBOXES[i]

            if dormant_is_selected(item, name) then
                selected[#selected + 1] = name
            end
        end

        if #selected == 0 then
            selected = {
                "Head",
                "Chest",
                "Stomach",
                "Legs"
            }

            dormant_controls.hitboxes:set(unpack(selected))
        end

        config.hitboxes = selected
    end
end)

dormant_controls.weapon:set_callback(function(item)
    local config = dormant_get_config()
    if config ~= nil then
        dormant_controls.accuracy:set(config.accuracy)
        dormant_controls.hitboxes:set(unpack(config.hitboxes))
    end
end, true)

local function dormant_set_esp(state)
    if dormant_esp_ref == nil then
        return
    end

    if state then
        if not dormant_esp_overridden then
            override(dormant_esp_ref, true)
            dormant_esp_overridden = true
        end
    elseif dormant_esp_overridden then
        override(dormant_esp_ref, nil)
        dormant_esp_overridden = false
    end
end

menu.dormant_aimbot:set_callback(function(item)
    dormant_set_esp(item:get())
end, true)

local function dormant_is_active()
    return menu.dormant_aimbot:get() == true
end

local function dormant_is_whitelisted(player)
    if plist == nil then
        return false
    end

    local index = dormant_call(player, "get_index")
    if index == nil then
        return false
    end

    local ok, getter = pcall(function()
        return plist.get
    end)

    if not ok or type(getter) ~= "function" then
        return false
    end

    local success, value = pcall(getter, index, "Add to whitelist")
    return success and (value == true or value == 1 or value == "On")
end

local function dormant_get_bbox(player)
    local bbox = dormant_call(player, "get_bbox")
    if type(bbox) ~= "table" then
        return nil
    end

    return bbox
end

local function dormant_get_alpha(player)
    local bbox = dormant_get_bbox(player)
    if bbox == nil or type(bbox.alpha) ~= "number" then
        return 0, bbox
    end

    local alpha = bbox.alpha
    if alpha > 1 then
        alpha = alpha / 255
    end

    return alpha, bbox
end

local function dormant_has_usable_esp(player)
    if player == nil
        or dormant_call(player, "is_alive") ~= true
        or dormant_call(player, "is_enemy") ~= true
        or dormant_call(player, "is_dormant") ~= true
        or dormant_call(player, "is_visible") == true
        or dormant_is_whitelisted(player)
    then
        return false
    end

    local network_state = dormant_call(player, "get_network_state")
    if network_state ~= 1 and network_state ~= 2 then
        return false
    end

    local alpha = dormant_get_alpha(player)
    return type(alpha) == "number" and alpha > 0
end

local function dormant_update_last_seen()
    local players = entity.get_players(true, true) or {}

    for i = 1, #players do
        local player = players[i]

        if player ~= nil
            and dormant_call(player, "is_alive") == true
            and dormant_call(player, "is_enemy") == true
        then
            local alpha = dormant_get_alpha(player)
            local index = dormant_call(player, "get_index")

            if index ~= nil then
                if alpha < 1 then
                    dormant_last_seen[index] = player
                else
                    dormant_last_seen[index] = nil
                end
            end
        end
    end

    for index, player in pairs(dormant_last_seen) do
        if player == nil
            or dormant_call(player, "is_alive") ~= true
            or dormant_call(player, "is_enemy") ~= true
        then
            dormant_last_seen[index] = nil
        end
    end
end

local function dormant_get_weapon_group(weapon, info)
    local weapon_type = read_number(info, "weapon_type")
    local weapon_index = dormant_call(weapon, "get_weapon_index")

    if weapon_type == 1 then
        if weapon_index == 1 then
            return "Desert Eagle"
        end

        if weapon_index == 64 then
            return "Revolver R8"
        end

        return "Pistols"
    end

    if weapon_type == 5 then
        if weapon_index == 40 then
            return "Scout"
        end

        if weapon_index == 9 then
            return "AWP"
        end

        return "Auto Snipers"
    end

    return nil
end

local function dormant_contains(list, value)
    for i = 1, #list do
        if list[i] == value then
            return true
        end
    end

    return false
end

local function dormant_get_selected_hitboxes(config)
    local selected = {}

    if config ~= nil and type(config.hitboxes) == "table" then
        for i = 1, #DORMANT_HITBOXES do
            local name = DORMANT_HITBOXES[i]

            if dormant_contains(config.hitboxes, name) then
                selected[#selected + 1] = name
            end
        end
    end

    if #selected == 0 then
        selected = {
            "Head",
            "Chest",
            "Stomach",
            "Legs"
        }
    end

    return selected
end

local function dormant_get_min_damage(target)
    local damage = dormant_call(dormant_min_damage, "get")
    if type(damage) ~= "number" then
        damage = 1
    end

    local health = read_number(target, "m_iHealth") or 100
    if damage > 100 then
        damage = damage - 100 + health
    end

    return damage
end

local function dormant_make_points(start_pos, center, radius)
    local dx = center.x - start_pos.x
    local dy = center.y - start_pos.y
    local yaw = math.atan2(dy, dx)
    local side = vector(
        math.cos(yaw + math.pi * 0.5),
        math.sin(yaw + math.pi * 0.5),
        0
    ) * radius

    return {
        {
            text = "Middle",
            vec = center
        },
        {
            text = "Left",
            vec = center + side
        },
        {
            text = "Right",
            vec = center - side
        }
    }
end

local function dormant_trace_damage(local_player, target, start_pos, end_pos)
    local ok, damage, trace = pcall(
        utils.trace_bullet,
        local_player,
        start_pos,
        end_pos
    )

    if not ok or type(damage) ~= "number" or damage <= 0 or trace == nil then
        return nil
    end

    local hit_entity = dormant_value(trace, "entity")

    if type(hit_entity) == "number" then
        hit_entity = entity.get(hit_entity)
    end

    if hit_entity == nil then
        return nil
    end

    local target_index = dormant_call(target, "get_index")
    local hit_index = dormant_call(hit_entity, "get_index")

    if hit_entity ~= target and (target_index == nil or hit_index ~= target_index) then
        return nil
    end

    return damage
end

local function dormant_point_damage(local_player, target, start_pos, end_pos, min_damage)
    local damage = dormant_trace_damage(local_player, target, start_pos, end_pos)

    if damage ~= nil and damage > min_damage then
        return damage
    end

    return nil
end

local function dormant_find_accurate_point(local_player, target, eye_pos, selected_hitboxes, min_damage)
    local origin = dormant_call(target, "get_origin")
    local reference_hitbox = dormant_call(target, "get_hitbox_position", 4)

    if origin == nil
        or reference_hitbox == nil
        or math.abs(origin.x - reference_hitbox.x) >= 7
    then
        return nil
    end

    local history_hitboxes = {
        { index = 0, name = "Head" },
        { index = 2, name = "Stomach" },
        { index = 4, name = "Stomach" },
        { index = 5, name = "Chest" },
        { index = 6, name = "Chest" }
    }

    for i = 1, #history_hitboxes do
        local history = history_hitboxes[i]

        if dormant_contains(selected_hitboxes, history.name) then
            local position = dormant_call(target, "get_hitbox_position", history.index)

            if position ~= nil then
                local points = dormant_make_points(eye_pos, position, 3)

                for j = 1, #points do
                    local point = points[j].vec
                    local damage = dormant_trace_damage(
                        local_player,
                        target,
                        eye_pos,
                        point
                    )

                    if damage ~= nil then
                        if history.name == "Head" then
                            damage = damage * 4
                        end

                        if damage > min_damage then
                            return point, damage, history.name, nil
                        end
                    end
                end
            end
        end
    end

    return nil
end

local function dormant_find_standard_point(local_player, target, eye_pos, selected_hitboxes, min_damage)
    local origin = dormant_call(target, "get_origin")
    if origin == nil then
        return nil
    end

    local duck_amount = read_number(target, "m_flDuckAmount") or 0

    local base_points = {
        {
            scale = 5,
            hitbox = "Stomach",
            offset = vector(0, 0, 40)
        },
        {
            scale = 6,
            hitbox = "Chest",
            offset = vector(0, 0, 50 - duck_amount * 4)
        },
        {
            scale = 3,
            hitbox = "Head",
            offset = vector(0, 0, 58 - duck_amount * 10)
        },
        {
            scale = 4,
            hitbox = "Legs",
            offset = vector(0, 0, 20)
        }
    }

    for i = 1, #base_points do
        local hitbox = base_points[i]

        if dormant_contains(selected_hitboxes, hitbox.hitbox) then
            local center = origin + hitbox.offset
            local points = dormant_make_points(eye_pos, center, hitbox.scale)

            for j = 1, #points do
                local point = points[j].vec
                local damage = dormant_point_damage(
                    local_player,
                    target,
                    eye_pos,
                    point,
                    min_damage
                )

                if damage ~= nil then
                    return point, damage, hitbox.hitbox, points[j].text
                end
            end
        end
    end

    return nil
end

local function dormant_limit_movement(cmd, max_speed)
    if type(max_speed) ~= "number" or max_speed <= 0 then
        return
    end

    local movement = math.sqrt(
        cmd.forwardmove * cmd.forwardmove
        + cmd.sidemove * cmd.sidemove
    )

    if movement <= 0 then
        return
    end

    if cmd.in_duck == 1 or cmd.in_duck == true then
        max_speed = max_speed * 2.94117647
    end

    if movement <= max_speed then
        return
    end

    local scale = max_speed / movement
    cmd.forwardmove = cmd.forwardmove * scale
    cmd.sidemove = cmd.sidemove * scale
end

local function dormant_get_targets(config)
    local players = entity.get_players(true, true) or {}
    local targets = {}
    local accuracy = config and config.accuracy or 90

    for i = 1, #players do
        local player = players[i]

        if dormant_has_usable_esp(player) then
            local alpha = dormant_get_alpha(player)

            if accuracy < math.floor(alpha * 100) + 5 then
                targets[#targets + 1] = player
            end
        end
    end

    return targets
end

local function dormant_can_fire(local_player, weapon, info)
    local now = read_number(local_player, "m_flSimulationTime") or globals.curtime
    local next_primary = read_number(weapon, "m_flNextPrimaryAttack") or 0
    local is_revolver = dormant_value(info, "is_revolver") == true

    if is_revolver then
        return now > next_primary
    end

    local next_secondary = read_number(weapon, "m_flNextSecondaryAttack") or 0
    local next_player_attack = read_number(local_player, "m_flNextAttack") or 0
    local next_attack = math.max(next_player_attack, next_primary, next_secondary)

    return now > next_attack
end

local function dormant_set_status(has_targets, target_found)
    dormant_has_targets = has_targets == true
    dormant_target_found = target_found == true
end

local lagrecord_update_callback

if lagrecord ~= nil then
    lagrecord_update_callback = function(player)
        if player ~= nil and player:is_enemy() and player:is_alive() then
            return true
        end
    end

    pcall(lagrecord.set_update_callback, lagrecord_update_callback)
end

local function dormant_get_lerp_time()
    local interp = 0
    local ratio = 1
    local update_rate = 64

    pcall(function()
        interp = cvar.cl_interp:float()
        ratio = cvar.cl_interp_ratio:float()
        update_rate = cvar.cl_updaterate:float()
    end)

    if type(interp) ~= "number" or interp < 0 then
        interp = 0
    end

    if type(ratio) ~= "number" or ratio < 0 then
        ratio = 1
    end

    if type(update_rate) ~= "number" or update_rate <= 0 then
        update_rate = 64
    end

    return math.max(interp, ratio / update_rate)
end

local function dormant_get_max_unlag()
    local max_unlag = 0

    pcall(function()
        max_unlag = cvar.sv_maxunlag:float()
    end)

    if type(max_unlag) ~= "number" or max_unlag <= 0 then
        return nil
    end

    return max_unlag
end

local function dormant_find_lagrecord_point(local_player, target, eye_pos, selected_hitboxes, min_damage)
    if lagrecord == nil or dormant_controls.lagrecords:get() ~= true then
        return nil
    end

    local ok, records = pcall(lagrecord.get_all, target)
    if not ok or type(records) ~= "table" or #records == 0 then
        return nil
    end

    local tick_interval = globals.tickinterval
    if type(tick_interval) ~= "number" or tick_interval <= 0 then
        return nil
    end

    local max_unlag = dormant_get_max_unlag()
    if max_unlag == nil then
        return nil
    end

    local configured_age = dormant_controls.record_age:get() / 1000
    local max_age = math.min(configured_age, max_unlag)
    local current_origin = dormant_call(target, "get_origin")
    if current_origin == nil then
        return nil
    end

    local lerp_time = dormant_get_lerp_time()
    local hitbox_fractions = {
        Head = 0.86,
        Chest = 0.70,
        Stomach = 0.51,
        Legs = 0.22
    }

    local record_indices = {}

    for record_index, record in pairs(records) do
        if type(record_index) == "number" and type(record) == "table" then
            record_indices[#record_indices + 1] = record_index
        end
    end

    table.sort(record_indices)

    for record_position = 1, #record_indices do
        local record = records[record_indices[record_position]]
        local simulation_time = dormant_value(record, "simulation_time")
        local origin = dormant_value(record, "origin")
        local volume = dormant_value(record, "volume")

        if type(simulation_time) == "number"
            and origin ~= nil
            and type(volume) == "table"
            and volume[1] ~= nil
            and volume[2] ~= nil
        then
            local age = globals.curtime - simulation_time
            local age_valid = age >= -tick_interval and age <= max_age
            local distance_valid = current_origin:distsqr(origin) <= 4096

            if age_valid and distance_valid then
                local mins = volume[1]
                local maxs = volume[2]
                local min_z = read_number(mins, "z")
                local max_z = read_number(maxs, "z")
                local width_x = read_number(maxs, "x") and read_number(mins, "x")
                    and math.abs(maxs.x - mins.x) or 0
                local width_y = read_number(maxs, "y") and read_number(mins, "y")
                    and math.abs(maxs.y - mins.y) or 0

                if min_z ~= nil and max_z ~= nil then
                    local height = max_z - min_z
                    local radius = clamp(math.max(width_x, width_y) * 0.25, 2, 5)

                    if height >= 30 and height <= 100 then
                        local desired_tick = math.floor(
                            (simulation_time + lerp_time) / tick_interval + 0.5
                        )
                        local backtrack_ticks = globals.tickcount - desired_tick
                        local max_ticks = math.floor(max_unlag / tick_interval)

                        if backtrack_ticks >= 0 and backtrack_ticks <= max_ticks then
                            for hitbox_index = 1, #DORMANT_HITBOXES do
                                local hitbox_name = DORMANT_HITBOXES[hitbox_index]
                                local fraction = hitbox_fractions[hitbox_name]

                                if dormant_contains(selected_hitboxes, hitbox_name) then
                                    local center = origin + vector(
                                        0,
                                        0,
                                        min_z + height * fraction
                                    )

                                    local points = dormant_make_points(eye_pos, center, radius)

                                    for point_index = 1, #points do
                                        local point = points[point_index].vec
                                        local damage = dormant_point_damage(
                                            local_player,
                                            target,
                                            eye_pos,
                                            point,
                                            min_damage
                                        )

                                        if damage ~= nil then
                                            return point,
                                                damage,
                                                hitbox_name,
                                                points[point_index].text,
                                                record,
                                                desired_tick
                                        end
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
    end

    return nil
end

local function dormant_on_createmove(cmd)
    dormant_update_last_seen()
    dormant_set_status(false, false)

    if dormant_pending_shot ~= nil
        and globals.tickcount - dormant_pending_shot.tick > 8
    then
        dormant_pending_shot = nil
    end

    if not dormant_is_active() then
        return
    end

    local local_player = entity.get_local_player()
    if local_player == nil or not local_player:is_alive() then
        return
    end

    if globals.tickcount < dormant_round_lock then
        return
    end

    local threat = entity.get_threat()
    if threat ~= nil
        and threat:is_alive()
        and threat:is_enemy()
        and not threat:is_dormant()
    then
        return
    end

    local weapon = local_player:get_player_weapon()
    if weapon == nil or dormant_call(weapon, "is_weapon") ~= true then
        return
    end

    local info = dormant_call(weapon, "get_weapon_info")
    if info == nil then
        return
    end

    local weapon_group = dormant_get_weapon_group(weapon, info)
    if weapon_group == nil then
        return
    end

    local config = dormant_store[weapon_group]
    if config == nil then
        config = dormant_default_config()
        dormant_store[weapon_group] = config
    end

    local selected_hitboxes = dormant_get_selected_hitboxes(config)
    local scoped_value = dormant_value(local_player, "m_bIsScoped")
    local scoped = scoped_value == true or scoped_value == 1
    local flags = read_number(local_player, "m_fFlags") or 0
    local on_ground = bit.band(flags, 1) == 1

    if (cmd.in_jump == 1 or cmd.in_jump == true) and not on_ground then
        return
    end

    if not dormant_can_fire(local_player, weapon, info) then
        return
    end

    if cmd.in_attack == 1 or cmd.in_attack == true then
        return
    end

    local targets = dormant_get_targets(config)
    if #targets == 0 then
        dormant_target_cursor = 1
        return
    end

    dormant_set_status(true, false)

    if globals.tickcount % #targets ~= 0 then
        dormant_target_cursor = dormant_target_cursor + 1
    else
        dormant_target_cursor = 1
    end

    local target = targets[dormant_target_cursor]
    if target == nil then
        dormant_target_cursor = 1
        target = targets[1]
    end

    if target == nil then
        return
    end

    local eye_pos = dormant_call(local_player, "get_eye_position")
    if eye_pos == nil then
        return
    end

    local min_damage = dormant_get_min_damage(target)
    local point, damage, hitbox, point_name
    local selected_record, selected_record_tick
    local use_lagrecords = dormant_controls.lagrecords:get() == true

    if use_lagrecords then
        point, damage, hitbox, point_name, selected_record, selected_record_tick =
            dormant_find_lagrecord_point(
                local_player,
                target,
                eye_pos,
                selected_hitboxes,
                min_damage
            )
    else
        if dormant_is_selected(dormant_controls.options, "Accurate history") then
            point, damage, hitbox, point_name = dormant_find_accurate_point(
                local_player,
                target,
                eye_pos,
                selected_hitboxes,
                min_damage
            )
        end

        if point == nil then
            point, damage, hitbox, point_name = dormant_find_standard_point(
                local_player,
                target,
                eye_pos,
                selected_hitboxes,
                min_damage
            )
        end
    end

    if point == nil or damage == nil then
        return
    end

    if dormant_call(target, "is_dormant") ~= true
        or not dormant_has_usable_esp(target)
    then
        return
    end

    dormant_set_status(true, true)

    local max_speed = scoped
        and read_number(info, "max_player_speed_alt")
        or read_number(info, "max_player_speed")

    dormant_limit_movement(
        cmd,
        type(max_speed) == "number" and max_speed * 0.33 or 0
    )

    if not scoped
        and read_number(info, "weapon_type") == 5
        and (cmd.in_jump == 0 or cmd.in_jump == false or cmd.in_jump == nil)
        and on_ground
    then
        cmd.in_attack2 = true
    end

    local inaccuracy = dormant_call(weapon, "get_inaccuracy")
    if type(inaccuracy) ~= "number" or inaccuracy >= 0.01 then
        return
    end

    if use_lagrecords then
        if selected_record == nil or selected_record_tick == nil then
            return
        end

        local tick_set = pcall(function()
            cmd.tickcount = selected_record_tick
        end)

        if not tick_set then
            return
        end

        local tick_read_ok, applied_tick = pcall(function()
            return cmd.tickcount
        end)

        if tick_read_ok and applied_tick ~= selected_record_tick then
            return
        end
    end

    local delta = point - eye_pos
    local horizontal = math.sqrt(delta.x * delta.x + delta.y * delta.y)
    local pitch = -math.deg(math.atan2(delta.z, horizontal))
    local yaw = math.deg(math.atan2(delta.y, delta.x))

    cmd.view_angles = vector(pitch, yaw, 0)
    cmd.in_attack = true

    dormant_pending_shot = {
        target = target,
        target_index = dormant_call(target, "get_index"),
        target_name = dormant_call(target, "get_name") or "unknown",
        hitbox = hitbox or "unknown",
        point = point_name,
        damage = damage,
        record_tick = selected_record_tick,
        record_simulation_time = selected_record and selected_record.simulation_time or nil,
        tick = globals.tickcount,
        fired = false,
        hit = false
    }
end

local function dormant_on_bullet_fire(event)
    local local_player = entity.get_local_player()
    if local_player == nil or dormant_pending_shot == nil then
        return
    end

    local shooter = event.entity
    if shooter ~= local_player then
        return
    end

    local shot = dormant_pending_shot
    if globals.tickcount - shot.tick > 3 then
        return
    end

    shot.fired = true

    if dormant_is_selected(dormant_controls.options, "Log shots") then
        common.add_event(
            "Dormant shot → " .. shot.target_name .. " [" .. shot.hitbox .. "]",
            "crosshairs"
        )
    end

    if type(utils.execute_after) == "function" then
        utils.execute_after(0.18, function()
            if dormant_pending_shot == shot then
                if not shot.hit and dormant_is_selected(dormant_controls.options, "Log shots") then
                    common.add_event(
                        "Dormant miss → " .. shot.target_name,
                        "crosshairs"
                    )
                end

                dormant_pending_shot = nil
            end
        end)
    end
end

local function dormant_on_player_hurt(event)
    local local_player = entity.get_local_player()
    if local_player == nil or dormant_pending_shot == nil then
        return
    end

    local attacker = entity.get(event.attacker, true)
    local victim = entity.get(event.userid, true)

    if attacker ~= local_player or victim == nil then
        return
    end

    local victim_index = dormant_call(victim, "get_index")
    if victim_index ~= dormant_pending_shot.target_index then
        return
    end

    dormant_pending_shot.hit = true

    if dormant_is_selected(dormant_controls.options, "Log shots") then
        common.add_event(
            "Dormant hit → " .. dormant_pending_shot.target_name,
            "crosshairs"
        )
    end
end

local function dormant_on_round_prestart()
    local freeze_time = 0

    pcall(function()
        freeze_time = cvar.mp_freezetime:get_float()
    end)

    local tick_interval = globals.tickinterval
    if type(tick_interval) ~= "number" or tick_interval <= 0 then
        tick_interval = 1 / 64
    end

    dormant_round_lock = globals.tickcount
        + math.floor((freeze_time + 1) / tick_interval)

    dormant_pending_shot = nil
    dormant_target_cursor = 1
    dormant_set_status(false, false)
end

local function dormant_on_render()
    if not menu.dormant_aimbot:get()
        or not dormant_is_selected(dormant_controls.options, "Indicator")
        or not dormant_is_active()
    then
        return
    end

    local screen = render.screen_size()
    local indicator_color

    if dormant_target_found then
        indicator_color = color(143, 194, 21, 255)
    elseif not dormant_has_targets then
        indicator_color = color(255, 0, 50, 255)
    else
        indicator_color = color(255, 255, 255, 200)
    end

    render.text(
        1,
        vector(screen.x * 0.5, screen.y * 0.5 + 42),
        indicator_color,
        "c",
        "DA"
    )
end

local function dormant_draw_last_seen()
    if not menu.dormant_aimbot:get()
        or not dormant_is_selected(dormant_controls.options, "Draw position")
    then
        return
    end

    local draw_color = dormant_controls.lastseen_color:get()
    if draw_color == nil then
        draw_color = color(255, 255, 255, 255)
    end

    for _, player in pairs(dormant_last_seen) do
        if player ~= nil
            and dormant_call(player, "is_alive") == true
            and dormant_call(player, "is_enemy") == true
            and dormant_call(player, "is_dormant") == true
            and dormant_has_usable_esp(player)
        then
            local origin = dormant_call(player, "get_origin")
            local reference_hitbox = dormant_call(player, "get_hitbox_position", 4)

            if origin ~= nil
                and reference_hitbox ~= nil
                and math.abs(origin.x - reference_hitbox.x) < 7
            then
                local screen_pos = origin:to_screen()

                if screen_pos ~= nil then
                    render.circle(screen_pos, draw_color, 4, 0, 1)
                    render.text(
                        1,
                        screen_pos + vector(0, 9),
                        draw_color,
                        "c",
                        "last"
                    )
                end
            end
        end
    end
end

events.createmove:set(dormant_on_createmove)
events.bullet_fire:set(dormant_on_bullet_fire)
events.player_hurt:set(dormant_on_player_hurt)
events.round_prestart:set(dormant_on_round_prestart)
events.render:set(dormant_on_render)
events.render:set(dormant_draw_last_seen)

events.shutdown:set(function()
    dormant_set_esp(false)
    dormant_pending_shot = nil
    dormant_last_seen = {}
    dormant_set_status(false, false)

    if lagrecord ~= nil and lagrecord_update_callback ~= nil then
        pcall(lagrecord.unset_update_callback, lagrecord_update_callback)
    end
end)


events.shutdown:set(function()
    fps_booster_apply(false)
    reflex_enabled = false
    reflex_restore()
    reset_overrides()
end)
