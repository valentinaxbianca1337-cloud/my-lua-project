local Backtrack = (function()
local M = {}
local TEMPLATE = "803d44332211000f84960200009c6083ec300f1114240f115c24100fae5c24208b4424200d801f0000894424240fae542424660f7ec0250000807f3d0000807f0f844a020000660f7ec8250000807f3d0000807f0f84360200008b4a0883f9020f822a02000081f9000100000f871e0200008d59ff85d90f85130200008b471083f8020f820702000039c80f87ff0100008b520481fa000001000f82f001000081fa00fcffff0f87e40100008b4f0c21d98b2c8a8b4f0c01c14921d98b348a81fd000001000f82c501000081fe000001000f82b901000081fd40ffffff0f87ad01000081fe40ffffff0f87a10100008b4524250000807f3d0000807f0f848e0100008b4624250000807f3d0000807f0f847b010000f30f1056240f57db0f2ed30f866a0100000f2e55240f83600100008b15554433228b1285d20f845001000089f829d00f824601000031d2b940090100f7f185d20f853501000083f8010f822c01000083f8400f8723010000f30f101485665544330f2e562476100f8a0e0100000f2e55240f86b2000000f30f105500f30f5c16f30f59d2f30f105d04f30f5c5e04f30f59dbf30f58d3f30f105d08f30f5c5e08f30f59dbf30f58d3660f7ed0250000807f3d0000807f0f84bf0000000f2e15776655440f8ab2000000735ef30f105568f30f5c5668660f7ed0250000807f3d0000807f0f84920000000f2e15998877660f8a850000007608f30f5c15785634120f2e15aa9988777308f30f5815785634120f57dbf30f5cdaf30f5fd30f2e15887766557a567702eb07837c2434007529803d44332211007442f0ff05ab8967450f1014240f105c24100fae54242083c430619dff2589674523803d443322110074190f1014240f105c24100fae54242083c430619dff259a7856340f1014240f105c24100fae54242083c430619d0f2ec87606ff2589674523ff259a785634"
local SLOTS = {
    enabled = { 2, 583, 624 },
    manager = { 306 },
    shots = { 370 },
    distance = { 468 },
    angle = { 564 },
    positive180 = { 513 },
    negative180 = { 536 },
    full360 = { 529, 546 },
    select = { 618, 682 },
    skip = { 652, 688 },
    counter = { 593 },
}
local function pack32(n)
    local out = {}
    n = n % 4294967296
    for i=1,4 do out[i]=string.char(n%256); n=math.floor(n/256) end
    return table.concat(out)
end
local function unhex(s)
    return (s:gsub('..',function(p)return string.char(tonumber(p,16))end))
end
function M.materialize(data)
    local code = unhex(TEMPLATE)
    local values={enabled=data, manager=data+0xC, shots=data+0x100,
        distance=data+0x20,angle=data+0x24,positive180=data+0x28,
        negative180=data+0x2C,full360=data+0x30,select=data+0x10,
        skip=data+0x14,counter=data+8}
    for name,offsets in pairs(SLOTS) do
        for _,offset in ipairs(offsets) do
            code=code:sub(1,offset)..pack32(values[name])..code:sub(offset+5)
        end
    end
    return code
end
local function main_menu()
    return globals.is_in_game == false and entity.get_local_player() == nil
end
function M.native_api()
    local ffi=require('ffi')
    assert(ffi.os=='Windows' and ffi.abi('32bit'),'Win32 CS:GO required')
    local function bind(name,decl,signature)
        local ok,value=pcall(function()return ffi.C[name]end)
        if not ok then ffi.cdef(decl);value=ffi.C[name] end
        return ffi.cast(signature,ffi.cast('void*',value))
    end
    local query=bind('VirtualQuery','size_t __stdcall VirtualQuery(const void*, void*, size_t);',
        'size_t(__stdcall*)(const void*, void*, size_t)')
    local alloc=bind('VirtualAlloc','void* __stdcall VirtualAlloc(void*, size_t, unsigned long, unsigned long);',
        'void*(__stdcall*)(void*, size_t, unsigned long, unsigned long)')
    local protect=bind('VirtualProtect','int __stdcall VirtualProtect(void*, size_t, unsigned long, unsigned long*);',
        'int(__stdcall*)(void*, size_t, unsigned long, unsigned long*)')
    local flush=bind('FlushInstructionCache','int __stdcall FlushInstructionCache(void*, const void*, size_t);',
        'int(__stdcall*)(void*, const void*, size_t)')
    local process=bind('GetCurrentProcess','void* __stdcall GetCurrentProcess(void);','void*(__stdcall*)(void)')()
    return {ffi=ffi,query=query,alloc=alloc,protect=protect,flush=flush,process=process}
end
function M.backend(api)
    assert(main_menu(),'First activation requires main menu')
    api=api or M.native_api()
    local ffi=api.ffi
    local base=0x412A0000
    local target=base+0x1EF4B9
    local original=unhex('0f2ec87669')
    local function pointer(n)return ffi.cast('void*',n)end
    local function number(p)return tonumber(ffi.cast('uintptr_t',p))end
    local function get32(n)return tonumber(ffi.cast('uint32_t*',n)[0])end
    local function put32(n,v)ffi.cast('uint32_t*',n)[0]=v end
    local function region(n)
        local info=ffi.new('uint32_t[7]')
        if api.query(pointer(n),info,28)~=28 then return nil end
        return {first=tonumber(info[0]),allocation=tonumber(info[1]),size=tonumber(info[3]),
            state=tonumber(info[4]),protection=tonumber(info[5])}
    end
    local permissions={[2]=true,[4]=true,[8]=true,[0x20]=true,[0x40]=true,[0x80]=true}
    local function readable(n,size)
        if n<0x10000 or n+size>0xFFFFFFFF then return false end
        local ending=n+size
        for _=1,4 do
            if n>=ending then return true end
            local r=region(n)
            if not r or r.state~=0x1000 or not permissions[r.protection%256]
                or math.floor(r.protection/256)%2==1 or r.first+r.size<=n then return false end
            n=r.first+r.size
        end
        return n>=ending
    end
    local function read(n,size)
        assert(readable(n,size),'Selector memory unavailable / unsupported build')
        return ffi.string(pointer(n),size)
    end
    local function jump(n,to)return '\233'..pack32(to-n-5)end
    local checks={
        {0x1EF180,'5553575683ec108b4c2424'},
        {0x1EF196,'8b2d4c004b42'},
        {0x1EF1D2,'69f84009010031f6837c3d1000'},
        {0x1EF3EC,'e8ff17f7ff'},
        {0x160BF0,'53575683ec1489ce8b7c242c'},
        {0x1EF441,'e88aa0f6ff84c00f84cf030000'},
        {0x1EF460,'8b42048b4a084921d98b04888b4c2430'},
        {0x1EF4A1,'f30f58c20fc6d255f30f58d00f57c0f30f51c2f30f100c24'},
        {0x1EF4BE,'89c60f28c8eb62'},
        {0x1EF4E1,'f681b000000008f30f100c240f85930200008b048780b8a4000000008b7c24087524e9da020000'},
        {0x1EF527,'0fb780b0000000a908080000750f43'}
    }
    local function validate()
        for _,check in ipairs(checks) do
            local bytes=unhex(check[2])
            assert(read(base+check[1],#bytes)==bytes,'Unsupported selector build / conflicting patch')
        end
    end
    validate()
    local code,data
    local installed=false
    if read(target,1)=='\233' then
        local delta=tonumber(ffi.cast('int32_t*',target+1)[0])
        code=(target+5+delta-0x100)%4294967296
        assert(code%4096==0 and read(code,0x50):sub(1,8)=='BIREC004','Unknown selector hook; restart CS:GO')
        assert(get32(code+8)==4 and get32(code+0xC)==base,'Selector header differs')
        data=get32(code+0x10)
        assert(data%4096==0 and readable(data,0x210),'Selector data unavailable')
        local r=region(data)
        assert(r.protection%256==4,'Selector data protection differs')
        assert(get32(data+4)==0,'Another selector session is loaded')
        installed=true
    else
        assert(read(target,5)==original,'Conflicting selector patch')
        local cp=api.alloc(nil,4096,0x3000,4)
        local dp=api.alloc(nil,4096,0x3000,4)
        assert(cp~=nil and dp~=nil,'Selector allocation failed')
        code,data=number(cp),number(dp)
        ffi.fill(cp,4096,0xCC);ffi.fill(dp,4096,0)
        ffi.copy(cp,'BIREC004',8)
        put32(code+8,4);put32(code+0xC,base);put32(code+0x10,data)
        ffi.copy(pointer(code+0x40),original,5)
        put32(data+0xC,base+0x121004C)
        put32(data+0x10,base+0x1EF4BE);put32(data+0x14,base+0x1EF527)
        local constants={[0x20]=64,[0x24]=8,[0x28]=180,[0x2C]=-180,[0x30]=360}
        for offset,value in pairs(constants) do ffi.cast('float*',data+offset)[0]=value end
        local bytes=M.materialize(data)
        ffi.copy(pointer(code+0x100),bytes,#bytes)
        local old=ffi.new('unsigned long[1]')
        assert(api.protect(cp,4096,0x20,old)~=0,'Cannot protect selector code')
        assert(api.flush(api.process,cp,4096)~=0,'Cannot flush selector code')
    end
    local native=M.materialize(data)
    assert(read(code+0x40,5)==original,'Selector saved bytes differ')
    assert(read(code+0x100,#native)==native,'Selector code differs')
    assert(get32(data+0xC)==base+0x121004C,'Selector manager differs')
    assert(get32(data+0x10)==base+0x1EF4BE and get32(data+0x14)==base+0x1EF527,'Selector return targets differ')
    assert(read(data+0x20,20)==unhex('000080420000004100003443000034c30000b443'),'Selector constants differ')
    local replacement=jump(target,code+0x100)
    assert(read(target,5)==(installed and replacement or original),'Selector target differs')
    ffi.cast('uint8_t*',data)[0]=0
    put32(data+4,1)
    ffi.fill(pointer(data+0x100),65*4,0)
    local backend={installed=installed,code=code,data=data,base=base}
    function backend:set_enabled(value)ffi.cast('uint8_t*',data)[0]=value and 1 or 0 end
    local saved_protection
    local function write(bytes)
        local old=ffi.new('unsigned long[1]')
        assert(api.protect(pointer(target),5,0x40,old)~=0,'Cannot change selector protection')
        saved_protection=saved_protection or tonumber(old[0])
        ffi.copy(pointer(target),bytes,5)
        assert(api.protect(pointer(target),5,saved_protection,old)~=0,'Cannot restore selector protection')
        assert(api.flush(api.process,pointer(target),5)~=0,'Cannot flush selector patch')
    end
    local function transaction(wanted)
        assert(main_menu(),'Selector attach/detach requires main menu')
        backend:set_enabled(false)
        validate()
        local before,after=wanted and original or replacement,wanted and replacement or original
        assert(read(target,5)==before,'Conflicting selector hook')
        local ok,err=pcall(write,after)
        if not ok then
            local rolled_back=pcall(write,before)
            error(tostring(err)..(rolled_back and '' or '; rollback incomplete; restart CS:GO'))
        end
        backend.installed=wanted
    end
    function backend:attach()if not self.installed then transaction(true)end end
    function backend:detach()if self.installed then transaction(false)end end
    function backend:update_shots()
        ffi.fill(pointer(data+0x100),65*4,0)
        if not globals.is_in_game then return end
        local ok,players=pcall(entity.get_players,true)
        if not ok or type(players)~='table' then return end
        for i=1,math.min(#players,64) do
            pcall(function()
                local player=players[i]
                if not player:is_alive() then return end
                local index=player:get_index()
                if type(index)~='number' or index<1 or index>64 or index%1~=0 then return end
                local weapon=player:get_player_weapon()
                local time=weapon and weapon.m_fLastShotTime
                if type(time)=='number' and time==time and time>0 and time<math.huge then
                    ffi.cast('float*',data+0x100)[index]=time
                end
            end)
        end
    end
    function backend:shutdown()
        self:set_enabled(false)
        if main_menu() then self:detach()end
        put32(data+4,0)
    end
    return backend
end

function M.create(group,running,decorate)
    local enabled=group:switch(decorate('Adaptive Backtrack'),false)
    local status=group:label('Selector status')
    status:visibility(false)
    local backend,updating,stopped,fault=nil,false,false,nil
    local object={enabled=enabled}
    local factory=function()return M.backend()end
    local function fail(err)
        if backend then pcall(backend.set_enabled,backend,false)end
        enabled:set(false)
        fault=tostring(err)
        status:name('Unavailable; see console')
        status:visibility(true)
        print('Bianca Utils selector: '..tostring(err))
    end
    function object:update()
        if stopped or not running() or updating then return end
        updating=true
        local wanted=enabled:get()
        if fault and not wanted then updating=false;return end
        if wanted then fault=nil end
        if wanted and not backend and not main_menu() then
            status:name('Enable in main menu');status:visibility(true)
            updating=false;return
        end
        local ok,err=pcall(function()
            if wanted and not backend then backend=factory()end
            if backend then
                if wanted then
                    if not backend.installed then
                        if not main_menu() then status:name('Enable in main menu');status:visibility(true);return end
                        backend:attach()
                    end
                    backend:set_enabled(true)
                else
                    backend:set_enabled(false)
                    if backend.installed and main_menu() then backend:detach()end
                end
            end
            if wanted then status:visibility(false)end
        end)
        if not ok then fail(err)end
        updating=false
    end
    function object:command()
        if stopped or not running() or not enabled:get() or not backend or not backend.installed then return end
        local ok,err=pcall(backend.update_shots,backend)
        if not ok then fail(err)end
    end
    enabled:set_callback(function(item)
        if not item:get() and backend then pcall(backend.set_enabled,backend,false)end
        status:visibility(false)
    end)
    function object:shutdown()
        stopped=true
        if backend then
            local ok,err=pcall(backend.shutdown,backend)
            if not ok then print('Bianca Utils selector cleanup: '..tostring(err))end
        end
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
local backtrack = Backtrack.create(tab_aimbot, function() return backtrack_running end,
    function(text) return with_icon("backtrack", text) end)
events.render:set(function()
    backtrack:update()
end)
events.createmove:set(function()
    backtrack:command()
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
end)



events.shutdown:set(function()
    fps_booster_apply(false)
    reflex_enabled = false
    reflex_restore()
    reset_overrides()
end)
