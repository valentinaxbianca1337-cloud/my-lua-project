local ShotResponse = (function()
local M={}
local DURATION,COOLDOWN,FIRE_AGE=1.25,.35,.3
local function finite(v)return type(v)=='number'and v==v and math.abs(v)~=math.huge end
local function call(object,key,...)
    if not object then return nil end
    local ok,value=pcall(function(...)return object[key](object,...)end,...)
    if ok then return value end
end
local function prop(object,key)
    if not object then return nil end
    local ok,value=pcall(function()return object[key]end)
    if ok then return value end
end
local function point(value)
    local x,y,z=prop(value,'x'),prop(value,'y'),prop(value,'z')
    if finite(x)and finite(y)and finite(z)then return {x=x,y=y,z=z}end
end
local function pressed(v)return v==true or v==1 end
function M.close_to_segment(a,b,p,radius)
    if not a or not b or not p then return false end
    local x,y,z=b.x-a.x,b.y-a.y,b.z-a.z
    local length=x*x+y*y+z*z
    if not finite(length)or length<1 then return false end
    local fraction=((p.x-a.x)*x+(p.y-a.y)*y+(p.z-a.z)*z)/length
    if fraction<=0 or fraction>1 then return false end
    local dx,dy,dz=a.x+x*fraction-p.x,a.y+y*fraction-p.y,a.z+z*fraction-p.z
    return dx*dx+dy*dy+dz*dz<=radius*radius
end
function M.create(group,find,running,decorate,suppressed)
    local enabled=group:switch(decorate(),false)
    local function angle(...)return find('Aimbot','Anti Aim','Angles',...)end
    local refs={enabled=angle('Enabled'),body=angle('Body Yaw'),
        inverter=angle('Body Yaw','Inverter'),freestanding=angle('Freestanding')}
    local fake_duck=find('Aimbot','Anti Aim','Misc','Fake Duck')
    local desired,expires,last_trigger,last_time,owned=nil,0,nil,nil,nil
    local fires,stopped={},false
    local object={enabled=enabled}
    local function override_value()
        return pcall(function()return refs.inverter:get_override()end)
    end
    local function effective(ref)
        local ok,value=pcall(function()return ref:get_override()end)
        if ok and value~=nil then return value end
        return call(ref,'get')
    end
    local function release()
        if owned then
            local ok,value=override_value()
            if ok and value==owned.applied then
                pcall(function()
                    if owned.before==nil then refs.inverter:override()
                    else refs.inverter:override(owned.before)end
                end)
            end
            owned=nil
        end
    end
    function object:reset()
        release();desired,expires,last_trigger,last_time=nil,0,nil,nil;fires={}
    end
    local function now()
        local value=globals.curtime
        if not finite(value)then object:reset();return nil end
        if last_time and value<last_time then object:reset()end
        last_time=value
        return value
    end
    local function eligible()
        if stopped or not running()or not enabled:get()or globals.is_in_game==false
            or(suppressed and suppressed())then return nil end
        if not pressed(effective(refs.enabled))or not pressed(effective(refs.body))
            or pressed(effective(refs.freestanding))or pressed(effective(fake_duck))then return nil end
        local player=entity.get_local_player()
        if player and call(player,'is_alive')==true then return player end
    end
    local function valid_enemy(shooter)
        if call(shooter,'is_alive')~=true or call(shooter,'is_enemy')~=true
            or call(shooter,'is_dormant')==true then return nil end
        local index=call(shooter,'get_index')
        if finite(index)and index%1==0 and index>=1 and index<=64 then return index end
    end
    local function clock_and_player()
        local time=now()
        local player=time and eligible()or nil
        if not player then object:reset();return nil end
        return time,player
    end
    function object:fire(event)
        local time=clock_and_player()
        if not time then return end
        local shooter=prop(event,'entity')
        local index=valid_enemy(shooter)
        if not index then return end
        local origin=point(call(shooter,'get_eye_position'))
        if origin then fires[index]={time=time,origin=origin}end
    end
    function object:impact(event)
        local time,player=clock_and_player()
        if not time then return end
        if last_trigger and time-last_trigger<COOLDOWN then return end
        local userid=prop(event,'userid')
        if not finite(userid)then return end
        local shooter=entity.get(userid,true)
        local index=valid_enemy(shooter)
        if not index then return end
        local finish=point(event)
        if not finish then return end
        local fire=fires[index]
        local start=fire and time-fire.time<=FIRE_AGE and fire.origin
            or point(call(shooter,'get_eye_position'))
        local head=point(call(player,'get_hitbox_position',0))
        local pelvis=point(call(player,'get_hitbox_position',2))
        if not M.close_to_segment(start,finish,head,40)
            and not M.close_to_segment(start,finish,pelvis,32)then return end
        local current=effective(refs.inverter)
        if desired~=nil then current=desired
        elseif rage and rage.antiaim then
            local actual=call(rage.antiaim,'inverter')
            if type(actual)=='boolean'then current=actual end
        end
        if type(current)~='boolean'then return end
        desired=not current;expires=time+DURATION;last_trigger=time
    end
    function object:watchdog()
        local time=clock_and_player()
        if not time then return end
        if desired~=nil and time>=expires then desired=nil;release()end
        for index,fire in pairs(fires)do
            if time-fire.time>FIRE_AGE then fires[index]=nil end
        end
    end
    function object:command(cmd)
        self:watchdog()
        if desired==nil then return end
        if pressed(prop(cmd,'in_attack'))or pressed(prop(cmd,'in_attack2'))or pressed(prop(cmd,'in_use'))then
            desired=nil;release();return
        end
        local ok,current=override_value()
        assert(ok,'Body Yaw override API unavailable')
        if not owned then owned={before=current}
        elseif current~=owned.applied then owned.before=current end
        owned.applied=desired
        refs.inverter:override(desired)
    end
    function object:safe(method,...)
        if stopped then return end
        local ok,err=pcall(self[method],self,...)
        if not ok then
            self:reset();enabled:set(false)
            print('Bianca shot response: '..tostring(err))
        end
    end
    enabled:set_callback(function()
        object:reset()
        if enabled:get()and(not refs.inverter or not refs.body or not refs.enabled)then
            enabled:set(false);print('Bianca shot response: Body Yaw reference unavailable')
        end
    end)
    function object:shutdown()stopped=true;self:reset()end
    return object
end
return M

end)()

local OwnBait = (function()
local M = {}
local INTERVAL, CONFIRMATIONS = .12, 3
local function finite(v)return type(v)=='number' and v==v and math.abs(v)~=math.huge end
local function prop(object,key)
    if not object then return nil end
    local ok,v=pcall(function()return object[key]end)
    if ok then return v end
end
local function call(object,key,...)
    if not object then return nil end
    local ok,v=pcall(function(...)return object[key](object,...)end,...)
    if ok then return v end
end
local function point(v)
    local x,y,z=prop(v,'x'),prop(v,'y'),prop(v,'z')
    if finite(x)and finite(y)and finite(z)then return {x=x,y=y,z=z}end
end
local function pressed(v)return v==true or v==1 end
local function angle_delta(a,b)return (a-b+180)%360-180 end
local function distance2(a,b)return (a.x-b.x)^2+(a.y-b.y)^2+(a.z-b.z)^2 end

function M.pick(probes,held)
    if not probes or not finite(probes.head_depth)or not finite(probes.pelvis_depth)
        or probes.head_depth<2 or probes.pelvis_depth>.5 or probes.shootable then return nil end
    local function score(side)
        local v=probes[side]
        if not v or not finite(v.wall_distance)or v.wall_distance<0 or v.wall_distance>=24
            or not finite(v.head_depth)or v.head_depth<2 then return nil end
        return math.min(v.head_depth,24)+(24-v.wall_distance)*.25
    end
    local left,right=score('Left'),score('Right')
    if held=='Left'and left and(not right or right-left<4)then return 'Left'end
    if held=='Right'and right and(not left or left-right<4)then return 'Right'end
    if left and not right then return 'Left'end
    if right and not left then return 'Right'end
    if left and right and math.abs(left-right)>=4 then return left>right and 'Left'or'Right'end
end

function M.probe(ctx)
    if not utils or type(utils.trace_line)~='function'then return nil end
    local function trace(from,to)
        local function filter(ent)return not ent or call(ent,'is_player')~=true end
        local ok,result=pcall(utils.trace_line,vector(from.x,from.y,from.z),
            vector(to.x,to.y,to.z),filter,0x4600400B)
        local fraction=ok and prop(result,'fraction')or nil
        if not finite(fraction)or fraction<0 or fraction>1
            or prop(result,'start_solid')==true or prop(result,'startsolid')==true then return nil end
        return (1-fraction)*math.sqrt(distance2(from,to)),fraction
    end
    local function shifted(center,offset)
        return {x=center.x+ctx.rx*offset,y=center.y+ctx.ry*offset,z=center.z}
    end
    local head_depth=math.huge
    for _,offset in ipairs({-3,0,3})do
        local depth=trace(ctx.eye,shifted(ctx.head,offset))
        if not depth then return nil end
        head_depth=math.min(head_depth,depth)
    end
    if head_depth<2 then return {head_depth=head_depth,pelvis_depth=math.huge}end
    local pelvis_depth=trace(ctx.eye,ctx.pelvis)
    if not pelvis_depth then return nil end
    if pelvis_depth>.5 then return {head_depth=head_depth,pelvis_depth=pelvis_depth}end
    local probes={head_depth=head_depth,pelvis_depth=pelvis_depth}
    local radius=math.max(4,math.min(12,math.sqrt((ctx.head.x-ctx.origin.x)^2+(ctx.head.y-ctx.origin.y)^2)+2))
    local chest={x=ctx.origin.x,y=ctx.origin.y,z=ctx.head.z-6}
    for _,side in ipairs({'Left','Right'})do
        local sign=side=='Left'and -1 or 1
        local remaining,fraction=trace(chest,shifted(chest,sign*24))
        if not remaining then return nil end
        local wall_distance=fraction*24
        local candidate=shifted({x=ctx.origin.x,y=ctx.origin.y,z=ctx.head.z},sign*radius)
        local a=trace(ctx.eye,shifted(candidate,-3))
        local b=trace(ctx.eye,shifted(candidate,3))
        if not a or not b then return nil end
        probes[side]={wall_distance=wall_distance,head_depth=math.min(a,b)}
    end
    if type(utils.trace_bullet)=='function'then
        local ok,damage,result=pcall(utils.trace_bullet,ctx.target,
            vector(ctx.eye.x,ctx.eye.y,ctx.eye.z),vector(ctx.head.x,ctx.head.y,ctx.head.z))
        if ok and finite(damage)and damage>0 and result then
            local hit=prop(result,'entity')
            local index=type(hit)=='number'and hit or call(hit,'get_index')
            probes.shootable=hit==ctx.player or(ctx.player_index~=nil and index==ctx.player_index)
        end
    end
    return probes
end

function M.create(group,find,running,decorate)
    local enabled=group:switch(decorate('Ass Bait'),false)
    local refs={}
    local function angle(name,...)
        refs[name]=find('Aimbot','Anti Aim','Angles',...)
    end
    angle('enabled','Enabled');angle('yaw','Yaw');angle('base','Yaw','Base');angle('offset','Yaw','Offset')
    angle('modifier','Yaw Modifier');angle('modifier_offset','Yaw Modifier','Offset')
    angle('freestanding','Freestanding')
    local fake_duck=find('Aimbot','Anti Aim','Misc','Fake Duck')
    local owned,held,pending,confirmations,checked,previous,last_time={},nil,nil,0,nil,nil,nil
    local stopped=false
    local function get_override(ref)
        local ok,value=pcall(function()return ref:get_override()end)
        return ok,value
    end
    local function effective(ref)
        local ok,value=get_override(ref)
        if ok and value~=nil then return value end
        return call(ref,'get')
    end
    local function set(ref,value)
        if value==nil then ref:override()else ref:override(value)end
    end
    local function release()
        for ref,state in pairs(owned)do
            local ok,value=get_override(ref)
            if ok and value==state.applied then pcall(set,ref,state.before)end
        end
        owned={}
    end
    local object={enabled=enabled}
    function object:reset()
        release();held,pending,confirmations,checked,previous=nil,nil,0,nil,nil
    end
    local function acquire(ref,value)
        local ok,current=get_override(ref)
        assert(ok,'Anti Aim override API unavailable')
        local state=owned[ref]
        if not state then state={before=current};owned[ref]=state
        elseif current~=state.applied then state.before=current end
        state.applied=value
        set(ref,value)
    end
    local function context(cmd)
        if globals.is_in_game==false or not pressed(effective(refs.enabled))or pressed(effective(refs.freestanding))
            or pressed(effective(fake_duck))then return nil end
        for _,key in ipairs({'in_attack','in_attack2','in_jump','in_use'})do if pressed(cmd[key])then return nil end end
        local player=entity.get_local_player()
        if not player or call(player,'is_alive')~=true then return nil end
        local duck,flags=prop(player,'m_flDuckAmount'),prop(player,'m_fFlags')
        local velocity=point(prop(player,'m_vecVelocity'))
        if not finite(duck)or duck<.8 or not finite(flags)or flags%2~=1
            or not velocity or velocity.x^2+velocity.y^2>25 then return nil end
        local ok,target=pcall(entity.get_threat)
        if not ok or not target or call(target,'is_alive')~=true or call(target,'is_enemy')~=true
            or call(target,'is_dormant')==true then return nil end
        local origin,head,pelvis=point(call(player,'get_origin')),point(call(player,'get_hitbox_position',0)),point(call(player,'get_hitbox_position',2))
        local eye=point(call(target,'get_eye_position'))
        if not origin or not head or not pelvis or not eye then return nil end
        local dx,dy=eye.x-origin.x,eye.y-origin.y
        local length=math.sqrt(dx*dx+dy*dy)
        if length<96 then return nil end
        return {player=player,player_index=call(player,'get_index'),target=target,key=call(target,'get_index'),
            origin=origin,head=head,pelvis=pelvis,eye=eye,rx=dy/length,ry=-dx/length,
            angle=math.deg(math.atan2(dy,dx))}
    end
    function object:update(cmd)
        if stopped or not running()then return end
        if not enabled:get()then self:reset();return end
        local time=globals.curtime
        if not finite(time)then self:reset();return end
        if last_time and time<last_time then self:reset()end
        last_time=time
        local ctx=context(cmd)
        if not ctx then self:reset();return end
        if previous and(ctx.key~=previous.key or math.abs(angle_delta(ctx.angle,previous.angle))>15
            or distance2(ctx.origin,previous.origin)>4)then self:reset()end
        if not checked or time-checked>=INTERVAL then
            checked=time;previous=ctx
            local probes=M.probe(ctx)
            local selected=probes and M.pick(probes,held)or nil
            if not selected then self:reset();checked=time;previous=ctx;return end
            if selected~=held then
                release();held=nil
                if pending~=selected then pending=selected;confirmations=1
                else confirmations=confirmations+1 end
                if confirmations>=CONFIRMATIONS then held=selected;pending=nil;confirmations=0 end
            end
        end
        if not held then return end
        acquire(refs.yaw,'Backward');acquire(refs.base,'At Target')
        acquire(refs.offset,held=='Left'and -90 or 90)
        acquire(refs.modifier,'Disabled');acquire(refs.modifier_offset,0)
    end
    local updating=false
    function object:command(cmd)
        if updating or stopped then return end
        updating=true
        local ok,err=pcall(self.update,self,cmd)
        if not ok then
            self:reset();enabled:set(false)
            print('Bianca Ass Bait: '..tostring(err))
        end
        updating=false
    end
    enabled:set_callback(function()
        object:reset()
        if enabled:get()then
            for _,name in ipairs({'enabled','yaw','base','offset','modifier','modifier_offset'})do
                if not refs[name]then enabled:set(false);print('Bianca Ass Bait: Anti Aim reference unavailable: '..name);break end
            end
        end
    end)
    function object:is_active()return held~=nil end
    function object:shutdown()stopped=true;self:reset()end
    return object
end

return M

end)()

local Backtrack = (function()
local M = {}
local CDEF = [=[

    typedef struct { float x, y, z; } vec3_t;
    typedef float matrix3x4_t[3][4];

    typedef struct {
        float anim_time;
        float fade_out_time;
        void* studio_hdr;
        int   dispatched_src;
        int   dispatched_dst;
        int   order;
        int   sequence;
        float prev_cycle;
        float weight;
        float weight_delta_rate;
        float playback_rate;
        float cycle;
        void* owner;
        int   invalidate_physics_bits;
    } anim_layer_t;

    typedef struct {
        matrix3x4_t* matrix_center;
        matrix3x4_t* matrix_left;
        matrix3x4_t* matrix_right;
        matrix3x4_t* matrix_secondary;
        float  pose_parameters[24];
        anim_layer_t anim_layers[13];
        char   pad[184];
    } lag_anim_data_t;

    typedef struct {
        vec3_t origin;
        vec3_t velocity;
        vec3_t abs_velocity;
        float  simulation_time;
        vec3_t mins;
        float  maxs_x;
        float  maxs_y;
        float  aim_yaw_max;
        int    choked_ticks;
        char   pad_44[24];
        float  desync_weight;
        char   pad_60[4];
        float  eye_pitch;
        float  abs_yaw;
        float  body_yaw;
        vec3_t view_offset;
        float  origin_prev_x;
        float  origin_prev_y;
        int    server_tick;
        char   pad_88[12];
        float  lagcomp_simtime;
        float  duck_amount;
        char   pad_9C[4];
        float  maxs_z;
        int    lagcomp_valid;
        char   pad_A8[4];
        int    extrap_cleared;
        int    record_flags;
        char   pad_B4[4];
        lag_anim_data_t anim;
    } lag_record_t;

    typedef struct {
        void*          pad;
        lag_record_t** records;
        int            capacity;
        int            head;
        int            count;
    } lag_ringbuf_t;

    typedef struct {
        void*         BaseAddress;
        void*         AllocationBase;
        unsigned long AllocationProtect;
        unsigned long RegionSize;
        unsigned long State;
        unsigned long Protect;
        unsigned long Type;
    } MEMORY_BASIC_INFORMATION;
    unsigned long VirtualQuery(const void*, MEMORY_BASIC_INFORMATION*, unsigned long);

    int   VirtualProtect(void*, unsigned long, unsigned long, unsigned long*);
    void* VirtualAlloc(void*, unsigned long, unsigned long, unsigned long);
    int   VirtualFree(void* addr, unsigned long size, unsigned long type);
    void* GetCurrentProcess(void);
    int   FlushInstructionCache(void* hProcess, const void* base, unsigned long size);

]=]
local PATTERNS = {
    ["8986b0000000a1????????8986ac000000"] = 0xaeac6,
    ["a908080000750f43"] = 0x1ef52e,
    ["4921d98b0c88e8????????84c00f84"] = 0x1ef43b,
    ["4821d88b0c81e8????????84c074"] = 0x1ef7a5,
    ["f681b000000008f30f100c240f85????????8b048780b8a400000000"] = 0x1ef4e1,
    ["8d59088b410889d9ff502883f841"] = 0x1ef19c,
    ["8b0d????????8d87a4000000f30f108794000000"] = 0x1ef57c,
    ["83791002730331c0c3568b410c"] = 0x15e710,
    ["56a1????????89c2c1ea1f01c2d1fa"] = 0x156d50,
    ["ff7424??ff7424??e8????????89c68b4c240c31e1"] = 0x1ef2a0,
    ["f30f109270030000f30f119080010000"] = 0xb625e,
}
local function main_menu()
    return globals.is_in_game == false and entity.get_local_player() == nil
end
local function trace(message)
    if type(print_dev) == 'function' then print_dev('Bianca Backtrack: '..message) end
end
function M.native_api()
    local ffi = require('ffi')
    assert(ffi.os == 'Windows' and ffi.abi('32bit'), 'Win32 CS:GO required')
    return {ffi=ffi}
end
function M.backend(api)
    assert(main_menu(), 'Main menu required')
    trace('prepare original modules')
    api = api or M.native_api()
    local real = api.ffi
    local rawC = api.C or real.C
    local allocations = {}
    local names = {'vec3_t','matrix3x4_t','anim_layer_t','lag_anim_data_t',
        'lag_record_t','lag_ringbuf_t','MEMORY_BASIC_INFORMATION'}
    local function rewrite(s)
        if type(s) ~= 'string' then return s end
        for _,name in ipairs(names) do
            s = s:gsub('%f[%w_]'..name..'%f[^%w_]', 'bianca_backtrack15_'..name)
        end
        return s
    end
    local proxyC = setmetatable({}, {__index=function(self,name)
        local fn = rawC[name]
        local wrapped = fn
        if name == 'VirtualProtect' or name == 'FlushInstructionCache' then
            wrapped = function(...)
                local result = fn(...)
                assert(result ~= 0, name..' failed')
                return result
            end
        elseif name == 'VirtualAlloc' then
            wrapped = function(...)
                local p = fn(...)
                assert(p ~= nil and p ~= real.NULL, 'VirtualAlloc failed')
                allocations[tonumber(real.cast('uintptr_t',p))] = p
                return p
            end
        elseif name == 'VirtualFree' then
            wrapped = function(p,...)
                local result = fn(p,...)
                assert(result ~= 0, 'VirtualFree failed')
                allocations[tonumber(real.cast('uintptr_t',p))] = nil
                return result
            end
        end
        rawset(self,name,wrapped)
        return wrapped
    end})
    local ffi = setmetatable({C=proxyC,
        cast=function(t,v)return real.cast(rewrite(t),v)end,
        new=function(t,...)return real.new(rewrite(t),...)end,
        sizeof=function(t,...)return real.sizeof(rewrite(t),...)end,
        cdef=function(s)return real.cdef(rewrite(s))end}, {__index=real})
    if not pcall(real.typeof, 'bianca_backtrack15_lag_ringbuf_t') then ffi.cdef(CDEF) end
    local bit = require('bit')
    local base, size = ffi.cast('uint8_t*',0x412A0000), 0x3501000
    local IS_BETA, MAX_ENTITY_INDEX = true, 64
    local W, interpoint = nil, ''
    local PAGE_EXECUTE_READWRITE, MEM_COMMIT_RESERVE, MEM_RELEASE = 0x40, 0x3000, 0x8000
    local MBI_SZ = ffi.sizeof('MEMORY_BASIC_INFORMATION')
    local function ptr(p)return tonumber(ffi.cast('uintptr_t',p))end
    local function VirtualQuery(addr)
        local info = ffi.new('MEMORY_BASIC_INFORMATION')
        if ffi.C.VirtualQuery(addr,info,MBI_SZ) == 0 then return nil end
        return info
    end
    local function readable(address,length)
        if address < 0x10000 or address+length > 0xFFFFFFFF then return false end
        local ending = address+length
        for _=1,4 do
            if address >= ending then return true end
            local info = VirtualQuery(ffi.cast('void*',address))
            if not info or info.State ~= 0x1000 or bit.band(info.Protect,0x101) ~= 0 then return false end
            local next_address = ptr(info.BaseAddress)+tonumber(info.RegionSize)
            if next_address <= address then return false end
            address = next_address
        end
        return address >= ending
    end
    local function read(address,length)
        assert(readable(address,length), 'Backtrack image unavailable / unsupported build')
        return ffi.string(ffi.cast('void*',address),length)
    end
    local function key(pattern)
        local out = {}
        local length = 0
        for i in pairs(pattern) do if type(i)=='number' and i>length then length=i end end
        for i=1,length do out[i] = pattern[i] and string.format('%02x',pattern[i]) or '??' end
        return table.concat(out), length
    end
    local function scan(_,_,pattern)
        local signature,length = key(pattern)
        local rva = PATTERNS[signature]
        assert(rva, 'Unknown original Backtrack pattern')
        local address = 0x412A0000+rva
        local bytes = read(address,length)
        for i=1,length do
            assert(pattern[i] == nil or bytes:byte(i) == pattern[i], 'Unsupported Backtrack build / conflicting Lua')
        end
        return ffi.cast('uint8_t*',address)
    end
    local function wi32(address,value)
        local p=ffi.cast('uint8_t*',address)
        for i=0,3 do p[i]=bit.band(bit.rshift(value,i*8),0xFF) end
    end
    local function save(address,n)
        local out={}
        local p=ffi.cast('uint8_t*',address)
        for i=0,n-1 do out[i+1]=p[i] end
        return out
    end
    local function patch(address,bytes)
        local p=ffi.cast('uint8_t*',address)
        for i,value in ipairs(bytes) do p[i-1]=value end
    end
    local function bytes_from_hex(hex)
        return (hex:gsub('..',function(s)return string.char(tonumber(s,16))end))
    end
    trace('check original signatures')
    for pattern,rva in pairs(PATTERNS) do
        local bytes=read(0x412A0000+rva,#pattern/2)
        for i=1,#pattern/2 do
            local pair=pattern:sub(i*2-1,i*2)
            assert(pair=='??' or bytes:byte(i)==tonumber(pair,16),'Unsupported Backtrack build / conflicting Lua')
        end
    end
    assert(read(0x4148F4B9,5)==bytes_from_hex('0f2ec87669'),'Old Bianca hook remains; restart CS:GO')
    assert(read(0x41400BF0,12)==bytes_from_hex('53575683ec1489ce8b7c242c'),'Another lagcomp hook is active')
    local sites={{0x4148F534,1},{0x4148F441,5},{0x4148F7AB,5},
        {0x4148F4E1,39},{0x4148F1A7,5},{0x4148F57C,6},{0x4135625E,16}}
    local originals={}
    for i,site in ipairs(sites) do originals[i]=read(site[1],site[2]) end
    local pages={0x4148F000,0x41356000}
    local function make_writable()
        local changed={}
        local ok,err=pcall(function()
            for _,page in ipairs(pages) do
                local old=ffi.new('unsigned long[1]')
                ffi.C.VirtualProtect(ffi.cast('void*',page),4096,PAGE_EXECUTE_READWRITE,old)
                changed[#changed+1]={page,tonumber(old[0])}
            end
        end)
        if not ok then
            for _,entry in ipairs(changed) do
                pcall(function()
                    local old=ffi.new('unsigned long[1]')
                    ffi.C.VirtualProtect(ffi.cast('void*',entry[1]),4096,entry[2],old)
                end)
            end
            error(err)
        end
        return changed
    end
    local function restore_protection(changed)
        for _,entry in ipairs(changed) do
            local old=ffi.new('unsigned long[1]')
            ffi.C.VirtualProtect(ffi.cast('void*',entry[1]),4096,entry[2],old)
        end
    end
    local function write_snapshot(snapshot)
        for i,site in ipairs(sites) do
            ffi.copy(ffi.cast('void*',site[1]),snapshot[i],site[2])
            ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(),ffi.cast('void*',site[1]),site[2])
        end
    end
    local function snapshot()
        local result={}
        for i,site in ipairs(sites) do result[i]=read(site[1],site[2]) end
        return result
    end
    local function equal(snapshot)
        for i,site in ipairs(sites) do
            assert(read(site[1],site[2])==snapshot[i], 'Backtrack hook changed by another Lua; restart CS:GO')
        end
    end
    local controls, on_shutdown, callbacks = {}, {}, {}
    local function text_format(_,text)return text end
    local virtual_group={}
    function virtual_group:switch(name)
        local control={value=false}
        function control:get()return self.value end
        function control:set(value)self.value=value;if self.callback then return self.callback(self)end end
        function control:set_callback(callback)self.callback=callback;return self end
        function control:tooltip()return self end
        controls[name]=control
        return control
    end
    local b_ui, d_ui = virtual_group, virtual_group
    local events={createmove=function(callback)callbacks[#callbacks+1]=callback end}
local table_ptr do
    local table_hit = scan(base, size, {0x89, 0x86, 0xB0, 0x00, 0x00, 0x00, 0xA1, W, W, W, W, 0x89, 0x86, 0xAC, 0x00, 0x00, 0x00})
        or error("failed to find ring pattern")
    table_ptr = ffi.cast("uint8_t**", ffi.cast("uint32_t*", table_hit + 7)[0])
end

local function get_table_base()
    local tb = table_ptr[0]
    if tb == nil or tb == ffi.NULL then return nil end
    return tb
end

local function get_ring_safe(idx)
    if idx < 0 or idx > MAX_ENTITY_INDEX then return nil end
    local tb = get_table_base()
    if tb == nil then return nil end
    local ring = ffi.cast("lag_ringbuf_t*", tb + idx * 0x10940)
    if ring.records == nil then return nil end
    if ring.capacity <= 0 then return nil end
    return ring
end

local function get_record_at(ring, offset)
    if not ring or ring.count <= 0 then return nil end
    if offset < 0 or offset >= ring.count then return nil end
    local j = bit.band(ring.head + offset, ring.capacity - 1)
    local rec = ring.records[j]
    if rec == nil then return nil end
    local mbi = VirtualQuery(rec)
    if not mbi or mbi.State ~= 0x1000 or bit.band(mbi.Protect, 0x101) ~= 0 then return nil end
    return rec
end


local preserve_valid_records do
    local scan_skip_sig = scan(base, size, {0xA9, 0x08, 0x08, 0x00, 0x00, 0x75, 0x0F, 0x43})
    local scan_skip_orig = scan_skip_sig and save(scan_skip_sig + 6, 1)

    if IS_BETA and scan_skip_sig then
        b_ui:switch(text_format(interpoint, "Preserve valid records", 2, 7, 7)):set_callback(function(e)
            if e:get() == false then
                patch(scan_skip_sig + 6, scan_skip_orig)
                return
            end
            patch(scan_skip_sig + 6, {0x00})
        end, true):tooltip("Keep valid-flagged records that would normally be skipped during scan")
    end

    on_shutdown[#on_shutdown + 1] = function()
        if scan_skip_orig then patch(scan_skip_sig + 6, scan_skip_orig) end
    end
end

local break_dist_bypass do
    local bd_site1 = scan(base, size, {
        0x49, 0x21, 0xD9, 0x8B, 0x0C, 0x88,
        0xE8, W, W, W, W,
        0x84, 0xC0, 0x0F, 0x84
    })
    local bd_site2 = scan(base, size, {
        0x48, 0x21, 0xD8, 0x8B, 0x0C, 0x81,
        0xE8, W, W, W, W,
        0x84, 0xC0, 0x74
    })

    local bd_orig1 = bd_site1 and save(bd_site1 + 6, 5)
    local bd_orig2 = bd_site2 and save(bd_site2 + 6, 5)
    local bd_applied = false
    local bd_nop = {0xB0, 0x00, 0x90, 0x90, 0x90}

    if IS_BETA and bd_site1 and bd_site2 then
        d_ui:switch(text_format(interpoint, "Skip break distance check", 2, 7, 7)):set_callback(function(e)
            if e:get() then
                patch(bd_site1 + 6, bd_nop)
                patch(bd_site2 + 6, bd_nop)
                bd_applied = true
            elseif bd_applied then
                patch(bd_site1 + 6, bd_orig1)
                patch(bd_site2 + 6, bd_orig2)
                bd_applied = false
            end
        end, true):tooltip(
            "Remove lagrecord_within_break_distance calls in select_lagrecord.\n"..
            "Eliminates extra delay when selecting backtrack records")
    end

    on_shutdown[#on_shutdown + 1] = function()
        if bd_applied then
            patch(bd_site1 + 6, bd_orig1)
            patch(bd_site2 + 6, bd_orig2)
            bd_applied = false
        end
    end
end

local record_select_patch do
    local rs_sig = scan(base, size, {
        0xF6, 0x81, 0xB0, 0x00, 0x00, 0x00, 0x08,
        0xF3, 0x0F, 0x10, 0x0C, 0x24,
        0x0F, 0x85, W, W, W, W,
        0x8B, 0x04, 0x87,
        0x80, 0xB8, 0xA4, 0x00, 0x00, 0x00, 0x00
    })

    local rs_eix_sig = scan(base, size, {
        0x8D, 0x59, 0x08,
        0x8B, 0x41, 0x08,
        0x89, 0xD9,
        0xFF, 0x50, 0x28,
        0x83, 0xF8, 0x41
    })
    local rs_eix_site = rs_eix_sig and (rs_eix_sig + 11) or nil

    local fb_sig = scan(base, size, {
        0x8B, 0x0D, W, W, W, W,
        0x8D, 0x87, 0xA4, 0x00, 0x00, 0x00,
        0xF3, 0x0F, 0x10, 0x87, 0x94, 0x00, 0x00, 0x00
    })

    local fn_valid_sig = scan(base, size, {
        0x83, 0x79, 0x10, 0x02, 0x73, 0x03, 0x31, 0xC0, 0xC3, 0x56, 0x8B, 0x41, 0x0C
    })
    local fn_expired_sig = scan(base, size, {
        0x56, 0xA1, W, W, W, W, 0x89, 0xC2, 0xC1, 0xEA, 0x1F, 0x01, 0xC2, 0xD1, 0xFA
    })
    local addr_ret_sig = scan(base, size, {
        0xFF, 0x74, 0x24, W, 0xFF, 0x74, 0x24, W, 0xE8, W, W, W, W,
        0x89, 0xC6, 0x8B, 0x4C, 0x24, 0x0C, 0x31, 0xE1
    })

    local af_sig = scan(base, size, {
        0xF3, 0x0F, 0x10, 0x92, 0x70, 0x03, 0x00, 0x00,
        0xF3, 0x0F, 0x11, 0x90, 0x80, 0x01, 0x00, 0x00
    })

    local rs_stub      = nil
    local rs_orig      = nil
    local rs_eix_orig  = nil
    local rs_applied   = false
    local fb_orig      = nil
    local fb_applied   = false
    local af_orig      = nil
    local af_applied   = false

    local rs_shot_arr = nil
    local rs_is_firing = nil
    local rs_tpr_arr = nil
    local tpr_offset = utils.get_netvar_offset("DT_CSPlayer", "m_flThirdpersonRecoil")

    local function rs_fill_shot_times()
        if not rs_applied or not rs_is_firing then return end
        ffi.fill(rs_is_firing, 65 * 4, 0)
        if rs_tpr_arr then ffi.fill(rs_tpr_arr, 65 * 4, 0) end
        local players = entity.get_players(true)
        if not players then return end
        for _, p in ipairs(players) do
            if p:is_alive() then
                local idx = p:get_index()
                if idx >= 0 and idx < 65 then
                    local ring = get_ring_safe(idx)
                    if ring and ring.count > 0 then
                        local newest = get_record_at(ring, 0)
                        if newest then
                            local oldest = ring.count > 1 and get_record_at(ring, ring.count - 1) or nil
                            local ok, lst = pcall(function()
                                local wpn = p:get_player_weapon()
                                if not wpn then return 0 end
                                local v = wpn.m_fLastShotTime
                                return type(v) == "number" and v or 0
                            end)
                            local last_shot = ok and lst or 0
                            if oldest and last_shot > 0
                               and newest.simulation_time >= last_shot
                               and last_shot > oldest.simulation_time then
                                rs_is_firing[idx] = 1.0
                            else
                                rs_is_firing[idx] = 0.0
                            end
                            if rs_tpr_arr and tpr_offset and tpr_offset > 0 then
                                local ok_tpr, tpr_val = pcall(function()
                                    local ptr = ffi.cast("float*", ffi.cast("uintptr_t", p[0]) + tpr_offset)
                                    return ptr[0]
                                end)
                                rs_tpr_arr[idx] = ok_tpr and tpr_val or 0
                            end
                        end
                    else
                        rs_is_firing[idx] = 0.0
                    end
                end
            end
        end
    end
    events.createmove(rs_fill_shot_times)


    local function rs_install()
        if rs_applied or not rs_sig or not fn_valid_sig or not fn_expired_sig or not addr_ret_sig then return end
        if rs_sig[0] == 0xE9 then return end

        if not rs_stub then
            rs_stub = ffi.cast("uint8_t*",
                ffi.C.VirtualAlloc(nil, 4096, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE))
            if rs_stub == nil then return end
        end

        local cave = ptr(rs_stub)
        local site = ptr(rs_sig)

        local addr_527   = site + 34 + tonumber(ffi.cast("int8_t*", rs_sig + 33)[0])
        local addr_7E2   = site + 39 + tonumber(ffi.cast("int32_t*", rs_sig + 35)[0])
        local g_cmd_ctx  = tonumber(ffi.cast("uint32_t*", addr_7E2 + 8)[0])
        local fn_valid   = ptr(fn_valid_sig)
        local fn_expired = ptr(fn_expired_sig)
        local addr_ret   = ptr(addr_ret_sig) + 15

        local d_8f       = cave + 0x15A
        local d_180      = cave + 0x15E
        local d_n180     = cave + 0x162
        local d_360      = cave + 0x166
        local g_entindex = cave + 0x26E
        local g_is_firing = cave + 0x3B0
        local g_tpr_arr  = cave + 0x4B8
        rs_is_firing = ffi.cast("float*", g_is_firing)
        rs_tpr_arr   = ffi.cast("float*", g_tpr_arr)

        local c = {

            0x56,
            0x57,
            0x52,
            0x51,




            0x8B, 0x74, 0x24, 0x18,
            0x8B, 0x46, 0x0C,
            0x03, 0x46, 0x10,
            0x48,
            0x8B, 0x72, 0x08,
            0x4E,
            0x21, 0xF0,
            0x8B, 0x34, 0x87,


            0xA1, 0,0,0,0,
            0x8B, 0x80, 0x6C, 0x01, 0x00, 0x00,
            0x3B, 0x81, 0x84, 0x00, 0x00, 0x00,
            0x0F, 0x84, 0x03, 0x01, 0x00, 0x00,


            0xA1, 0,0,0,0,
            0xF3, 0x0F, 0x10, 0x04, 0x85, 0,0,0,0,
            0x0F, 0x57, 0xC9,
            0x0F, 0x2E, 0xC1,
            0x0F, 0x87, 0xA4, 0x00, 0x00, 0x00,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90,


            0x8B, 0x0C, 0x24,
            0xF3, 0x0F, 0x10, 0x01,
            0xF3, 0x0F, 0x5C, 0x06,
            0xF3, 0x0F, 0x59, 0xC0,
            0xF3, 0x0F, 0x10, 0x49, 0x04,
            0xF3, 0x0F, 0x5C, 0x4E, 0x04,
            0xF3, 0x0F, 0x59, 0xC9,
            0xF3, 0x0F, 0x58, 0xC1,
            0xF3, 0x0F, 0x10, 0x49, 0x08,
            0xF3, 0x0F, 0x5C, 0x4E, 0x08,
            0xF3, 0x0F, 0x59, 0xC9,
            0xF3, 0x0F, 0x58, 0xC1,
            0xF3, 0x0F, 0x51, 0xC0,
            0x0F, 0x2E, 0x05, 0,0,0,0,
            0x73, 0x46,


            0xF3, 0x0F, 0x10, 0x41, 0x68,
            0xF3, 0x0F, 0x5C, 0x46, 0x68,
            0x0F, 0x2E, 0x05, 0,0,0,0,
            0x76, 0x08,
            0xF3, 0x0F, 0x5C, 0x05, 0,0,0,0,
            0xF3, 0x0F, 0x10, 0x0D, 0,0,0,0,
            0x0F, 0x2E, 0xC8,
            0x76, 0x08,
            0xF3, 0x0F, 0x58, 0x05, 0,0,0,0,
            0x0F, 0x57, 0xC9,
            0xF3, 0x0F, 0x5C, 0xC8,
            0xF3, 0x0F, 0x5F, 0xC1,
            0x0F, 0x2E, 0x05, 0,0,0,0,
            0x77, 0x02,
            0xEB, 0x03,


            0x8B, 0x34, 0x24,


            0x8B, 0x4C, 0x24, 0x18,
            0xB8, 0,0,0,0,
            0xFF, 0xD0,
            0x84, 0xC0,
            0x74, 0x0F,

            0x8B, 0xCE,
            0xB8, 0,0,0,0,
            0xFF, 0xD0,
            0x84, 0xC0,
            0x75, 0x02,

            0xEB, 0x1C,


            0x8B, 0x54, 0x24, 0x04,
            0x8B, 0x7C, 0x24, 0x08,
            0x8B, 0x44, 0x24, 0x18,
            0x8B, 0x48, 0x0C,
            0x03, 0x48, 0x10,
            0x49,
            0x8B, 0x42, 0x08,
            0x48,
            0x21, 0xC1,
            0x8B, 0x34, 0x8F,


            0x83, 0xC4, 0x10,
            0xE9, 0,0,0,0,


            0x59,
            0x5A,
            0x5F,
            0x5E,
            0x8B, 0x42, 0x08,
            0x48,
            0x21, 0xD8,
            0xF3, 0x0F, 0x10, 0x0C, 0x24,
            0x8B, 0x04, 0x87,
            0x80, 0xB8, 0xA4, 0x00, 0x00, 0x00, 0x00,
            0x8B, 0x7C, 0x24, 0x08,
            0x0F, 0x85, 0,0,0,0,
            0xE9, 0,0,0,0,


            0x00, 0x00, 0x00, 0x41,
            0x00, 0x00, 0x34, 0x43,
            0x00, 0x00, 0x34, 0xC3,
            0x00, 0x00, 0xB4, 0x43,

        }

        local function fix(off, val)
            c[off+1] = bit.band(val, 0xFF)
            c[off+2] = bit.band(bit.rshift(val,  8), 0xFF)
            c[off+3] = bit.band(bit.rshift(val, 16), 0xFF)
            c[off+4] = bit.band(bit.rshift(val, 24), 0xFF)
        end

        fix(0x19,  g_cmd_ctx)
        fix(0x30,  g_entindex)
        fix(0x39,  g_is_firing)
        fix(0xA1,  d_8f)
        fix(0xB4,  d_180)
        fix(0xBE,  d_360)
        fix(0xC6,  d_n180)
        fix(0xD3,  d_360)
        fix(0xE5,  d_8f)
        fix(0xF5,  fn_valid)
        fix(0x102, fn_expired)
        fix(0x12E, addr_ret - (cave + 0x132))
        fix(0x151, addr_527 - (cave + 0x155))
        fix(0x156, addr_7E2 - (cave + 0x15A))

        for i = 1, #c do rs_stub[i-1] = c[i] end




        local eix_stub = cave + 0x272
        local eix_stub_p = ffi.cast("uint8_t*", eix_stub)
        local eix_s = {
            0xA3, 0,0,0,0,
            0x83, 0xF8, 0x41,
            0x72, 0x05,
            0xE9, 0,0,0,0,
            0xE9, 0,0,0,0,
        }
        local eix_site_val = ptr(rs_eix_site)
        local function eix_fix(off, val)
            eix_s[off+1] = bit.band(val, 0xFF)
            eix_s[off+2] = bit.band(bit.rshift(val,  8), 0xFF)
            eix_s[off+3] = bit.band(bit.rshift(val, 16), 0xFF)
            eix_s[off+4] = bit.band(bit.rshift(val, 24), 0xFF)
        end
        eix_fix(0x01, g_entindex)
        eix_fix(0x0B, (eix_site_val + 5) - (eix_stub + 0x0F))
        eix_fix(0x10, (eix_site_val + 5 + 0x26) - (eix_stub + 0x14))
        for i = 1, #eix_s do eix_stub_p[i-1] = eix_s[i] end


        local cave2 = cave + 0x290
        local cave2_p = ffi.cast("uint8_t*", cave2)
        local d2_8f   = cave2 + 0x106
        local d2_180  = cave2 + 0x10A
        local d2_n180 = cave2 + 0x10E
        local d2_360  = cave2 + 0x112
        local g_pdc   = fb_sig and tonumber(ffi.cast("uint32_t*", fb_sig + 2)[0]) or 0
        local c2 = {
            0x51,
            0x52,
            0x8B, 0xC3,
            0x8B, 0x55, 0x08,
            0x4A,
            0x21, 0xD0,
            0x8B, 0x55, 0x04,
            0x8B, 0x14, 0x82,
            0x52,


            0xA1, 0,0,0,0,
            0xF3, 0x0F, 0x10, 0x04, 0x85, 0,0,0,0,
            0x0F, 0x57, 0xC9,
            0x0F, 0x2E, 0xC1,
            0x0F, 0x87, 0x9E, 0x00, 0x00, 0x00,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,

            0x8B, 0x0C, 0x24,
            0xF3, 0x0F, 0x10, 0x01,
            0xF3, 0x0F, 0x5C, 0x07,
            0xF3, 0x0F, 0x59, 0xC0,
            0xF3, 0x0F, 0x10, 0x49, 0x04,
            0xF3, 0x0F, 0x5C, 0x4F, 0x04,
            0xF3, 0x0F, 0x59, 0xC9,
            0xF3, 0x0F, 0x58, 0xC1,
            0xF3, 0x0F, 0x10, 0x49, 0x08,
            0xF3, 0x0F, 0x5C, 0x4F, 0x08,
            0xF3, 0x0F, 0x59, 0xC9,
            0xF3, 0x0F, 0x58, 0xC1,
            0xF3, 0x0F, 0x51, 0xC0,
            0x0F, 0x2E, 0x05, 0,0,0,0,
            0x0F, 0x83, 0x46, 0x00, 0x00, 0x00,

            0xF3, 0x0F, 0x10, 0x41, 0x68,
            0xF3, 0x0F, 0x5C, 0x47, 0x68,
            0x0F, 0x2E, 0x05, 0,0,0,0,
            0x76, 0x08,
            0xF3, 0x0F, 0x5C, 0x05, 0,0,0,0,
            0xF3, 0x0F, 0x10, 0x0D, 0,0,0,0,
            0x0F, 0x2E, 0xC8,
            0x76, 0x08,
            0xF3, 0x0F, 0x58, 0x05, 0,0,0,0,
            0x0F, 0x57, 0xC9,
            0xF3, 0x0F, 0x5C, 0xC8,
            0xF3, 0x0F, 0x5F, 0xC1,
            0x0F, 0x2E, 0x05, 0,0,0,0,
            0x77, 0x02,
            0xEB, 0x2F,

            0x8B, 0xCD,
            0xB8, 0,0,0,0,
            0xFF, 0xD0,
            0x84, 0xC0,
            0x74, 0x17,
            0x8B, 0xCF,
            0xB8, 0,0,0,0,
            0xFF, 0xD0,
            0x84, 0xC0,
            0x75, 0x0A,
            0x8B, 0xF7,
            0x83, 0xC4, 0x0C,
            0xE9, 0,0,0,0,

            0x8B, 0x34, 0x24,
            0x83, 0xC4, 0x0C,
            0xE9, 0,0,0,0,

            0x83, 0xC4, 0x0C,
            0x8B, 0x0D, 0,0,0,0,
            0xE9, 0,0,0,0,

            0x00, 0x00, 0x00, 0x41,
            0x00, 0x00, 0x34, 0x43,
            0x00, 0x00, 0x34, 0xC3,
            0x00, 0x00, 0xB4, 0x43,
        }
        local function fix2(off, val)
            c2[off+1] = bit.band(val, 0xFF)
            c2[off+2] = bit.band(bit.rshift(val,  8), 0xFF)
            c2[off+3] = bit.band(bit.rshift(val, 16), 0xFF)
            c2[off+4] = bit.band(bit.rshift(val, 24), 0xFF)
        end
        fix2(0x12,  g_entindex)
        fix2(0x1B,  g_is_firing)
        fix2(0x79,  d2_8f)
        fix2(0x90,  d2_180)
        fix2(0x9A,  d2_360)
        fix2(0xA2,  d2_n180)
        fix2(0xAF,  d2_360)
        fix2(0xC1,  d2_8f)
        fix2(0xCC,  fn_valid)
        fix2(0xD9,  fn_expired)
        fix2(0xE9,  addr_ret - (cave2 + 0xED))
        fix2(0xF4,  addr_ret - (cave2 + 0xF8))
        fix2(0xFD,  g_pdc)
        fix2(0x102, fb_sig and (ptr(fb_sig + 6) - (cave2 + 0x106)) or 0)
        for i = 1, #c2 do cave2_p[i-1] = c2[i] end


        rs_orig = save(rs_sig, 39)
        local old = ffi.new("unsigned long[1]")
        ffi.C.VirtualProtect(ffi.cast("void*", site), 39, PAGE_EXECUTE_READWRITE, old)
        rs_sig[0] = 0xE9
        wi32(site + 1, cave - (site + 5))
        for i = 5, 38 do rs_sig[i] = 0x90 end
        ffi.C.VirtualProtect(ffi.cast("void*", site), 39, old[0], old)


        if rs_eix_site and rs_eix_site[0] ~= 0xE9 then
            rs_eix_orig = save(rs_eix_site, 5)
            ffi.C.VirtualProtect(ffi.cast("void*", eix_site_val), 5, PAGE_EXECUTE_READWRITE, old)
            rs_eix_site[0] = 0xE9
            wi32(eix_site_val + 1, eix_stub - (eix_site_val + 5))
            ffi.C.VirtualProtect(ffi.cast("void*", eix_site_val), 5, old[0], old)
            ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), ffi.cast("void*", eix_site_val), 5)
        end

        ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), ffi.cast("void*", site), 39)


        if af_sig and tpr_offset and tpr_offset > 0 and af_sig[0] ~= 0xE9 then
            local cave3 = cave + 0x16A
            local cave3_p = ffi.cast("uint8_t*", cave3)
            local af_site = ptr(af_sig)
            local af_ret = af_site + 16
            local c3 = {

                0xF3, 0x0F, 0x10, 0x92, 0x70, 0x03, 0x00, 0x00,
                0xF3, 0x0F, 0x11, 0x90, 0x80, 0x01, 0x00, 0x00,

                0x51,
                0x8B, 0x0D, 0,0,0,0,
                0xF3, 0x0F, 0x10, 0x14, 0x8D, 0,0,0,0,
                0x0F, 0x57, 0xDB,
                0x0F, 0x2E, 0xD3,
                0x76, 0x1B,

                0xF3, 0x0F, 0x10, 0x14, 0x8D, 0,0,0,0,

                0x8B, 0x8E, 0xE0, 0x02, 0x00, 0x00,
                0x85, 0xC9,
                0x74, 0x08,
                0xF3, 0x0F, 0x11, 0x91, 0,0,0,0,

                0x59,
                0xE9, 0,0,0,0,
            }
            local function fix3(off, val)
                c3[off+1] = bit.band(val, 0xFF)
                c3[off+2] = bit.band(bit.rshift(val,  8), 0xFF)
                c3[off+3] = bit.band(bit.rshift(val, 16), 0xFF)
                c3[off+4] = bit.band(bit.rshift(val, 24), 0xFF)
            end
            fix3(0x13, g_entindex)
            fix3(0x1C, g_is_firing)
            fix3(0x2D, g_tpr_arr)
            fix3(0x3F, tpr_offset)
            fix3(0x45, af_ret - (cave3 + 0x49))
            for i = 1, #c3 do cave3_p[i-1] = c3[i] end

            af_orig = save(af_sig, 16)
            ffi.C.VirtualProtect(ffi.cast("void*", af_site), 16, PAGE_EXECUTE_READWRITE, old)
            af_sig[0] = 0xE9
            wi32(af_site + 1, cave3 - (af_site + 5))
            for i = 5, 15 do af_sig[i] = 0x90 end
            ffi.C.VirtualProtect(ffi.cast("void*", af_site), 16, old[0], old)
            ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), ffi.cast("void*", af_site), 16)
            af_applied = true
        end

        ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), ffi.cast("void*", cave), 0x400)
        rs_applied = true
    end

    local function fb_install()
        if fb_applied or not rs_applied then return end
        if not fb_sig then return end
        if fb_sig[0] == 0xE9 then return end
        local site = ptr(fb_sig)
        local cave2 = ptr(rs_stub) + 0x290
        fb_orig = save(fb_sig, 6)
        local old = ffi.new("unsigned long[1]")
        ffi.C.VirtualProtect(ffi.cast("void*", site), 6, PAGE_EXECUTE_READWRITE, old)
        fb_sig[0] = 0xE9
        wi32(site + 1, cave2 - (site + 5))
        fb_sig[5] = 0x90
        ffi.C.VirtualProtect(ffi.cast("void*", site), 6, old[0], old)
        ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), ffi.cast("void*", site), 6)
        fb_applied = true
    end

    local function fb_uninstall()
        if not fb_applied then return end
        if not fb_orig or fb_sig[0] ~= 0xE9 then fb_applied = false return end
        local site = ptr(fb_sig)
        local old = ffi.new("unsigned long[1]")
        ffi.C.VirtualProtect(ffi.cast("void*", site), 6, PAGE_EXECUTE_READWRITE, old)
        patch(fb_sig, fb_orig)
        ffi.C.VirtualProtect(ffi.cast("void*", site), 6, old[0], old)
        ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), ffi.cast("void*", site), 6)
        fb_orig = nil
        fb_applied = false
    end

    local function rs_uninstall()
        if not rs_applied then return end
        fb_uninstall()
        local old = ffi.new("unsigned long[1]")


        if rs_eix_site and rs_eix_orig and rs_eix_site[0] == 0xE9 then
            local eix_site_val = ptr(rs_eix_site)
            ffi.C.VirtualProtect(ffi.cast("void*", eix_site_val), 5, PAGE_EXECUTE_READWRITE, old)
            patch(rs_eix_site, rs_eix_orig)
            ffi.C.VirtualProtect(ffi.cast("void*", eix_site_val), 5, old[0], old)
            ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), ffi.cast("void*", eix_site_val), 5)
            rs_eix_orig = nil
        end


        if af_applied and af_orig and af_sig[0] == 0xE9 then
            local af_site = ptr(af_sig)
            ffi.C.VirtualProtect(ffi.cast("void*", af_site), 16, PAGE_EXECUTE_READWRITE, old)
            patch(af_sig, af_orig)
            ffi.C.VirtualProtect(ffi.cast("void*", af_site), 16, old[0], old)
            ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), ffi.cast("void*", af_site), 16)
            af_orig = nil
            af_applied = false
        end


        if rs_orig and rs_sig[0] == 0xE9 then
            local site = ptr(rs_sig)
            ffi.C.VirtualProtect(ffi.cast("void*", site), 39, PAGE_EXECUTE_READWRITE, old)
            patch(rs_sig, rs_orig)
            ffi.C.VirtualProtect(ffi.cast("void*", site), 39, old[0], old)
            ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), ffi.cast("void*", site), 39)
        end
        rs_shot_arr = nil
        rs_is_firing = nil
        rs_tpr_arr = nil
        rs_applied = false
    end

    if IS_BETA and rs_sig and rs_eix_site and fn_valid_sig and fn_expired_sig and addr_ret_sig then
        b_ui:switch(text_format(interpoint, "Custom record selection", 2, 7, 7)):set_callback(function(e)
            if e:get() then
                rs_install()
            else
                rs_uninstall()
            end
        end, true)
    end

    if IS_BETA and fb_sig and rs_eix_site and fn_valid_sig and fn_expired_sig and addr_ret_sig then
        b_ui:switch(text_format(interpoint, "Custom fallback selection", 2, 7, 7)):set_callback(function(e)
            if e:get() then
                rs_install()
                fb_install()
            else
                fb_uninstall()
            end
        end, true)
    end

    on_shutdown[#on_shutdown + 1] = function()
        fb_uninstall()
        rs_uninstall()
        if rs_stub then
            ffi.C.VirtualFree(rs_stub, 0, MEM_RELEASE)
            rs_stub = nil
        end
    end
end


    local order={'Preserve valid records','Skip break distance check','Custom record selection','Custom fallback selection'}
    for _,name in ipairs(order) do assert(controls[name],'Original Backtrack feature unavailable: '..name) end
    local backend={installed=false,callbacks=callbacks,tainted=false}
    local installed_snapshot
    local function transaction(wanted)
        assert(main_menu(), 'Backtrack switches require main menu')
        assert(not backend.tainted,'Previous rollback failed; restart CS:GO')
        local before=wanted and originals or installed_snapshot
        equal(before)
        trace(wanted and 'enable original backtrack' or 'disable original backtrack')
        local changed=make_writable()
        local ok,err=pcall(function()
            if wanted then
                for _,name in ipairs(order) do trace(name);controls[name]:set(true) end
            else
                for i=#order,1,-1 do controls[order[i]]:set(false) end
            end
            restore_protection(changed)
        end)
        if not ok then
            local restored=pcall(function()
                make_writable()
                write_snapshot(before)
                restore_protection(changed)
            end)
            backend.tainted=true
            error(tostring(err)..(restored and '; original bytes restored' or '; rollback failed; restart CS:GO'))
        end
        backend.installed=wanted
        if wanted then installed_snapshot=snapshot()else equal(originals)end
        trace(wanted and 'original modules active' or 'original modules disabled')
    end
    function backend:enable()if not self.installed then transaction(true)end end
    function backend:disable()if self.installed then transaction(false)end end
    function backend:command()
        if not self.installed then return end
        for _,callback in ipairs(callbacks) do callback()end
    end
    function backend:shutdown()
        if not main_menu() then
            trace('in-match unload: native code retained; restart before reloading')
            return
        end
        if self.tainted then return end
        if self.installed then self:disable()end
        local changed=make_writable()
        local ok,err=pcall(function()
            for i=#on_shutdown,1,-1 do on_shutdown[i]()end
        end)
        restore_protection(changed)
        if not ok then error(err)end
    end
    return backend
end

function M.create(group,running,decorate)
    local enabled=group:switch(decorate('Backtrack'),false)
    local status=group:label('Backtrack status')
    status:visibility(false)
    local object={enabled=enabled}
    local backend, stopped, busy, failed, cache_fault=nil,false,false,false,false
    local factory=function()return M.backend()end
    enabled:set_callback(function()
        if not busy then failed=false;status:visibility(false)end
    end)
    function object:update()
        if stopped or not running()or busy or failed then return end
        local wanted=enabled:get()
        local active=backend and backend.installed or false
        if wanted==active then return end
        busy=true
        if not main_menu()then
            enabled:set(active);status:name('Main menu only');status:visibility(true)
            busy=false;return
        end
        local ok,err=pcall(function()
            if wanted then
                if not backend then backend=factory()end
                backend:enable()
            elseif backend then backend:disable()end
        end)
        if not ok then
            failed=true
            enabled:set(backend and backend.installed or false)
            status:name('Unavailable; see console');status:visibility(true)
            print('Bianca Backtrack: '..tostring(err))
        else cache_fault=false;status:visibility(false)end
        busy=false
    end
    function object:command()
        if stopped or not running()or cache_fault or not backend or not backend.installed then return end
        local ok,err=pcall(backend.command,backend)
        if not ok then
            cache_fault=true
            status:name('Record cache error');status:visibility(true)
            print('Bianca Backtrack record cache: '..tostring(err))
        end
    end
    function object:shutdown()
        stopped=true
        if backend then
            local ok,err=pcall(backend.shutdown,backend)
            if not ok then print('Bianca Backtrack cleanup: '..tostring(err))end
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
    ass_bait = "shield",
    anti_aim = "compass",
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

local own_bait_running = true
local own_bait_group = pui.create("Bianca Utils", with_icon("anti_aim", "Anti-Aim"), 1)
local own_bait = OwnBait.create(own_bait_group, ref, function() return own_bait_running end,
    function(text) return with_icon("ass_bait", text) end)
events.createmove:set(function(cmd)
    own_bait:command(cmd)
end)
events.round_prestart:set(function()
    own_bait:reset()
end)
events.shutdown:set(function()
    own_bait_running = false
    own_bait:shutdown()
end)

local response_running = true
local shot_response = ShotResponse.create(own_bait_group, ref,
    function() return response_running end,
    function()
        local glyph = icon_of("force_shoot")
        return "\a{Link Active}" .. (glyph and (glyph .. "  ") or "")
            .. "\aFFFFFFFFG\a9FCA2BFFS\a{Link Active} Anti-Bruteforce\aDEFAULT"
    end,
    function() return own_bait:is_active() end)
events.bullet_fire:set(function(event) shot_response:safe("fire", event) end)
events.bullet_impact:set(function(event) shot_response:safe("impact", event) end)
events.createmove:set(function(cmd) shot_response:safe("command", cmd) end)
events.render:set(function() shot_response:safe("watchdog") end)
events.round_prestart:set(function() shot_response:reset() end)
events.shutdown:set(function()
    response_running = false
    shot_response:shutdown()
end)
