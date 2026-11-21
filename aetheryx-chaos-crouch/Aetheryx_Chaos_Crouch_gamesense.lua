-- Aetheryx Chaos Crouch | GameSense CS:GO | revision 1.0
-- Standalone extraction of the two uploaded chaotic delay modes plus an
-- experimental bounded variant. No claim of preventing hits/resolution.
-- Only grounded, nearly stationary crouch. No dependencies or FFI.
local C={refs={},owned={},active=false,entry=0,clock={},serial=nil,loading=false}
C.ui={}
local function control(key,kind,label,...)
    local name=label.."\nAetheryxChaosCrouch_"..key
    C.ui[key]=(kind=="check" and ui.new_checkbox or kind=="combo" and ui.new_combobox or ui.new_slider)("AA","Other",name,...)
end
control("enabled","check","Chaos Crouch")
control("mode","combo","Mode","Chaos Crouch","Chaotic Tick for League","Chaotic Flick Aggressive")
control("left","slider","Left yaw",-180,180,-58,true,"°")
control("right","slider","Right yaw",-180,180,58,true,"°")
control("hold_min","slider","Hold min",1,8,2,true,"t")
control("hold_max","slider","Hold max",1,8,4,true,"t")
control("legacy_delay","slider","Delay",1,22,4,true,"t")
control("body","slider","Body limit",0,58,58,true,"°")
function C.get(key) return ui.get(C.ui[key]) end
function C.finite(v) return type(v)=="number" and v==v and v~=math.huge and v~=-math.huge end
function C.clamp(v,a,b) return math.max(a,math.min(b,v)) end
function C.yaw(v) return (v+180)%360-180 end
function C.random(a,b) return client.random_int(math.min(a,b),math.max(a,b)) end
function C.find(key,tab,group,name,required)
    local values={pcall(ui.reference,tab,group,name)}
    if not values[1] then if required then error("[Chaos Crouch] Missing "..name) end;C.refs[key]={};return end
    table.remove(values,1);C.refs[key]=values
end
C.find("enabled","AA","Anti-aimbot angles","Enabled",true)
C.find("pitch","AA","Anti-aimbot angles","Pitch",true)
C.find("yaw_base","AA","Anti-aimbot angles","Yaw base",true)
C.find("yaw","AA","Anti-aimbot angles","Yaw",true)
C.find("jitter","AA","Anti-aimbot angles","Yaw jitter",true)
C.find("body","AA","Anti-aimbot angles","Body yaw",true)
C.find("fs_body","AA","Anti-aimbot angles","Freestanding body yaw")
C.find("limit","AA","Anti-aimbot angles","Fake yaw limit")
C.find("edge","AA","Anti-aimbot angles","Edge yaw")
C.find("roll","AA","Anti-aimbot angles","Roll")
C.find("duck","RAGE","Other","Duck peek assist")
C.find("freestanding","AA","Anti-aimbot angles","Freestanding")
function C.ref_active(refs)
    if not refs or not refs[1] then return false end
    local value=ui.get(refs[1]);local enabled
    if type(value)=="table" then enabled=#value>0
    elseif type(value)=="string" then enabled=value~="-" and value~="Off"
    else enabled=value==true end
    if refs[2] then return enabled and ui.get(refs[2])==true end
    return enabled
end
function C.eligible(cmd)
    if not C.get("enabled") then return false end
    local me=entity.get_local_player();if not me or not entity.is_alive(me) then return false end
    local team=entity.get_prop(me,"m_iTeamNum");if team~=2 and team~=3 then return false end
    local flags=entity.get_prop(me,"m_fFlags")
    local duck=entity.get_prop(me,"m_flDuckAmount")
    local vx,vy=entity.get_prop(me,"m_vecVelocity")
    if not (C.finite(flags) and C.finite(duck) and C.finite(vx) and C.finite(vy)) then return false end
    if bit.band(flags,1)==0 or duck<.8 or vx*vx+vy*vy>25 then return false end
    if entity.get_prop(me,"m_MoveType")~=2 then return false end
    if cmd and (cmd.in_jump==1 or cmd.in_jump==true or cmd.in_use==1 or cmd.in_use==true) then return false end
    if C.ref_active(C.refs.duck) or C.ref_active(C.refs.freestanding) then return false end
    local weapon=entity.get_player_weapon(me)
    if weapon then
        local throw=entity.get_prop(weapon,"m_fThrowTime")
        if C.finite(throw) and throw>0 then return false end
    end
    return true
end
function C.write(key,index,value)
    local ref=(C.refs[key] or {})[index];if not ref then return end
    local current=ui.get(ref)
    if not C.owned[ref] then C.owned[ref]={old=current,last=value} end
    if current~=value then ui.set(ref,value) end
    C.owned[ref].last=value
end
function C.restore()
    local refs={};for ref in pairs(C.owned) do refs[#refs+1]=ref end
    local first_error
    for _,ref in ipairs(refs) do
        local saved=C.owned[ref]
        local ok,err=pcall(function()
            -- Preserve an explicit edit made while this Lua owned the control.
            if ui.get(ref)==saved.last then ui.set(ref,saved.old) end
        end)
        if ok then C.owned[ref]=nil else first_error=first_error or err end
    end
    if first_error then error(first_error) end
end
function C.stop()
    C.restore();C.active=false;C.entry=0;C.clock={};C.serial=nil
end
local pattern={-1.00,.74,-.18,1.00,-.61,.27,.88,-.79}
function C.legacy_next(s,aggressive)
    if s.burst>0 then
        s.burst=s.burst-1;s.step=s.step%#pattern+1;s.multiplier=pattern[s.step]
        if aggressive then
            s.wide=0
            if s.burst<=2 and C.random(1,4)==1 then s.wide=C.random(90,130)*(s.multiplier>=0 and 1 or -1) end
        end
        return 1
    end
    s.burst=C.random(3,7);s.step=C.random(1,#pattern);s.multiplier=pattern[s.step];s.wide=0
    local first=C.get("legacy_delay")
    local low=math.max(2,math.min(first,6));local high=math.max(low,math.min(first+3,8))
    return C.random(low,high)
end
function C.pick_magnitude(s,side)
    s.bags=s.bags or {}
    local bag=s.bags[side]
    if not bag or #bag==0 then
        bag={.58,.72,.86,1.00}
        for i=#bag,2,-1 do local j=C.random(1,i);bag[i],bag[j]=bag[j],bag[i] end
        if bag[#bag]==s.last_magnitude and #bag>1 then bag[1],bag[#bag]=bag[#bag],bag[1] end
        s.bags[side]=bag
    end
    local value=table.remove(bag)
    if value==s.last_magnitude and #bag>0 then
        local other=table.remove(bag);bag[#bag+1]=value;value=other
    end
    s.last_magnitude=value;return value
end
function C.enhanced_next(s)
    local side=C.random(0,1)==0 and -1 or 1
    if side==s.side and s.side_run>=2 then side=-side end
    if side==s.side then s.side_run=s.side_run+1 else s.side=side;s.side_run=1 end
    s.multiplier=side*C.pick_magnitude(s,side);s.wide=0
    if s.burst>0 then s.burst=s.burst-1;return C.random(1,2) end
    s.burst=C.random(3,6)
    return C.random(C.get("hold_min"),C.get("hold_max"))
end
function C.next_interval(s)
    if s.mode=="Chaos Crouch" then return C.enhanced_next(s) end
    return C.legacy_next(s,s.mode=="Chaotic Flick Aggressive")
end
function C.begin()
    C.clock={mode=C.get("mode"),elapsed=0,burst=0,step=1,multiplier=-1,wide=0,side=0,side_run=0,threat=nil}
    local s=C.clock
    if s.mode~="Chaos Crouch" then s.threat=client.current_threat and client.current_threat() or 0 end
    s.interval=C.next_interval(s)
end
function C.advance()
    local s=C.clock
    -- Original modes preserve their threat-reset behavior for an honest A/B
    -- comparison. The new mode intentionally has no threat in its signature.
    if s.mode~="Chaos Crouch" then
        local threat=client.current_threat and client.current_threat() or 0
        if threat~=s.threat then C.begin();s=C.clock end
    end
    s.elapsed=s.elapsed+1
    if s.elapsed>=s.interval then s.elapsed=0;s.interval=C.next_interval(s) end
end
function C.output()
    local s=C.clock;local left,right=C.get("left"),C.get("right")
    local center=(left+right)*.5;local amplitude=math.abs(right-left)*.5
    local yaw
    if s.mode=="Chaotic Flick Aggressive" then
        amplitude=math.max(58,amplitude);yaw=C.clamp(center+amplitude*s.multiplier+s.wide,-180,180)
    elseif s.mode=="Chaotic Tick for League" then
        amplitude=C.clamp(amplitude,55,65);yaw=C.clamp(center+amplitude*s.multiplier,-65,65)
    else
        amplitude=C.clamp(amplitude,1,65)
        center=C.clamp(center,-65+amplitude,65-amplitude)
        yaw=center+amplitude*s.multiplier
    end
    local body=C.get("body")*(s.multiplier>=0 and 1 or -1)
    return C.yaw(yaw),body
end
function C.apply()
    local yaw,body=C.output()
    C.write("enabled",1,true);C.write("pitch",1,"Down");C.write("yaw_base",1,"At targets")
    C.write("yaw",1,"180");C.write("yaw",2,yaw)
    C.write("jitter",1,"Off");C.write("jitter",2,0)
    C.write("body",1,body==0 and "Off" or "Static");C.write("body",2,body)
    C.write("limit",1,math.abs(body));C.write("fs_body",1,false);C.write("edge",1,false);C.write("roll",1,0)
    C.last_yaw=yaw;C.last_body=body
end
function C.setup(cmd)
    if not C.eligible(cmd) then C.stop();return end
    local serial=cmd.command_number
    local fresh=(not serial) or serial~=C.serial
    if serial then C.serial=serial end
    local sent=cmd.chokedcommands==0 and fresh
    if not C.active then
        if sent then C.entry=C.entry+1 end
        if C.entry<2 then return end
        C.active=true;C.begin()
    end
    if sent then C.advance() end
    C.apply()
end
function C.visibility()
    local enabled=C.get("enabled");local enhanced=C.get("mode")=="Chaos Crouch"
    for key,ref in pairs(C.ui) do
        if key~="enabled" then
            local visible=enabled
            if key=="hold_min" or key=="hold_max" then visible=visible and enhanced end
            if key=="legacy_delay" then visible=visible and not enhanced end
            ui.set_visible(ref,visible)
        end
    end
end
function C.guard(fn,...)
    local ok,err=pcall(fn,...)
    if not ok then
        pcall(C.stop);C.loading=true;ui.set(C.ui.enabled,false);C.loading=false;C.visibility()
        client.color_log(235,160,100,"[Chaos Crouch] Disabled after API error: "..tostring(err))
    end
end
for _,ref in pairs(C.ui) do ui.set_callback(ref,function()
    if C.loading then return end
    C.guard(function() C.stop();C.visibility() end)
end) end
C.visibility()
client.set_event_callback("setup_command",function(cmd) C.guard(C.setup,cmd) end)
client.set_event_callback("paint_ui",function()
    if C.active and not C.eligible(nil) then C.guard(C.stop) end
end)
for _,event in ipairs({"round_start","level_init","cs_game_disconnected","pre_config_save","pre_config_load"}) do
    client.set_event_callback(event,function() C.guard(C.stop) end)
end
client.set_event_callback("post_config_load",function() C.guard(function() C.stop();C.visibility() end) end)
client.set_event_callback("shutdown",function()
    local ok,err=pcall(C.stop)
    if not ok then client.color_log(235,160,100,"[Chaos Crouch] Restore failed: "..tostring(err)) end
end)
