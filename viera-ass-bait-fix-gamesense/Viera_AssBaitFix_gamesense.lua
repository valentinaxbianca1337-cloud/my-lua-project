-- Viera Ass Bait Fix | GameSense CS:GO | revision 1.0
-- Public-API adaptation, NOT a port of Neverlose lag-record/matrix patches.
-- Uses networked eye/LBY angles as a heuristic and the native player list.
-- Works against enemies on either team. No FFI, signatures or dependencies.

local A={history={},owned={},blocked={},reported={},loading=false,revision="1.0"}
A.enabled=ui.new_checkbox("AA","Other","Ass bait fix\nVieraAssBaitFix_enabled")
A.amount=ui.new_slider("AA","Other","Correction limit\nVieraAssBaitFix_amount",1,58,58,true,"°")

function A.finite(v)
    return type(v)=="number" and v==v and v~=math.huge and v~=-math.huge
end
function A.yaw(v) return (v+180)%360-180 end
function A.identity(index)
    local steam=entity.get_steam64(index)
    if steam and tostring(steam)~="0" then return tostring(steam) end
    local name=entity.get_player_name(index)
    if name and name~="unknown" then return "bot:"..name end
end
function A.context()
    local me=entity.get_local_player()
    if not me or not entity.is_alive(me) then return end
    local team=entity.get_prop(me,"m_iTeamNum")
    if team~=2 and team~=3 then return end
    return me
end
function A.valid_enemy(index)
    if not entity.is_alive(index) or entity.is_dormant(index) or not entity.is_enemy(index) then return false end
    local team=entity.get_prop(index,"m_iTeamNum")
    return team==2 or team==3
end
function A.read_player(index)
    if not A.valid_enemy(index) then return end
    local identity=A.identity(index);if not identity then return end
    local sim=entity.get_prop(index,"m_flSimulationTime")
    local duck=entity.get_prop(index,"m_flDuckAmount")
    local vx,vy=entity.get_prop(index,"m_vecVelocity")
    local _,eye=entity.get_prop(index,"m_angEyeAngles")
    local lby=entity.get_prop(index,"m_flLowerBodyYawTarget")
    if not (A.finite(sim) and A.finite(duck) and A.finite(vx) and A.finite(vy) and A.finite(eye) and A.finite(lby)) then return end
    -- Preserve the source's SQUARED velocity threshold: sqrt(90) ~= 9.49 u/s.
    if duck<.8 or vx*vx+vy*vy>90 then return end
    return {identity=identity,sim=sim,eye=A.yaw(eye),delta=A.yaw(lby-eye)}
end
function A.read_override(index)
    local flag=plist.get(index,"Force body yaw")
    local value=plist.get(index,"Force body yaw value")
    if type(flag)~="boolean" or not A.finite(value) then error("Unsupported GameSense Force body yaw fields") end
    return flag,value
end
function A.matches(index,entry)
    if A.identity(index)~=entry.identity then return false end
    local flag,value=A.read_override(index)
    return flag==true and value==entry.last
end
function A.release(index)
    local entry=A.owned[index]
    if not entry then return end
    -- A manual edit or another Lua takes precedence. Do not overwrite it.
    if A.matches(index,entry) then
        plist.set(index,"Force body yaw value",entry.value)
        plist.set(index,"Force body yaw",entry.flag)
    end
    A.owned[index]=nil
end
function A.clear()
    local indices={};for index in pairs(A.owned) do indices[#indices+1]=index end
    local first_error
    for _,index in ipairs(indices) do
        local ok,err=pcall(A.release,index)
        if not ok then first_error=first_error or err end
    end
    A.history={};A.blocked={}
    if first_error then error(first_error) end
end
function A.jitter(samples)
    local jumps,steady=0,0
    for i=2,#samples do
        if math.abs(A.yaw(samples[i].eye-samples[i-1].eye))>18 then jumps=jumps+1 else steady=steady+1 end
    end
    return jumps>steady
end
function A.correction(history)
    local samples=history.samples
    if #samples<3 or A.jitter(samples) then return end
    local last=samples[#samples]
    if math.abs(last.delta)<3 then return end
    local side=last.delta>0 and 1 or -1
    -- Three independent server samples must agree on the side. The real NL
    -- desync_weight and resolved abs_yaw are not exported by the GS API.
    for i=#samples-2,#samples do
        if math.abs(samples[i].delta)<3 or (samples[i].delta>0 and 1 or -1)~=side then return end
    end
    return side*ui.get(A.amount)
end
function A.force(index,identity,value)
    if A.blocked[index]==identity then return end
    local entry=A.owned[index]
    if entry and entry.identity~=identity then A.owned[index]=nil;entry=nil end
    if entry and not A.matches(index,entry) then
        A.owned[index]=nil;A.blocked[index]=identity;return
    end
    if not entry then
        local flag,old=A.read_override(index)
        if flag then return end -- Respect an already configured manual force.
        entry={identity=identity,flag=flag,value=old,last=value}
        A.owned[index]=entry
        -- Restore the old numeric value if enabling the checkbox fails.
        local ok,err=pcall(function()
            plist.set(index,"Force body yaw value",value)
            plist.set(index,"Force body yaw",true)
        end)
        if not ok then
            pcall(plist.set,index,"Force body yaw value",old)
            pcall(plist.set,index,"Force body yaw",flag)
            A.owned[index]=nil;error(err)
        end
    elseif entry.last~=value then
        plist.set(index,"Force body yaw value",value);entry.last=value
    end
end
function A.update()
    if not ui.get(A.enabled) or not A.context() then A.clear();return end
    local now=globals.realtime();local seen={}
    for _,index in ipairs(entity.get_players(true)) do
        local sample=A.read_player(index)
        if sample then
            seen[index]=true
            local h=A.history[index]
            if not h or h.identity~=sample.identity or sample.sim<h.sim then
                A.release(index)
                h={identity=sample.identity,sim=sample.sim,samples={sample},changed=now}
                A.history[index]=h;A.blocked[index]=nil
            elseif sample.sim>h.sim then
                -- A long gap is not a continuous history (dormancy/choke).
                if now-h.changed>.5 then h.samples={} end
                h.samples[#h.samples+1]=sample
                if #h.samples>8 then table.remove(h.samples,1) end
                h.sim=sample.sim;h.changed=now
            end
            local value=now-h.changed<=.5 and A.correction(h) or nil
            if value then A.force(index,sample.identity,value) else A.release(index) end
        end
    end
    local remove={}
    for index in pairs(A.history) do if not seen[index] then remove[#remove+1]=index end end
    for _,index in ipairs(remove) do A.release(index);A.history[index]=nil end
    -- Also release an override left by an interrupted update.
    remove={};for index in pairs(A.owned) do if not seen[index] then remove[#remove+1]=index end end
    for _,index in ipairs(remove) do A.release(index) end
end
function A.log(reason)
    local key=tostring(reason)
    if A.reported[key] then return end
    A.reported[key]=true
    client.color_log(235,160,100,"[Ass bait fix] "..key)
end
function A.fail(reason)
    pcall(A.clear)
    A.loading=true;ui.set(A.enabled,false);A.loading=false
    ui.set_visible(A.amount,false)
    A.log("Disabled after API error: "..tostring(reason))
end
function A.guard(fn,...)
    local ok,err=pcall(fn,...)
    if not ok then A.fail(err) end
end
function A.sweep()
    if not ui.get(A.enabled) or not A.context() then
        if next(A.owned) or next(A.history) then A.clear() end
        return
    end
    local now=globals.realtime();local remove={}
    for index,entry in pairs(A.owned) do
        local h=A.history[index]
        if not A.valid_enemy(index) or not h or now-h.changed>.5 or A.identity(index)~=entry.identity then
            remove[#remove+1]=index
        elseif not A.matches(index,entry) then
            A.owned[index]=nil;A.blocked[index]=entry.identity
        end
    end
    for _,index in ipairs(remove) do A.release(index);A.history[index]=nil end
end
ui.set_callback(A.enabled,function()
    if A.loading then return end
    A.guard(function()
        A.clear()
        ui.set_visible(A.amount,ui.get(A.enabled))
    end)
end)
ui.set_callback(A.amount,function() A.guard(A.update) end)
ui.set_visible(A.amount,ui.get(A.enabled))
client.set_event_callback("net_update_end",function() A.guard(A.update) end)
client.set_event_callback("paint_ui",function() A.guard(A.sweep) end)
for _,event in ipairs({"round_start","level_init","cs_game_disconnected","pre_config_load","pre_config_save"}) do
    client.set_event_callback(event,function() A.guard(A.clear) end)
end
client.set_event_callback("post_config_load",function()
    A.guard(function() A.clear();ui.set_visible(A.amount,ui.get(A.enabled)) end)
end)
client.set_event_callback("player_death",function(e)
    A.guard(function()
        local index=client.userid_to_entindex(e.userid)
        if index==entity.get_local_player() then A.clear()
        elseif index then A.release(index);A.history[index]=nil;A.blocked[index]=nil end
    end)
end)
client.set_event_callback("player_disconnect",function(e)
    A.guard(function()
        local index=client.userid_to_entindex(e.userid)
        if index then A.release(index);A.history[index]=nil;A.blocked[index]=nil end
    end)
end)
client.set_event_callback("shutdown",function()
    local ok,err=pcall(A.clear)
    if not ok then A.log("Could not restore a player-list setting: "..tostring(err)) end
end)
