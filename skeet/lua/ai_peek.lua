-- Movement-only peek assistant. Public GameSense API, no FFI or native patches.
-- trace_bullet tests current poses: it cannot validate historical backtrack bones.
local ui,client,entity,globals=ui,client,entity,globals
local unpack=unpack or table.unpack
local function ref(tab,group,name)
 local ok,a,b,c=pcall(ui.reference,tab,group,name);return ok and {a,b,c} or {}
end
local native={rage=ref("RAGE","Aimbot","Enabled"),quick=ref("RAGE","Other","Quick peek assist"),
 boxes=ref("RAGE","Aimbot","Target hitbox"),damage=ref("RAGE","Aimbot","Minimum damage"),
 override=ref("RAGE","Aimbot","Minimum damage override")}
local menu={enabled=ui.new_checkbox("MISC","Movement","AI Peek"),
 key=ui.new_hotkey("MISC","Movement","AI Peek key",true),
 distance=ui.new_slider("MISC","Movement","AI Peek distance",16,64,32,true,"u"),
 damage=ui.new_slider("MISC","Movement","AI Peek minimum damage",1,130,35,true,"hp"),
 risk=ui.new_checkbox("MISC","Movement","AI Peek risk filter"),
 fps=ui.new_slider("MISC","Movement","AI Peek planning FPS floor",30,120,45,true,"fps"),
 indicator=ui.new_checkbox("MISC","Movement","AI Peek indicator")}
ui.set(menu.risk,true)
local function finite(n)return type(n)=="number" and n==n and math.abs(n)<1e8 end
local function vec(x,y,z)if finite(x)and finite(y)and finite(z)then return{x=x,y=y,z=z}end end
local function add(a,b)return{x=a.x+b.x,y=a.y+b.y,z=a.z+b.z}end
local function sub(a,b)return{x=a.x-b.x,y=a.y-b.y,z=a.z-b.z}end
local function mul(a,k)return{x=a.x*k,y=a.y*k,z=a.z*k}end
local function len(a)return math.sqrt(a.x*a.x+a.y*a.y+a.z*a.z)end
local function flat(a,b)local x,y=a.x-b.x,a.y-b.y;return math.sqrt(x*x+y*y)end
local function origin(i)return vec(entity.get_prop(i,"m_vecOrigin"))end
local function value(r,default)if not r then return default end;local ok,v=pcall(ui.get,r);return ok and v or default end
local function on(r)return r[1] and value(r[1],false) and(not r[2]or value(r[2],false))end
local function yaw(x,y)return math.deg(math.atan2(y,x))end
local function angle(a,b)local d=(a-b+180)%360-180;return math.abs(d)end
local state,held,status=nil,false,"Off"
local totals={line=0,bullet=0,planning_steps=0,time_budget_yields=0,failed_queries=0,confirmed=0}
local function stop(reason)state=nil;status=reason or"Idle"end
local function snapshot(i)
 if not i or not entity.is_alive(i)or entity.is_dormant(i)then return end
 local p=origin(i);local sim=entity.get_prop(i,"m_flSimulationTime")
 local flags=entity.get_prop(i,"m_fFlags");local duck=entity.get_prop(i,"m_flDuckAmount")
 if not p or not finite(sim)or not finite(flags)or not finite(duck)then return end
 local age=globals.curtime()-sim
 local latency=client.latency and client.latency()or 0
 if age<-.05 or age>math.min(.35,.18+math.max(0,latency))then return end
 return{target=i,pos=p,sim=sim,ground=flags%2==1,duck=duck,health=entity.get_prop(i,"m_iHealth")or 100}
end
local function fresh(a,b)
 return a and b and a.target==b.target and flat(a.pos,b.pos)<=6 and math.abs(a.pos.z-b.pos.z)<=6
  and a.ground==b.ground and math.abs(a.duck-b.duck)<=.12
end
local function hitboxes()
 local selected=value(native.boxes[1],nil)
 if type(selected)~="table"then return{}end
 local has={};for _,name in ipairs(selected)do has[name]=true end
 local out={};if has.Stomach then out[#out+1]=3 end;if has.Chest then out[#out+1]=5 end
 if #out==0 and has.Head then out[1]=0 end
 return out
end
local function required_damage(s)
 local n=value(native.damage[1],0)
 if #native.override>=3 and on(native.override)then n=value(native.override[3],n)end
 if not finite(n)then return end
 if n>100 then n=s.health+n-100 end
 return math.max(ui.get(menu.damage),n)
end
local function ray(skip,a,b)
 return coroutine.yield("line",skip,a.x,a.y,a.z,b.x,b.y,b.z)
end
local function bullet(shooter,a,b)
 return coroutine.yield("bullet",shooter,a.x,a.y,a.z,b.x,b.y,b.z)
end
-- Conservative corridor of rays, not an exact swept player hull. Stairs,
-- moving obstacles and unsupported geometry can be rejected rather than crossed.
local function path(me,a,b)
 local top=add(b,{x=0,y=0,z=24});local bottom=add(b,{x=0,y=0,z=-40})
 local f=ray(me,top,bottom)
 if not finite(f)or f<=.01 or f>=.99 then return false end
 local ground=24-64*f
 if math.abs(ground)>12 then return false end
 b={x=b.x,y=b.y,z=b.z+ground}
 local d=sub(b,a);local distance=flat(a,b);if distance<1 then return true,b end
 local side={x=-d.y/distance*18,y=d.x/distance*18,z=0}
 for _,offset in ipairs({{x=0,y=0,z=20},{x=side.x,y=side.y,z=20},
  {x=-side.x,y=-side.y,z=20},{x=0,y=0,z=50}})do
  local fraction=ray(me,add(a,offset),add(b,offset))
  if not finite(fraction)or fraction<.99 then return false end
 end
 return true,b
end
local function choose(me,p,eye,yaw0)
 local best,score
 for _,i in ipairs(entity.get_players(true)or{})do
  local s=snapshot(i)
  if s then
   local d=sub(s.pos,p);local distance=len(d);local fov=angle(yaw(d.x,d.y),yaw0)
   if distance>=48 and distance<=2200 and fov<=55 then
    local n=fov*20+distance*.02
    if not score or n<score then best,score=s,n end
   end
  end
 end
 return best
end
local function risk(me,point,target)
 -- Additional visible enemies mean an exposed exit. Enemy intention cannot
 -- be inferred; this only rejects a limited, observable crossfire condition.
 local checked=0
 for _,i in ipairs(entity.get_players(true)or{})do
  if i~=target and entity.is_alive(i)and not entity.is_dormant(i)then
   local p=origin(i)
   if p and flat(p,point)<1800 then
    local eye=vec(entity.hitbox_position(i,0))
    if not eye or checked>=3 then return false end
    checked=checked+1;local f,hit=ray(i,eye,point)
    if not finite(f)or f>=.97 or hit==me then return false end
   end
  end
 end
 return true
end
local function evaluate(s,from,to,target,boxes,need)
 local valid,p=path(s.me,from,to);if not valid then return end
 local eye=add(p,s.eye_offset);local best=0
 for _,box in ipairs(boxes)do
  local aim=vec(entity.hitbox_position(target.target,box))
  if aim then
   local visible=true
   if ui.get(menu.risk)then
    local f,hit=ray(s.me,eye,aim);visible=finite(f)and(f>=.97 or hit==target.target)
   end
   if visible then
    local hit,damage=bullet(s.me,eye,aim)
    if hit==target.target and finite(damage)and damage>=need then best=math.max(best,damage)end
   end
  end
 end
 if best<need then return end
 if ui.get(menu.risk)and not risk(s.me,eye,target.target)then return end
 return{point=p,target=target,damage=best,finished=client.timestamp()}
end
local function planner(s,from,target,boxes,need,verify)
 if verify then return evaluate(s,from,verify.point,target,boxes,need)end
 local already=evaluate(s,from,s.anchor,target,boxes,need)
 if already then already.stay=true;return already end
 local distance=ui.get(menu.distance);local side={x=-math.sin(s.yaw)*distance,y=math.cos(s.yaw)*distance,z=0}
 local best
 -- Evaluate the two nearer exits first. Do not expand after finding one.
 for _,scale in ipairs({.5,1})do
  for _,sign in ipairs({1,-1})do
   local candidate=evaluate(s,from,add(s.anchor,mul(side,scale*sign)),target,boxes,need)
   if candidate then
    candidate.score=candidate.damage-flat(s.anchor,candidate.point)*.25
    if not best or candidate.score>best.score then best=candidate end
   end
  end
  if best then break end
 end
 return best
end
local function begin_job(s,fn,...)
 local args={...};s.job={co=coroutine.create(function()return fn(unpack(args))end),args={}}
end
local function advance(s)
 local job=s.job;if not job then return end
 local started=client.timestamp();local lines,bullets=0,0
 totals.planning_steps=totals.planning_steps+1
 while true do
  if not job.request then
   local result={coroutine.resume(job.co,unpack(job.args))};job.args={}
   if not result[1]then totals.failed_queries=totals.failed_queries+1;s.job=nil;return true,nil end
   if coroutine.status(job.co)=="dead"then s.job=nil;return true,result[2]end
   table.remove(result,1);job.request=result
  end
  local r=job.request;local kind=r[1]
  if (kind=="line"and lines>=6)or(kind=="bullet"and bullets>=2)or client.timestamp()-started>=.7 then
   totals.time_budget_yields=totals.time_budget_yields+1;return
  end
  local fn=kind=="line"and client.trace_line or kind=="bullet"and client.trace_bullet
  if not fn then s.job=nil;return true,nil end
  local args={};for i=2,#r do args[#args+1]=r[i]end
  local ok,a,b=pcall(fn,unpack(args))
  if kind=="line"then lines=lines+1;totals.line=totals.line+1 else bullets=bullets+1;totals.bullet=totals.bullet+1 end
  if not ok then totals.failed_queries=totals.failed_queries+1;s.job=nil;return true,nil end
  job.request=nil;job.args={a,b}
 end
end
local function retreat(s,reason)
 s.phase="return";s.job=nil;s.next=0;s.return_reason=reason;s.route=nil;s.progress=nil;status="Returning"
end
local function move(cmd,to,p)
 local d=sub(to,p);local distance=flat(to,p)
 cmd.move_yaw=yaw(d.x,d.y);cmd.forwardmove=math.min(160,distance*18);cmd.sidemove=0
end
local function ready(me,weapon)
 local t=globals.curtime();local a=entity.get_prop(weapon,"m_flNextPrimaryAttack");local b=entity.get_prop(me,"m_flNextAttack")
 local clip=entity.get_prop(weapon,"m_iClip1")
 return finite(a)and finite(b)and finite(clip)and clip>0 and a<=t+globals.tickinterval()and b<=t+globals.tickinterval()
end
local function command(cmd)
 local pressed=ui.get(menu.enabled)and ui.get(menu.key)
 if not pressed then held=false;stop("Idle");return end
 if held and not state then return end
 held=true
 if ui.is_menu_open and ui.is_menu_open()then stop("Menu open");return end
 if not on(native.rage)then stop("Rage inactive");return end
 if on(native.quick)then stop("Native quick peek active");return end
 local me=entity.get_local_player();local p=me and origin(me)
 if not me or not p or not entity.is_alive(me)then stop("Unavailable");return end
 local flags=entity.get_prop(me,"m_fFlags");local move_type=entity.get_prop(me,"movetype")
 if move_type==nil then move_type=entity.get_prop(me,"m_MoveType")end
 if not finite(flags)or flags%2~=1 or move_type~=2 then stop("Ground movement only");return end
 for _,k in ipairs({"in_forward","in_back","in_moveleft","in_moveright","in_jump","in_use"})do
  if cmd[k]==1 then stop("Manual input");return end
 end
 local weapon=entity.get_player_weapon(me);local class=weapon and entity.get_classname(weapon)or""
 if not weapon or class:find("Knife")or class=="CC4"or class=="CFlashbang"or class:find("Grenade")then stop("Unsupported weapon");return end
 local timestamp=client.timestamp()
 local duck=entity.get_prop(me,"m_flDuckAmount")
 if not finite(duck)then stop("Unavailable");return end
 if not state then
  local eye=vec(client.eye_position());local _,camera=client.camera_angles()
  if not eye or not finite(camera)then stop("Unavailable");return end
  state={me=me,weapon=weapon,anchor=p,eye_offset=sub(eye,p),yaw=math.rad(camera),duck=duck,phase="search",next=0,started=timestamp}
 end
 local s=state;local moving=false
 if me~=s.me or weapon~=s.weapon or math.abs(duck-s.duck)>.12 or math.abs(p.z-s.anchor.z)>18 or flat(p,s.anchor)>ui.get(menu.distance)+12 then stop("Context changed");return end
 if s.phase=="done"then return end
 if s.phase~="return"and not ready(me,weapon)then
  if flat(p,s.anchor)>3 then retreat(s,"Weapon unavailable")else s.job=nil;s.candidate=nil;s.target=nil;status="Waiting for weapon";return end
 end
 if s.phase=="search"and flat(p,s.anchor)>3 then stop("Anchor moved");return end
 if timestamp>=s.next then
  s.next=timestamp+50
  if s.phase=="return"then
   if not s.job then begin_job(s,function()local ok,q=path(me,p,s.anchor);return ok and q end)end
   local done,q=advance(s)
   if done then if not q then stop("Return blocked");return end;s.route={point=q,time=timestamp}end
  else
   local frame=globals.absoluteframetime()
   if frame>1/ui.get(menu.fps)then
    if s.phase~="search"then retreat(s,"Low FPS")else s.job=nil;s.candidate=nil;status="Planning paused: FPS"end
   else
    local target=snapshot(s.target and s.target.target or nil)
    if not target and s.phase=="search"then target=choose(me,p,nil,math.deg(s.yaw))end
    local boxes=hitboxes();local need=target and required_damage(target)
    if not target or #boxes==0 or not need then
     s.job=nil;s.candidate=nil
     if s.phase~="search"then retreat(s,"No valid target")else status="No valid target"end
    else
     if ui.get(menu.risk)and #boxes==1 and boxes[1]==0 and(not target.ground or target.duck>.5)then
      s.job=nil;s.candidate=nil;if s.phase~="search"then retreat(s,"Uncertain head")else status="Uncertain head"end
     else
      local signature=table.concat(boxes,",")..":"..need..":"..tostring(ui.get(menu.risk))..":"..ui.get(menu.distance)
      if s.signature and s.signature~=signature then
       s.job=nil;s.candidate=nil
       if s.phase~="search"then retreat(s,"Settings changed");return end
      end
      s.signature=signature
      if not s.job then
       s.target=target
       begin_job(s,planner,s,p,target,boxes,need,s.plan or s.candidate)
      end
      local done,plan=advance(s)
      if done then
       if not plan or not fresh(plan.target,snapshot(plan.target.target))then
        s.candidate=nil;if s.phase~="search"then retreat(s,"Plan invalid")else status="Searching"end
       elseif s.phase=="search"and plan.stay then s.candidate=nil;status="Shot possible at anchor"
       elseif s.phase=="search"then
        local previous=s.candidate
        if previous and fresh(previous.target,plan.target)and previous.target.sim~=plan.target.sim and flat(previous.point,plan.point)<2 then
         s.phase="out";s.plan=plan;s.committed=timestamp;s.checked=timestamp;totals.confirmed=totals.confirmed+1;status="Peeking"
        else s.candidate=plan;status="Confirming"end
       else s.plan=plan;s.checked=timestamp end
      end
     end
    end
   end
  end
 end
 if state~=s then return end
 if s.phase=="out"or s.phase=="hold"then
  if timestamp-s.committed>900 or timestamp-(s.checked or 0)>200 then retreat(s,"Timeout")
  elseif flat(p,s.plan.point)<=3 then s.phase="hold";status="Holding";cmd.forwardmove=0;cmd.sidemove=0
  else move(cmd,s.plan.point,p);moving=true end
 end
 if s.phase=="return"then
  if flat(p,s.anchor)<=3 then s.phase="done";s.job=nil;status="Returned";cmd.forwardmove=0;cmd.sidemove=0
  elseif s.route and timestamp-s.route.time<=200 then move(cmd,s.route.point,p);moving=true end
 end
 if moving then
  if s.progress and timestamp-s.progress.time>=250 then
   if flat(p,s.progress.point)<.75 then stop("Movement blocked");return end
   s.progress={point=p,time=timestamp}
  elseif not s.progress then s.progress={point=p,time=timestamp}end
 else s.progress=nil end
end
client.set_event_callback("setup_command",command)
client.set_event_callback("aim_fire",function()if state and(state.phase=="out"or state.phase=="hold")then retreat(state,"Shot")end end)
client.set_event_callback("round_start",function()stop("Round changed")end)
client.set_event_callback("shutdown",function()stop("Unloaded")end)
client.set_event_callback("paint",function()
 if ui.get(menu.enabled)and ui.get(menu.indicator)then renderer.indicator(180,210,220,255,"AI PEEK: "..status)end
end)
ui.new_button("MISC","Movement","AI Peek diagnostic report",function()
 writefile("ai_peek_diagnostics.json",json.stringify({version="1.0",state=status,counters=totals,
  historical_pose_validation=false,exact_hull_trace=false,gameplay_tests_here=false}))
end)
return{fresh=fresh,path=path,advance=advance,menu=menu,status=function()return status end,counters=totals}
