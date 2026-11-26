-- Horizontal extrapolation reconstructed from BLGODZ's Predict option.
-- Samples use {x, y, z, t}. Sample timestamps and now are in seconds.
local DEFAULT_MAX_LEAD_MS = 200

local function predict(latest, previous, now, max_lead_ms)
    local result = {x = latest.x, y = latest.y, z = latest.z}

    if previous == nil or latest.t <= previous.t then
        return result, 0
    end

    local sample_interval = latest.t - previous.t
    local max_lead = (max_lead_ms or DEFAULT_MAX_LEAD_MS) / 1000
    local lead = math.max(0, math.min(now - latest.t, max_lead))
    local vx = (latest.x - previous.x) / sample_interval
    local vy = (latest.y - previous.y) / sample_interval

    result.x = latest.x + vx * lead
    result.y = latest.y + vy * lead
    return result, lead
end

return predict
