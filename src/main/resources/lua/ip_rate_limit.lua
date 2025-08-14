-- ip_rate_limit.lua
-- Atomic token-bucket using Redis TIME (server time).
-- KEYS[1] = credits hash key: fields "c" (credits), "ts" (last update ms)
-- ARGV:
--   1 = maxCredits (double)
--   2 = creditsPerSecond (double)
--   3 = costPerRequest (int)
--   4 = idleTtlSeconds (int)

local key   = KEYS[1]
local max   = tonumber(ARGV[1])
local cps   = tonumber(ARGV[2])
local cost  = tonumber(ARGV[3])
local ttl   = tonumber(ARGV[4])

-- Get Redis server time (seconds, microseconds) -> ms
local t = redis.call('TIME')
local nowMs = (tonumber(t[1]) * 1000) + math.floor(tonumber(t[2]) / 1000)

-- Load current state
local h = redis.call('HMGET', key, 'c', 'ts')
local credits = tonumber(h[1])
local lastMs  = tonumber(h[2])

if credits == nil then credits = max end
if lastMs  == nil then lastMs  = nowMs end

-- Refill
local elapsedSec = math.max(0, (nowMs - lastMs) / 1000.0)
credits = math.min(max, credits + elapsedSec * cps)

local allowed = 0
if credits >= cost then
  credits = credits - cost
  allowed = 1
end

-- Persist and set idle TTL
redis.call('HMSET', key, 'c', tostring(credits), 'ts', tostring(nowMs))
redis.call('EXPIRE', key, ttl)

-- Return: [allowedFlag(int), creditsAfter(string)]
return { allowed, tostring(credits) }
