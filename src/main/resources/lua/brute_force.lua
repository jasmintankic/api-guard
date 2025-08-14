-- KEYS:
-- 1: z_user     (bf:z:user:<username>)
-- 2: z_ip       (bf:z:ip:<ip>)
-- 3: z_user_ip  (bf:z:userip:<username>:<ip>)
-- 4: lock_user  (bf:lock:user:<username>)
-- 5: lock_ip    (bf:lock:ip:<ip>)
-- 6: lock_user_ip (bf:lock:userip:<username>:<ip>)

-- ARGV:
-- 1: nowMs
-- 2: windowMs
-- 3: lockTtlSec
-- 4: threshold_user
-- 5: threshold_ip
-- 6: threshold_user_ip
-- 7: maxEventsPerScope
-- 8: uniqueSuffix (to keep zset member unique, e.g. a UUID)

local nowMs         = tonumber(ARGV[1])
local windowMs      = tonumber(ARGV[2])
local lockTtlSec    = tonumber(ARGV[3])
local thUser        = tonumber(ARGV[4])
local thIp          = tonumber(ARGV[5])
local thUserIp      = tonumber(ARGV[6])
local maxSize       = tonumber(ARGV[7])
local uniq          = ARGV[8]

local function touchScope(zkey, lkey, threshold)
  -- prune by time (before insert)
  redis.call('ZREMRANGEBYSCORE', zkey, 0, nowMs - windowMs)

  -- add current event with unique member
  local member = tostring(nowMs) .. ":" .. uniq
  redis.call('ZADD', zkey, nowMs, member)

  -- cap size to avoid unbounded growth
  local size = redis.call('ZCARD', zkey)
  if maxSize > 0 and size > maxSize then
    -- remove oldest extras, keep only the newest 'maxSize'
    redis.call('ZREMRANGEBYRANK', zkey, 0, size - maxSize - 1)
    size = redis.call('ZCARD', zkey)
  end

  -- soft expire on zset to allow cleanup if idle
  redis.call('EXPIRE', zkey, math.floor((windowMs / 1000) + 60))

  local locked = 0
  if threshold > 0 and size > threshold then
    locked = 1
    redis.call('SET', lkey, 1, 'EX', lockTtlSec)
  end

  return { size, locked }
end

local u  = touchScope(KEYS[1], KEYS[4], thUser)
local ip = touchScope(KEYS[2], KEYS[5], thIp)
local ui = touchScope(KEYS[3], KEYS[6], thUserIp)

-- Return: [userCount, userLocked, ipCount, ipLocked, userIpCount, userIpLocked]
return { u[1], u[2], ip[1], ip[2], ui[1], ui[2] }