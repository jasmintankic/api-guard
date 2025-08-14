-- KEYS:
-- 1: ZSET of IPs       (dsa:ips:<principal>)
-- 2: last seen IP key  (dsa:lastip:<principal>)
-- 3: IP switch counter (dsa:ipswitch:<principal>)
-- 4: lock key          (dsa:lock:<principal>)

-- ARGV:
-- 1: current IP
-- 2: now (epoch seconds)
-- 3: windowSeconds
-- 4: distinctIpThreshold
-- 5: ipSwitchThreshold
-- 6: maxZsetSize
-- 7: lockTTL

local zsetKey     = KEYS[1]
local lastIpKey   = KEYS[2]
local switchKey   = KEYS[3]
local lockKey     = KEYS[4]

local ip          = ARGV[1]
local now         = tonumber(ARGV[2])
local window      = tonumber(ARGV[3])
local ipThreshold = tonumber(ARGV[4])
local switchThreshold = tonumber(ARGV[5])
local maxZsetSize = tonumber(ARGV[6])
local lockTTL     = tonumber(ARGV[7])

-- 1. Prune old IPs
redis.call('ZREMRANGEBYSCORE', zsetKey, 0, now - window)

-- 2. Add current IP
redis.call('ZADD', zsetKey, now, ip)

-- 3. Cap ZSET size
local currentSize = redis.call('ZCARD', zsetKey)
if currentSize > maxZsetSize then
  redis.call('ZREMRANGEBYRANK', zsetKey, 0, currentSize - maxZsetSize - 1)
end

-- 4. Count distinct IPs
local distinctIps = redis.call('ZCARD', zsetKey)

-- 5. IP switch detection
local lastIp = redis.call('GET', lastIpKey)
local ipSwitches = 0
if not lastIp or lastIp ~= ip then
  ipSwitches = redis.call('INCR', switchKey)
  redis.call('SET', lastIpKey, ip, 'EX', window)
  redis.call('EXPIRE', switchKey, window)
else
  redis.call('EXPIRE', lastIpKey, window)
end

-- 6. Decision: lock if needed
local abuse = 0
if distinctIps >= ipThreshold or ipSwitches >= switchThreshold then
  abuse = 1
  redis.call('SET', lockKey, 1, 'EX', lockTTL)
end

return { abuse, distinctIps, ipSwitches }
