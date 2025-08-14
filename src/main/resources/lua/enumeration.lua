-- enumeration.lua

local usernameKey = KEYS[1]
local ipKey = KEYS[2]
local zsetKey = KEYS[3]
local lockKey = KEYS[4]

local username = ARGV[1]
local ip = ARGV[2]
local timestamp = tonumber(ARGV[3])

local bucketTtlSec = tonumber(ARGV[4])
local lockTtlSec = tonumber(ARGV[5])
local zsetWindowMs = tonumber(ARGV[6])
local ipRateLimit = tonumber(ARGV[7])
local usernameThreshold = tonumber(ARGV[8])
local ipThreshold = tonumber(ARGV[9])

-- Add username to HLL per IP (signal A)
redis.call('PFADD', usernameKey, username)
redis.call('EXPIRE', usernameKey, bucketTtlSec)

-- Add IP to HLL per username (signal B)
redis.call('PFADD', ipKey, ip)
redis.call('EXPIRE', ipKey, bucketTtlSec)

-- Add to ZSET for IP request rate (signal C)
local zMember = timestamp .. ":" .. math.random()
redis.call('ZADD', zsetKey, timestamp, zMember)
redis.call('ZREMRANGEBYSCORE', zsetKey, 0, timestamp - zsetWindowMs)
redis.call('EXPIRE', zsetKey, bucketTtlSec)

local zCount = redis.call('ZCARD', zsetKey)
local aCount = redis.call('PFCOUNT', usernameKey)
local bCount = redis.call('PFCOUNT', ipKey)

if aCount >= usernameThreshold or bCount >= ipThreshold or zCount >= ipRateLimit then
  redis.call('SET', lockKey, 1, 'EX', lockTtlSec)
  return {1, aCount, bCount, zCount}
end

return {0, aCount, bCount, zCount}
