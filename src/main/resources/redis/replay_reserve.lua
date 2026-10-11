-- Prevalidate every key and control field before the only write (SET NX).
local control_type = redis.call('TYPE', KEYS[1]).ok
if control_type ~= 'hash' then
    return 'AUTHORITY_CLOSED'
end
if redis.call('HLEN', KEYS[1]) ~= 7 then
    return 'AUTHORITY_CLOSED'
end

local replay_type = redis.call('TYPE', KEYS[2]).ok
if replay_type ~= 'none' and replay_type ~= 'string' then
    return 'AUTHORITY_CLOSED'
end
if replay_type == 'string' and redis.call('GET', KEYS[2]) ~= '1' then
    return 'AUTHORITY_CLOSED'
end

local control = redis.call('HMGET', KEYS[1], 'schemaVersion', 'state', 'generation',
    'redisRunId', 'controllerId', 'controllerFence', 'leaseUntilMs')
if control[1] ~= '1' or control[2] ~= 'READY' or control[3] ~= ARGV[1]
    or control[4] ~= ARGV[2] or not control[5] or not control[6] or not control[7] then
    return 'AUTHORITY_CLOSED'
end

if not string.match(control[6], '^%d+$') or not string.match(control[7], '^%d+$') then
    return 'AUTHORITY_CLOSED'
end
local fence = tonumber(control[6])
local lease_until = tonumber(control[7])
if not fence or not lease_until or fence > 9007199254740991
    or lease_until > 9007199254740991 then
    return 'AUTHORITY_CLOSED'
end

local current_time = redis.call('TIME')
local now_ms = tonumber(current_time[1]) * 1000 + math.floor(tonumber(current_time[2]) / 1000)
if now_ms >= lease_until then
    return 'AUTHORITY_CLOSED'
end

local reserved = redis.call('SET', KEYS[2], '1', 'NX', 'PX', 120000)
if reserved then
    return 'RESERVED'
end
return 'REPLAYED'
