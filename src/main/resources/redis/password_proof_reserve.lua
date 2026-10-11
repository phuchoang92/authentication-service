-- All proof markers are checked before any write. This is a single-primary authority script.
if #KEYS ~= 3 and #KEYS ~= 4 then
    return 'AUTHORITY_CLOSED'
end
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' or redis.call('HLEN', KEYS[1]) ~= 7 then
    return 'AUTHORITY_CLOSED'
end
local control = redis.call('HMGET', KEYS[1], 'schemaVersion', 'state', 'generation',
    'redisRunId', 'controllerId', 'controllerFence', 'leaseUntilMs')
if control[1] ~= '1' or control[2] ~= 'READY' or not control[3]
    or control[4] ~= ARGV[1] or not control[5] or not control[6] or not control[7] then
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
local repeated = false
for i = 2, #KEYS do
    local marker_type = redis.call('TYPE', KEYS[i]).ok
    if marker_type ~= 'none' and marker_type ~= 'string' then
        return 'AUTHORITY_CLOSED'
    end
    if marker_type == 'string' and redis.call('GET', KEYS[i]) ~= '1' then
        return 'AUTHORITY_CLOSED'
    end
    if marker_type == 'string' then
        repeated = true
    end
end
if repeated then
    return 'REPLAYED'
end
for i = 2, #KEYS do
    redis.call('SET', KEYS[i], '1', 'PX', 120000)
end
return 'RESERVED:' .. control[3]
