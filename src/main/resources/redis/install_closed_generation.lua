-- Installs only CLOSED. A recovery controller must own a committed SQL fence first.
local existing_type = redis.call('TYPE', KEYS[1]).ok
if existing_type ~= 'none' and existing_type ~= 'hash' then return 'AUTHORITY_CLOSED' end
if ARGV[1] == '' or ARGV[2] == '' or ARGV[3] == '' then return 'INVALID_INPUT' end
for _, index in ipairs({4, 5}) do
    if not string.match(ARGV[index], '^%d+$') then return 'INVALID_INPUT' end
    local value = tonumber(ARGV[index])
    if not value or value > 9007199254740991 then return 'INVALID_INPUT' end
end
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if now_ms >= tonumber(ARGV[5]) then return 'INVALID_INPUT' end

if existing_type == 'hash' then
    if redis.call('HLEN', KEYS[1]) ~= 7 then return 'AUTHORITY_CLOSED' end
    local existing = redis.call('HMGET', KEYS[1], 'schemaVersion', 'state',
        'generation', 'redisRunId', 'controllerId', 'controllerFence', 'leaseUntilMs')
    if existing[1] ~= '1' or (existing[2] ~= 'READY' and existing[2] ~= 'CLOSED'
        and existing[2] ~= 'REBUILDING') or not existing[3] or not existing[4]
        or not existing[5] or not existing[6] or not existing[7]
        or not string.match(existing[6], '^%d+$')
        or not string.match(existing[7], '^%d+$') then return 'AUTHORITY_CLOSED' end
    local old_fence = tonumber(existing[6])
    local old_lease = tonumber(existing[7])
    if not old_fence or not old_lease or old_fence > 9007199254740991
        or old_lease > 9007199254740991 then return 'AUTHORITY_CLOSED' end
    if tonumber(ARGV[4]) < old_fence then return 'STALE' end
    if tonumber(ARGV[4]) == old_fence then
        if existing[2] == 'CLOSED' and existing[3] == ARGV[1]
            and existing[4] == ARGV[2] and existing[5] == ARGV[3]
            and existing[7] == ARGV[5] then return 'ALREADY_INSTALLED' end
        return 'STALE'
    end
end

redis.call('HSET', KEYS[1], 'schemaVersion', '1', 'state', 'CLOSED',
    'generation', ARGV[1], 'redisRunId', ARGV[2], 'controllerId', ARGV[3],
    'controllerFence', ARGV[4], 'leaseUntilMs', ARGV[5])
return 'INSTALLED'
