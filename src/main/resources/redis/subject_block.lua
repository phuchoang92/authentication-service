-- Applies only a customer block. Never clears an administrative or reset barrier.
-- All reads and type/value checks precede the first write.
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' then return 'AUTHORITY_CLOSED' end
if redis.call('HLEN', KEYS[1]) ~= 7 then return 'AUTHORITY_CLOSED' end
local guard_type = redis.call('TYPE', KEYS[2]).ok
if guard_type ~= 'none' and guard_type ~= 'hash' then return 'AUTHORITY_CLOSED' end

local control = redis.call('HMGET', KEYS[1], 'schemaVersion', 'state', 'generation',
    'redisRunId', 'controllerId', 'controllerFence', 'leaseUntilMs')
if control[1] ~= '1' or control[2] ~= 'READY' or control[3] ~= ARGV[1]
    or control[4] ~= ARGV[2] or not control[5] or not control[6] or not control[7] then
    return 'AUTHORITY_CLOSED'
end

for _, index in ipairs({6, 7}) do
    if not string.match(control[index], '^%d+$') then return 'AUTHORITY_CLOSED' end
    local number = tonumber(control[index])
    if not number or number > 9007199254740991 then return 'AUTHORITY_CLOSED' end
end
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if now_ms >= tonumber(control[7]) then return 'AUTHORITY_CLOSED' end

for _, index in ipairs({4, 5, 6}) do
    if not string.match(ARGV[index], '^%d+$') then return 'INVALID_INPUT' end
    local number = tonumber(ARGV[index])
    if not number or number > 9007199254740991 then return 'INVALID_INPUT' end
end
if ARGV[3] == '' or ARGV[4] == '0' then return 'INVALID_INPUT' end

local admin_deny = '0'
local reset_operation = ''
if guard_type == 'hash' then
    if redis.call('HLEN', KEYS[2]) ~= 11 then return 'AUTHORITY_CLOSED' end
    local guard = redis.call('HMGET', KEYS[2], 'schemaVersion', 'owner', 'scope',
        'generation', 'guardVersion', 'minCustomerSecurityVersion',
        'minCredentialSecurityVersion', 'minDeviceSecurityVersion',
        'customerDenied', 'administrativeDenied', 'resetOperationId')
    if guard[1] ~= '1' or guard[2] ~= ARGV[3] or guard[3] ~= 'SUBJECT'
        or guard[4] ~= ARGV[1] or not guard[11]
        or (guard[9] ~= '0' and guard[9] ~= '1')
        or (guard[10] ~= '0' and guard[10] ~= '1')
        or guard[8] ~= '0' then
        return 'AUTHORITY_CLOSED'
    end
    if guard[11] ~= '' then
        if string.len(guard[11]) ~= 36
            or string.sub(guard[11], 9, 9) ~= '-'
            or string.sub(guard[11], 14, 14) ~= '-'
            or string.sub(guard[11], 19, 19) ~= '-'
            or string.sub(guard[11], 24, 24) ~= '-'
            or not string.match(guard[11], '^[0-9a-f%-]+$') then
            return 'AUTHORITY_CLOSED'
        end
    end
    for _, index in ipairs({5, 6, 7, 8}) do
        if not guard[index] or not string.match(guard[index], '^%d+$') then
            return 'AUTHORITY_CLOSED'
        end
        local number = tonumber(guard[index])
        if not number or number > 9007199254740991 then return 'AUTHORITY_CLOSED' end
    end
    if tonumber(ARGV[4]) < tonumber(guard[5])
        or tonumber(ARGV[5]) < tonumber(guard[6])
        or tonumber(ARGV[6]) < tonumber(guard[7]) then return 'STALE' end
    if tonumber(ARGV[4]) == tonumber(guard[5]) then
        if guard[9] == '1' and ARGV[5] == guard[6] and ARGV[6] == guard[7]
            then return 'ALREADY_APPLIED' end
        return 'STALE'
    end
    admin_deny = guard[10]
    reset_operation = guard[11]
end

redis.call('HSET', KEYS[2],
    'schemaVersion', '1', 'owner', ARGV[3], 'scope', 'SUBJECT',
    'generation', ARGV[1], 'guardVersion', ARGV[4],
    'minCustomerSecurityVersion', ARGV[5],
    'minCredentialSecurityVersion', ARGV[6],
    'minDeviceSecurityVersion', '0', 'customerDenied', '1',
    'administrativeDenied', admin_deny, 'resetOperationId', reset_operation)
return 'APPLIED'
