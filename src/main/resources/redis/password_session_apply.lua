-- KEYS: control, feed, subject guard, device guard, session guard, session, nonce, receipt.
-- All key types and stored fields are checked before the first write.
if #KEYS ~= 8 or #ARGV ~= 24 then return 'AUTHORITY_CLOSED' end
local function type_is(key, expected)
    return redis.call('TYPE', key).ok == expected
end
local function integer(value)
    if not value or not string.match(value, '^%d+$') then return nil end
    local n = tonumber(value)
    if not n or n > 9007199254740991 then return nil end
    return n
end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if not integer(ARGV[13]) or not integer(ARGV[14]) or not integer(ARGV[15])
    or not integer(ARGV[16]) or string.len(ARGV[21]) ~= 43 then return 'DENIED' end
if not type_is(KEYS[1], 'hash') or redis.call('HLEN', KEYS[1]) ~= 7 then
    return 'AUTHORITY_CLOSED'
end
local c = redis.call('HMGET', KEYS[1], 'schemaVersion', 'state', 'generation',
    'redisRunId', 'controllerId', 'controllerFence', 'leaseUntilMs')
if c[1] ~= '1' or c[2] ~= 'READY' or c[3] ~= ARGV[2] or c[4] ~= ARGV[1]
    or not c[5] or not integer(c[6]) or not integer(c[7]) or now >= integer(c[7]) then
    return 'AUTHORITY_CLOSED'
end
if not type_is(KEYS[2], 'hash') or redis.call('HLEN', KEYS[2]) ~= 7 then
    return 'AUTHORITY_CLOSED'
end
local feed = redis.call('HMGET', KEYS[2], 'schemaVersion', 'source',
    'transportProfileVersion', 'appliedCheckpointDigest', 'observedAtMs',
    'validUntilMs', 'state')
if feed[1] ~= '1' or feed[2] ~= ARGV[24] or not feed[3] or not feed[4]
    or not integer(feed[5]) or not integer(feed[6]) or feed[7] ~= 'CURRENT'
    or now >= integer(feed[6]) then return 'AUTHORITY_CLOSED' end
if not type_is(KEYS[3], 'hash') or redis.call('HLEN', KEYS[3]) ~= 11 then
    return 'AUTHORITY_CLOSED'
end
local subject = redis.call('HMGET', KEYS[3], 'schemaVersion', 'owner', 'scope',
    'generation', 'guardVersion', 'minCustomerSecurityVersion',
    'minCredentialSecurityVersion', 'minDeviceSecurityVersion', 'customerDenied',
    'administrativeDenied', 'resetOperationId')
if subject[1] ~= '1' or subject[2] ~= ARGV[7] or subject[3] ~= 'SUBJECT'
    or subject[4] ~= ARGV[2] or not integer(subject[5])
    or not integer(subject[6]) or not integer(subject[7]) or subject[8] ~= '0'
    or subject[9] ~= '0' or subject[10] ~= '0' or subject[11] ~= ''
    or integer(subject[6]) > integer(ARGV[13])
    or integer(subject[7]) > integer(ARGV[14]) then return 'DENIED' end
if not type_is(KEYS[4], 'hash') or redis.call('HLEN', KEYS[4]) ~= 12 then
    return 'AUTHORITY_CLOSED'
end
local device = redis.call('HMGET', KEYS[4], 'schemaVersion', 'owner', 'scope',
    'bindingId', 'generation', 'guardVersion', 'minCustomerSecurityVersion',
    'minCredentialSecurityVersion', 'minDeviceSecurityVersion', 'customerDenied',
    'administrativeDenied', 'resetOperationId')
if device[1] ~= '1' or device[2] ~= ARGV[7] or device[3] ~= 'DEVICE'
    or device[4] ~= ARGV[8] or device[5] ~= ARGV[2]
    or not integer(device[6]) or not integer(device[7])
    or not integer(device[8]) or not integer(device[9])
    or device[10] ~= '0' or device[11] ~= '0' or device[12] ~= ''
    or integer(device[7]) > integer(ARGV[13])
    or integer(device[8]) > integer(ARGV[14])
    or integer(device[9]) > integer(ARGV[15]) then return 'DENIED' end
local idle = integer(ARGV[18])
local absolute = integer(ARGV[19])
local delivery = integer(ARGV[20])
local customer_valid = integer(ARGV[17])
local nonce_validity = integer(ARGV[23])
if not idle or not absolute or not delivery or not customer_valid or not nonce_validity
    or now >= idle or now >= absolute or now >= delivery or now >= customer_valid
    or idle > absolute or delivery > absolute or nonce_validity < 1000
    or nonce_validity > 120000 then return 'DENIED' end
if type_is(KEYS[8], 'hash') then
    local receipt = redis.call('HMGET', KEYS[8], 'schemaVersion', 'operationId',
        'intentId', 'generation', 'fence', 'inputDigest', 'outcome', 'sessionId',
        'resultDigest', 'deadlineMs')
    if redis.call('HLEN', KEYS[8]) == 10 and receipt[1] == '1'
        and receipt[2] == ARGV[3] and receipt[3] == ARGV[4]
        and receipt[4] == ARGV[2] and receipt[5] == '0'
        and receipt[6] == ARGV[5] and receipt[7] == 'APPLIED'
        and receipt[8] == ARGV[6] and receipt[9] == ARGV[5]
        and receipt[10] == ARGV[19] then return 'ALREADY_APPLIED' end
    return 'AUTHORITY_CLOSED'
end
if not type_is(KEYS[8], 'none') or not type_is(KEYS[5], 'none')
    or not type_is(KEYS[6], 'none') or not type_is(KEYS[7], 'none') then
    return 'AUTHORITY_CLOSED'
end
if string.len(ARGV[10]) > 4096 or string.len(ARGV[22]) > 1024
    or string.len(ARGV[12]) ~= 43 or string.len(ARGV[11]) ~= 43 then
    return 'AUTHORITY_CLOSED'
end
local nonce_expiry = math.min(now + nonce_validity, absolute)
redis.call('HSET', KEYS[6], 'schemaVersion', '1', 'state', 'ACTIVE',
    'sessionId', ARGV[6], 'subjectId', ARGV[7], 'appId', ARGV[9],
    'audience', ARGV[9], 'channel', 'MOBILE', 'scope', '["banking"]',
    'deviceBindingId', ARGV[8], 'requestKeyJkt', ARGV[11],
    'requestPublicJwk', ARGV[10], 'generation', ARGV[2],
    'customerSecurityVersion', ARGV[13], 'credentialSecurityVersion', ARGV[14],
    'deviceSecurityVersion', ARGV[15], 'sessionVersion', '0',
    'customerStatusVersion', ARGV[16], 'customerStatusValidUntilMs', ARGV[17],
    'createdAtMs', tostring(now), 'idleExpiresAtMs', ARGV[18],
    'absoluteExpiresAtMs', ARGV[19], 'nonceFamilyId', ARGV[6],
    'assurance', ARGV[22])
redis.call('PEXPIREAT', KEYS[6], idle)
redis.call('HSET', KEYS[5], 'schemaVersion', '1', 'owner', ARGV[7],
    'scope', 'SESSION', 'sessionId', ARGV[6], 'generation', ARGV[2],
    'guardVersion', '0', 'minCustomerSecurityVersion', ARGV[13],
    'minCredentialSecurityVersion', ARGV[14], 'minDeviceSecurityVersion', ARGV[15],
    'customerDenied', '0', 'administrativeDenied', '0', 'resetOperationId', '')
redis.call('PEXPIREAT', KEYS[5], absolute + 120000)
redis.call('HSET', KEYS[7], 'schemaVersion', '1', 'familyId', ARGV[6],
    'requestKeyJkt', ARGV[11], 'familyVersion', '0',
    'currentDigest', ARGV[12], 'currentExpiresAtMs', tostring(nonce_expiry),
    'previousDigest', '', 'previousExpiresAtMs', '0',
    'familyDeadlineMs', ARGV[19])
redis.call('PEXPIREAT', KEYS[7], absolute)
redis.call('HSET', KEYS[8], 'schemaVersion', '1', 'operationId', ARGV[3],
    'intentId', ARGV[4], 'generation', ARGV[2], 'fence', '0',
    'inputDigest', ARGV[5], 'outcome', 'APPLIED', 'sessionId', ARGV[6],
    'resultDigest', ARGV[5], 'deadlineMs', ARGV[19])
redis.call('PEXPIREAT', KEYS[8], absolute + 120000)
return 'APPLIED'
