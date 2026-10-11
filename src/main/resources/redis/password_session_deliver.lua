-- DELIVER reads the live guard. ADMIT consumes a proof and may touch eligible activity.
if (#KEYS ~= 7 or #ARGV ~= 8) and (#KEYS ~= 8 or #ARGV ~= 14) then
    return 'CLOSED'
end
local function numeric(value)
    if not value or not string.match(value, '^%d+$') then return nil end
    local parsed = tonumber(value)
    if not parsed or parsed > 9007199254740991 then return nil end
    return parsed
end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' or redis.call('HLEN', KEYS[1]) ~= 7 then
    return 'CLOSED'
end
local control = redis.call('HMGET', KEYS[1], 'schemaVersion','state','generation',
    'redisRunId','controllerId','controllerFence','leaseUntilMs')
if control[1] ~= '1' or control[2] ~= 'READY' or control[3] ~= ARGV[2]
    or control[4] ~= ARGV[1] or not control[5]
    or not numeric(control[6]) or not numeric(control[7])
    or now >= numeric(control[7]) then return 'CLOSED' end
if redis.call('TYPE', KEYS[2]).ok ~= 'hash' or redis.call('HLEN', KEYS[2]) ~= 7 then
    return 'CLOSED'
end
local feed = redis.call('HMGET', KEYS[2], 'schemaVersion','source',
    'transportProfileVersion','appliedCheckpointDigest','observedAtMs',
    'validUntilMs','state')
if feed[1] ~= '1' or feed[2] ~= ARGV[8] or not feed[3] or not feed[4]
    or not numeric(feed[5]) or not numeric(feed[6]) or feed[7] ~= 'CURRENT'
    or now >= numeric(feed[6]) then return 'CLOSED' end
if redis.call('TYPE', KEYS[3]).ok ~= 'hash' or redis.call('HLEN', KEYS[3]) ~= 11
    or redis.call('TYPE', KEYS[4]).ok ~= 'hash' or redis.call('HLEN', KEYS[4]) ~= 12
    or redis.call('TYPE', KEYS[5]).ok ~= 'hash' or redis.call('HLEN', KEYS[5]) ~= 12
    or redis.call('TYPE', KEYS[6]).ok ~= 'hash' or redis.call('HLEN', KEYS[6]) ~= 23
    or redis.call('TYPE', KEYS[7]).ok ~= 'hash' or redis.call('HLEN', KEYS[7]) ~= 9 then
    return 'CLOSED'
end
local s = redis.call('HMGET', KEYS[6], 'schemaVersion','state','sessionId',
    'subjectId','appId','audience','channel','scope','deviceBindingId','requestKeyJkt',
    'requestPublicJwk','generation','customerSecurityVersion',
    'credentialSecurityVersion','deviceSecurityVersion','sessionVersion',
    'customerStatusVersion','customerStatusValidUntilMs','createdAtMs',
    'idleExpiresAtMs','absoluteExpiresAtMs','nonceFamilyId','assurance')
if s[1] ~= '1' or s[2] ~= 'ACTIVE' or s[3] ~= ARGV[3]
    or s[4] ~= ARGV[4] or s[5] ~= ARGV[7] or s[6] ~= ARGV[7]
    or s[9] ~= ARGV[5] or s[10] ~= ARGV[6]
    or s[12] ~= ARGV[2] or s[22] ~= ARGV[3]
    or not numeric(s[13]) or not numeric(s[14]) or not numeric(s[15])
    or not numeric(s[16]) or not numeric(s[17]) or not numeric(s[18])
    or not numeric(s[19]) or not numeric(s[20]) or not numeric(s[21])
    or now >= numeric(s[18]) or now >= numeric(s[20])
    or now >= numeric(s[21]) then return 'CLOSED' end
local subject = redis.call('HMGET', KEYS[3], 'schemaVersion','owner','scope',
    'generation','guardVersion','minCustomerSecurityVersion',
    'minCredentialSecurityVersion','minDeviceSecurityVersion','customerDenied',
    'administrativeDenied','resetOperationId')
local device = redis.call('HMGET', KEYS[4], 'schemaVersion','owner','scope',
    'bindingId','generation','guardVersion','minCustomerSecurityVersion',
    'minCredentialSecurityVersion','minDeviceSecurityVersion','customerDenied',
    'administrativeDenied','resetOperationId')
local session_guard = redis.call('HMGET', KEYS[5], 'schemaVersion','owner','scope',
    'sessionId','generation','guardVersion','minCustomerSecurityVersion',
    'minCredentialSecurityVersion','minDeviceSecurityVersion','customerDenied',
    'administrativeDenied','resetOperationId')
if subject[1] ~= '1' or subject[2] ~= s[4] or subject[3] ~= 'SUBJECT'
    or subject[4] ~= s[12] or not numeric(subject[5])
    or not numeric(subject[6]) or not numeric(subject[7])
    or subject[8] ~= '0' or subject[9] ~= '0' or subject[10] ~= '0'
    or subject[11] ~= '' or numeric(subject[6]) > numeric(s[13])
    or numeric(subject[7]) > numeric(s[14]) then return 'CLOSED' end
if device[1] ~= '1' or device[2] ~= s[4] or device[3] ~= 'DEVICE'
    or device[4] ~= s[9] or device[5] ~= s[12]
    or not numeric(device[6]) or not numeric(device[7])
    or not numeric(device[8]) or not numeric(device[9])
    or device[10] ~= '0' or device[11] ~= '0' or device[12] ~= ''
    or numeric(device[7]) > numeric(s[13])
    or numeric(device[8]) > numeric(s[14])
    or numeric(device[9]) > numeric(s[15]) then return 'CLOSED' end
if session_guard[1] ~= '1' or session_guard[2] ~= s[4]
    or session_guard[3] ~= 'SESSION' or session_guard[4] ~= s[3]
    or session_guard[5] ~= s[12] or not numeric(session_guard[6])
    or not numeric(session_guard[7]) or not numeric(session_guard[8])
    or not numeric(session_guard[9]) or session_guard[10] ~= '0'
    or session_guard[11] ~= '0' or session_guard[12] ~= ''
    or numeric(session_guard[7]) > numeric(s[13])
    or numeric(session_guard[8]) > numeric(s[14])
    or numeric(session_guard[9]) > numeric(s[15]) then return 'CLOSED' end
local nonce = redis.call('HMGET', KEYS[7], 'schemaVersion','familyId',
    'requestKeyJkt','familyVersion','currentDigest','currentExpiresAtMs',
    'previousDigest','previousExpiresAtMs','familyDeadlineMs')
if redis.call('HLEN', KEYS[7]) ~= 9 or nonce[1] ~= '1' or nonce[2] ~= s[3]
    or nonce[3] ~= s[10] or not numeric(nonce[4]) or not nonce[5]
    or not numeric(nonce[6]) or not numeric(nonce[8])
    or not numeric(nonce[9]) then return 'CLOSED' end
if #KEYS == 7 then return 'DELIVERABLE' end
if ARGV[9] ~= 'ADMIT' or (ARGV[11] ~= '0' and ARGV[11] ~= '1')
    or string.len(ARGV[10]) ~= 43 or string.len(ARGV[12]) ~= 43
    or not numeric(ARGV[13]) or not numeric(ARGV[14])
    or numeric(ARGV[13]) < 1000 or numeric(ARGV[13]) > 120000
    or numeric(ARGV[14]) > numeric(ARGV[13]) then return 'CLOSED' end
local marker_type = redis.call('TYPE', KEYS[8]).ok
if marker_type ~= 'none' and marker_type ~= 'string' then return 'CLOSED' end
if marker_type == 'string' then
    if redis.call('GET', KEYS[8]) == '1' then return 'REPLAYED' end
    return 'CLOSED'
end
local current = nonce[5] == ARGV[10] and now < numeric(nonce[6])
local previous = nonce[7] == ARGV[10] and now < numeric(nonce[8])
if not current and not previous then
    if nonce[5] ~= ARGV[10] or now < numeric(nonce[6])
        or now >= numeric(nonce[9]) or numeric(nonce[4]) >= 9007199254740991 then
        return 'DENIED'
    end
    local next_expiry = math.min(now + numeric(ARGV[13]), numeric(nonce[9]))
    redis.call('HSET', KEYS[7], 'familyVersion', tostring(numeric(nonce[4]) + 1),
        'currentDigest', ARGV[12], 'currentExpiresAtMs', tostring(next_expiry),
        'previousDigest', nonce[5],
        'previousExpiresAtMs', tostring(math.min(now + numeric(ARGV[14]), next_expiry)))
    return 'NONCE_REQUIRED'
end
redis.call('SET', KEYS[8], '1', 'PX', 120000)
local idle = numeric(s[20])
if ARGV[11] == '1' then
    idle = math.min(now + 900000, numeric(s[21]))
    redis.call('HSET', KEYS[6], 'idleExpiresAtMs', tostring(idle))
    redis.call('PEXPIREAT', KEYS[6], idle)
end
return 'ADMITTED:' .. tostring(idle) .. ':' .. s[21]
