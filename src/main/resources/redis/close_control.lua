-- Fails closed; a separate fenced recovery protocol is required before READY.
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' then return 'AUTHORITY_CLOSED' end
if redis.call('HLEN', KEYS[1]) ~= 7 then return 'AUTHORITY_CLOSED' end
local control = redis.call('HMGET', KEYS[1], 'schemaVersion', 'state', 'generation',
    'redisRunId', 'controllerId', 'controllerFence', 'leaseUntilMs')
if control[1] ~= '1' or not control[2] or control[3] ~= ARGV[1]
    or control[4] ~= ARGV[2] or not control[5] or control[6] ~= ARGV[3]
    or not control[7] then return 'AUTHORITY_CLOSED' end
if not string.match(control[6], '^%d+$') or not string.match(control[7], '^%d+$')
    then return 'AUTHORITY_CLOSED' end
local fence = tonumber(control[6])
local lease = tonumber(control[7])
if not fence or not lease or fence > 9007199254740991
    or lease > 9007199254740991 then return 'AUTHORITY_CLOSED' end
if control[2] == 'CLOSED' then return 'ALREADY_CLOSED' end
if control[2] ~= 'READY' and control[2] ~= 'REBUILDING' then return 'AUTHORITY_CLOSED' end
redis.call('HSET', KEYS[1], 'state', 'CLOSED')
return 'CLOSED'
