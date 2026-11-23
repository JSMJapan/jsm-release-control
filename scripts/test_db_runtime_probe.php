<?php
declare(strict_types=1);

namespace JsmTestDbRuntime2760;

// Private protocol library. Including it alone never opens an application or DB.
const VERSION = 'jsm-test-db-runtime-2760-v1';
const MAX_FRAME = 4096;
const PHP_REASONS = ['STARTUP_REFUSED','CONFIG_SHAPE_REFUSED','GENERATED_CONFIG_REFUSED','STARTUP_SOURCE_REFUSED',
    'STARTUP_HOOK_REFUSED','STARTUP_CONTEXT_REFUSED','VENDOR_PROFILE_REFUSED','APPLICATION_REFUSED',
    'DB_DEFINITION_REFUSED','PDO_ATTRIBUTE_REFUSED','PDO_CAPABILITY_REFUSED','PDO_AUTH_REFUSED',
    'PDO_CONNECT_REFUSED','PDO_QUERY_REFUSED','METADATA_REFUSED','INTERNAL_REFUSED','DEADLINE'];

function canonical($value): string
{
    if (is_array($value)) {
        if (array_keys($value) !== range(0, count($value) - 1)) { ksort($value, SORT_STRING); }
        foreach ($value as $key => $item) {
            if (is_array($item)) { $value[$key] = ordered($item); }
        }
    }
    $raw = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    return $raw."\n";
}

function ordered(array $value): array
{
    if (array_keys($value) !== range(0, count($value) - 1)) { ksort($value, SORT_STRING); }
    foreach ($value as $key => $item) {
        if (is_array($item)) { $value[$key] = ordered($item); }
    }
    return $value;
}

function keys(array $value, array $expected): bool
{
    $actual = array_keys($value); sort($actual); sort($expected); return $actual === $expected;
}

function payloadValid(string $role, int $sequence, array $value): bool
{
    $stage = $value['stage'] ?? null;
    if ($role === 'ROOT') {
        if ($sequence === 0) {
            return keys($value, ['stage','publisher_uid']) && $stage === 'HELLO'
                && is_int($value['publisher_uid']) && $value['publisher_uid'] > 0 && $value['publisher_uid'] <= 2147483647;
        }
        if ($sequence === 2 || $sequence === 4) {
            return keys($value, ['stage']) && in_array($stage, $sequence === 2 ? ['OPEN','ABORT'] : ['SELECT','ABORT'], true);
        }
        if ($sequence === 6) { return keys($value, ['stage','accepted']) && $stage === 'RESULT' && is_bool($value['accepted']); }
    }
    if ($role === 'PHP') {
        if (in_array($sequence,[1,3,5],true) && $stage==='REFUSED') { return keys($value,['stage','reason']) && in_array($value['reason'],PHP_REASONS,true); }
        if ($sequence === 1) {
            return keys($value, ['stage','host','port','schema','same_db']) && $stage === 'TARGET'
                && $value['host'] === '127.0.0.1' && is_int($value['port']) && $value['port'] > 0 && $value['port'] <= 65535
                && is_string($value['schema']) && preg_match('/\A[A-Za-z0-9_]{1,64}\z/D', $value['schema']) && $value['same_db'] === true;
        }
        if ($sequence === 3) { return keys($value, ['stage','native_pdo']) && $stage === 'CONNECTED' && $value['native_pdo'] === true; }
        if ($sequence === 5) {
            return keys($value, ['stage','schema_matches','principal_kind','version_family','server_read_only','query_count'])
                && $stage === 'RESULT' && is_bool($value['schema_matches'])
                && in_array($value['principal_kind'], ['ROOT','OTHER'], true)
                && in_array($value['version_family'], ['MYSQL_5_7','MYSQL_8','MARIADB','OTHER'], true)
                && is_bool($value['server_read_only']) && $value['query_count'] === 1;
        }
    }
    return false;
}

function frame(string $nonce, string $digest, string $role, int $sequence, array $payload): string
{
    if (!preg_match('/\A[0-9a-f]{32}\z/D', $nonce) || !preg_match('/\A[0-9a-f]{64}\z/D', $digest)
        || !in_array($role, ['ROOT', 'PHP'], true) || $sequence < 0 || $sequence > 6
        || !payloadValid($role, $sequence, $payload)) {
        throw new \RuntimeException('FRAME_REFUSED');
    }
    $tag = hash_hmac('sha256', "jsm-test-db-runtime-2760\0".$digest."\0".$role."\0".$sequence."\0".canonical($payload), hex2bin($nonce));
    $raw = canonical(['context'=>$digest, 'role'=>$role, 'sequence'=>$sequence, 'payload'=>$payload, 'tag'=>$tag]);
    if (strlen($raw) > MAX_FRAME) { throw new \RuntimeException('FRAME_LIMIT'); }
    return $raw;
}

function unframe(string $raw, string $nonce, string $digest, string $role, int $sequence): array
{
    try {
        if (strlen($raw) < 1 || strlen($raw) > MAX_FRAME) { throw new \RuntimeException(); }
        $value = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($value) || array_keys(ordered($value)) !== ['context','payload','role','sequence','tag']
            || canonical($value) !== $raw || $value['context'] !== $digest || $value['role'] !== $role
            || !is_int($value['sequence']) || $value['sequence'] !== $sequence || !is_array($value['payload'])
            || !is_string($value['tag']) || !hash_equals(frame($nonce, $digest, $role, $sequence, $value['payload']), $raw)) {
            throw new \RuntimeException();
        }
        return $value['payload'];
    } catch (\Throwable $ignored) { throw new \RuntimeException('FRAME_REFUSED'); }
}
