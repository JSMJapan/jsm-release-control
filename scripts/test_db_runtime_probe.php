<?php
declare(strict_types=1);

namespace JsmTestDbRuntime2760;

// Library only. No request/DB/application is opened on include. The private
// installer/FPM entry will call the completed producer; no public URL exists.
const VERSION = 'jsm-test-db-runtime-2760-v1';
const MAX_FRAME = 4096;

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

function frame(string $nonce, string $digest, string $role, int $sequence, array $payload): string
{
    if (!preg_match('/\A[0-9a-f]{32}\z/D', $nonce) || !preg_match('/\A[0-9a-f]{64}\z/D', $digest)
        || !in_array($role, ['ROOT', 'PHP'], true) || $sequence < 0 || $sequence > 6
        || !in_array($payload['stage'] ?? null, ['HELLO','TARGET','OPEN','CONNECTED','SELECT','RESULT','ABORT'], true)) {
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
