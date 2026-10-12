<?php
declare(strict_types=1);

namespace MyProof\Evidence;

use Mmccook\JsonCanonicalizator\JsonCanonicalizator;

/** Restricted RFC 8785 serialization; not a general floating-point JCS implementation. */
final class CanonicalJson
{
    public const MAX_BYTES = 1048576;
    public const MAX_DEPTH = 32;
    public const MAX_NODES = 20000;
    public const MAX_INTEGER = 9007199254740991;

    public function decode(string $json, int $maxBytes = self::MAX_BYTES): mixed
    {
        return (new StrictJsonParser($json, min($maxBytes, self::MAX_BYTES)))->parse();
    }

    public function encode(mixed $value, int $maxBytes = self::MAX_BYTES): string
    {
        $nodes = 0;
        $stringBytes = 0;
        $this->validate($value, 0, $nodes, $stringBytes);
        $encoding = mb_internal_encoding();
        $bufferLevel = ob_get_level();
        try {
            // Upstream omits an explicit source encoding in its UTF-16BE comparator.
            mb_internal_encoding('UTF-8');
            $bytes = (new JsonCanonicalizator())->canonicalize($value);
        } finally {
            mb_internal_encoding($encoding);
            while (ob_get_level() > $bufferLevel) {
                ob_end_clean();
            }
        }
        // Upstream's JSON flags escape U+2028/2029. JCS requires literal UTF-8.
        // Match complete escape tokens, preserving literal backslash-u text.
        $bytes = preg_replace_callback('/\\\\(?:u[0-9a-fA-F]{4}|["\\\\\/bfnrt])/', static fn (array $m): string => match ($m[0]) {
            '\\u2028' => "\u{2028}",
            '\\u2029' => "\u{2029}",
            default => $m[0],
        }, $bytes);
        if (strlen($bytes) > min($maxBytes, self::MAX_BYTES)) {
            throw new EvidenceException('Canonical JSON byte limit exceeded.');
        }
        return $bytes;
    }

    public function canonicalize(string $json, int $maxBytes = self::MAX_BYTES): string
    {
        return $this->encode($this->decode($json, $maxBytes), $maxBytes);
    }

    public function requireCanonical(string $bytes, int $maxBytes = self::MAX_BYTES): mixed
    {
        $value = $this->decode($bytes, $maxBytes);
        if ($this->encode($value, $maxBytes) !== $bytes) {
            throw new EvidenceException('Stored bytes are not canonical.');
        }
        return $value;
    }

    private function validate(mixed $value, int $depth, int &$nodes, int &$stringBytes): void
    {
        if (PHP_INT_SIZE < 8 || $depth > self::MAX_DEPTH || ++$nodes > self::MAX_NODES) {
            throw new EvidenceException('JSON nesting, node or runtime limit exceeded.');
        }
        if (is_int($value)) {
            if ($value < -self::MAX_INTEGER || $value > self::MAX_INTEGER) {
                throw new EvidenceException('Unsafe integer.');
            }
        } elseif (is_string($value)) {
            $stringBytes += strlen($value);
            if ($stringBytes > self::MAX_BYTES || preg_match('//u', $value) !== 1) {
                throw new EvidenceException('Invalid or oversized UTF-8 string.');
            }
        } elseif (is_array($value) || $value instanceof \stdClass) {
            if (is_array($value) && !array_is_list($value)) {
                throw new EvidenceException('Use stdClass for JSON objects; PHP arrays must be lists.');
            }
            foreach ($value as $key => $child) {
                if ($value instanceof \stdClass) {
                    $this->validate((string) $key, $depth + 1, $nodes, $stringBytes);
                }
                $this->validate($child, $depth + 1, $nodes, $stringBytes);
            }
        } elseif (!is_null($value) && !is_bool($value)) {
            throw new EvidenceException('Only JSON primitives, safe integers, lists and stdClass objects are permitted.');
        }
    }
}
