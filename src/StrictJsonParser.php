<?php
declare(strict_types=1);

namespace MyProof\Evidence;

/** A bounded JSON grammar reader. Decode string tokens only after checking their boundaries. */
final class StrictJsonParser
{
    private int $offset = 0;
    private int $nodes = 0;

    public function __construct(private readonly string $json, int $maxBytes)
    {
        if (PHP_INT_SIZE < 8 || strlen($json) > $maxBytes || preg_match('//u', $json) !== 1) {
            throw new EvidenceException('JSON exceeds bounds or is not valid UTF-8 on a 64-bit runtime.');
        }
    }

    public function parse(): mixed
    {
        $value = $this->value(0);
        $this->whitespace();
        if ($this->offset !== strlen($this->json)) {
            throw new EvidenceException('Trailing JSON input.');
        }
        return $value;
    }

    private function value(int $depth): mixed
    {
        if ($depth > CanonicalJson::MAX_DEPTH || ++$this->nodes > CanonicalJson::MAX_NODES) {
            throw new EvidenceException('JSON nesting or node limit exceeded.');
        }
        $this->whitespace();
        $character = $this->json[$this->offset] ?? '';
        if ($character === '"') {
            return $this->string();
        }
        if ($character === '{' || $character === '[') {
            $object = $character === '{';
            ++$this->offset;
            $result = $object ? new \stdClass() : [];
            $seen = [];
            $this->whitespace();
            $end = $object ? '}' : ']';
            if (($this->json[$this->offset] ?? '') === $end) {
                ++$this->offset;
                return $result;
            }
            while (true) {
                if ($object) {
                    $this->whitespace();
                    $key = $this->string();
                    if (++$this->nodes > CanonicalJson::MAX_NODES) {
                        throw new EvidenceException('JSON node limit exceeded.');
                    }
                    // Prefix prevents PHP's numeric-string array key coercion.
                    if (isset($seen['k'.$key]) || str_starts_with($key, "\0")) {
                        throw new EvidenceException('Duplicate or unsupported NUL-leading object key.');
                    }
                    $seen['k'.$key] = true;
                    $this->whitespace();
                    if (($this->json[$this->offset++] ?? '') !== ':') {
                        throw new EvidenceException('Missing object colon.');
                    }
                    $result->{$key} = $this->value($depth + 1);
                } else {
                    $result[] = $this->value($depth + 1);
                }
                $this->whitespace();
                $separator = $this->json[$this->offset++] ?? '';
                if ($separator === $end) {
                    return $result;
                }
                if ($separator !== ',') {
                    throw new EvidenceException('Invalid JSON separator.');
                }
            }
        }
        foreach (['true' => true, 'false' => false, 'null' => null] as $literal => $value) {
            if (substr($this->json, $this->offset, strlen($literal)) === $literal) {
                $this->offset += strlen($literal);
                return $value;
            }
        }
        if (preg_match('/\G-?(?:0|[1-9][0-9]*)/A', $this->json, $match, 0, $this->offset) === 1) {
            $token = $match[0];
            $magnitude = ltrim($token, '-');
            if ($token === '-0' || strlen($magnitude) > 16 || (strlen($magnitude) === 16 && strcmp($magnitude, '9007199254740991') > 0)) {
                throw new EvidenceException('Number is outside the canonical safe-integer profile.');
            }
            $this->offset += strlen($token);
            return (int) $token;
        }
        throw new EvidenceException('Invalid JSON value; floats and exponent forms are prohibited.');
    }

    private function string(): string
    {
        $start = $this->offset;
        if (($this->json[$this->offset++] ?? '') !== '"') {
            throw new EvidenceException('Expected JSON string.');
        }
        $length = strlen($this->json);
        while ($this->offset < $length) {
            $character = $this->json[$this->offset++];
            if ($character === '\\') {
                ++$this->offset;
            } elseif ($character === '"') {
                try {
                    return json_decode(substr($this->json, $start, $this->offset - $start), false, 2, JSON_THROW_ON_ERROR);
                } catch (\JsonException $exception) {
                    throw new EvidenceException('Invalid JSON string or Unicode surrogate.', previous: $exception);
                }
            }
        }
        throw new EvidenceException('Unterminated JSON string.');
    }

    private function whitespace(): void
    {
        $this->offset += strspn($this->json, " \t\n\r", $this->offset);
    }
}
