<?php
declare(strict_types=1);

namespace MyProof\Evidence;

final readonly class Event
{
    public const MAX_BYTES = 65536;

    private function __construct(public string $canonicalBytes, public string $sha256) {}

    public static function fromArray(array $fields): self
    {
        if (isset($fields['payload']) && is_array($fields['payload'])) {
            $fields['payload'] = (object) $fields['payload'];
        }
        $bytes = (new CanonicalJson())->encode((object) $fields, self::MAX_BYTES);
        return self::fromCanonical($bytes);
    }

    public static function fromCanonical(string $bytes): self
    {
        Schema::event((new CanonicalJson())->requireCanonical($bytes, self::MAX_BYTES));
        return new self($bytes, hash('sha256', $bytes));
    }

    /** Return a fresh object so callers cannot mutate the stored event. */
    public function data(): \stdClass
    {
        return (new CanonicalJson())->decode($this->canonicalBytes, self::MAX_BYTES);
    }
}
