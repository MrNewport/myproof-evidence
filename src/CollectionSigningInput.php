<?php
declare(strict_types=1);

namespace MyProof\Evidence;

final class CollectionSigningInput
{
    public const DOMAIN = "MyProof evidence collection v1\n";

    public static function forIndex(string $canonicalIndex): string
    {
        CollectionSchema::index((new CanonicalJson())->requireCanonical($canonicalIndex, CollectionSchema::MAX_INDEX_BYTES));
        return self::DOMAIN.hash('sha256', $canonicalIndex, true);
    }
}
