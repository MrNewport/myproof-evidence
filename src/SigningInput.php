<?php
declare(strict_types=1);

namespace MyProof\Evidence;

final class SigningInput
{
    public const DOMAIN = "MyProof evidence v2\n";

    public static function forManifest(string $canonicalManifest): string
    {
        Schema::manifest((new CanonicalJson())->requireCanonical($canonicalManifest, 262144));
        return self::DOMAIN.hash('sha256', $canonicalManifest, true);
    }
}
