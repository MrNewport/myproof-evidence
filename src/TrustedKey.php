<?php
declare(strict_types=1);

namespace MyProof\Evidence;

/** Supplied by an independent trust policy, never populated from bundle contents. */
final readonly class TrustedKey
{
    public function __construct(public string $keyId, public string $publicKey, public string $mode)
    {
        Schema::value($keyId, 'opaque');
        Schema::oneOf($mode, Schema::MODES);
        if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new EvidenceException('Pinned public key must be 32 raw Ed25519 bytes.');
        }
    }
}
