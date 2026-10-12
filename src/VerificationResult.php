<?php
declare(strict_types=1);

namespace MyProof\Evidence;

final readonly class VerificationResult
{
    public function __construct(public string $mode, public string $keyId, public ChainHead $head, public int $artifactCount) {}
}
