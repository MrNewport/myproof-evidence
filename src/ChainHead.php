<?php
declare(strict_types=1);

namespace MyProof\Evidence;

final readonly class ChainHead
{
    public function __construct(public int $sequence, public ?string $sha256) {}
}
