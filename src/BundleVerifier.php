<?php
declare(strict_types=1);

namespace MyProof\Evidence;

final class BundleVerifier
{
    public const MAX_ARTIFACT_BYTES = 16777216;
    public const MAX_TOTAL_ARTIFACT_BYTES = 33554432;

    /**
     * @param iterable<string> $canonicalEvents Original canonical event bytes.
     * @param callable(string, int): string $readArtifact Bounded local/authorized storage reader.
     */
    public function verify(string $canonicalManifest, string $rawSignature, TrustedKey $pinnedKey, iterable $canonicalEvents, callable $readArtifact): VerificationResult
    {
        $json = new CanonicalJson();
        $manifest = Schema::manifest($json->requireCanonical($canonicalManifest, 262144));
        if ($manifest->key_id !== $pinnedKey->keyId || $manifest->mode !== $pinnedKey->mode || strlen($rawSignature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new EvidenceException('Signature key identity, expected mode or signature length mismatch.');
        }
        if (!sodium_crypto_sign_verify_detached($rawSignature, SigningInput::forManifest($canonicalManifest), $pinnedKey->publicKey)) {
            throw new EvidenceException('Ed25519 signature verification failed.');
        }
        $head = (new ChainVerifier())->verify($canonicalEvents, $manifest->workspace_id, $manifest->delivery_id, $manifest->mode);
        if ($head->sequence !== $manifest->chain_head->sequence || $head->sha256 !== $manifest->chain_head->sha256) {
            throw new EvidenceException('Manifest chain cutoff mismatch.');
        }
        $total = 0;
        foreach ($manifest->artifacts as $artifact) {
            $total += $artifact->size;
            if ($total > self::MAX_TOTAL_ARTIFACT_BYTES) {
                throw new EvidenceException('Total artifact byte limit exceeded.');
            }
            $bytes = $readArtifact($artifact->name, $artifact->size);
            if (!is_string($bytes) || strlen($bytes) !== $artifact->size || !hash_equals($artifact->sha256, hash('sha256', $bytes))) {
                throw new EvidenceException('Artifact size or SHA-256 mismatch.');
            }
            if ($artifact->name === 'snapshot.json') {
                $snapshot = $json->requireCanonical($bytes);
                if (!$snapshot instanceof \stdClass || ($snapshot->workspace_id ?? null) !== $manifest->workspace_id || ($snapshot->delivery_id ?? null) !== $manifest->delivery_id || ($snapshot->mode ?? null) !== $manifest->mode) {
                    throw new EvidenceException('Snapshot ownership or mode mismatch.');
                }
            }
        }
        return new VerificationResult($manifest->mode, $manifest->key_id, $head, count($manifest->artifacts));
    }
}
