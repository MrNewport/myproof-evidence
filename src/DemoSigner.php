<?php
declare(strict_types=1);

namespace MyProof\Evidence;

/** Local demonstration/test only. Production must use a separately authorized signing adapter. */
final class DemoSigner
{
    public function sign(string $canonicalManifest, string $secretKey): string
    {
        $manifest = Schema::manifest((new CanonicalJson())->requireCanonical($canonicalManifest, 262144));
        Schema::oneOf($manifest->mode, ['demo', 'test']);
        if (strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new EvidenceException('Demo signing requires a raw sodium secret key.');
        }
        return sodium_crypto_sign_detached(SigningInput::forManifest($canonicalManifest), $secretKey);
    }
}
