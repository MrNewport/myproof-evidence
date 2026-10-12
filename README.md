# MyProof evidence v2

Portable PHP 8.3+ package for bounded JSON canonicalization, immutable event bytes,
SHA-256 chain verification and ordinary Ed25519 manifest/collection verification. MIT licensed.
No Laravel runtime, database, cloud client or signing credentials are required.
Release versions are identified by repository tags. This protocol has not had an
independent external audit.

From this standalone package checkout:

```sh
composer install
composer test
bin/myproof-verify \
  --bundle=spec/evidence/fixtures/test-bundle \
  --public-key=spec/evidence/fixtures/test-only-public-key.hex \
  --key-id=test-vector-2026 --mode=test
```

The supplied fixture key is publicly reproducible **TEST MATERIAL**. The example
explicitly selects it for that test. It authenticates no real seller or live
evidence. Supply a key obtained through an independent, approved trust channel
for actual verification; the CLI requires its pin file outside the bundle.
An export's own public key cannot establish trust in that export.

The application can install this directory through a Composer path repository
and require `myproof/evidence`. PSR-4 namespace: `MyProof\Evidence\`.

```php
use MyProof\Evidence\Event;

// Application assigns source/type after authorization and delivery-head locking.
$event = Event::fromArray([
    'schema' => 'myproof.evidence.v2',
    'event_id' => $eventId,
    'workspace_id' => $workspaceId,
    'delivery_id' => $deliveryId,
    'sequence' => $lockedSequence + 1,
    'previous_hash' => $lockedHash, // null for sequence 1
    'occurred_at' => $occurredAt, // 2026-10-12T12:00:00.000000Z
    'recorded_at' => $recordedAt,
    'source' => 'app',
    'source_event_id' => $sourceEventId,
    'type' => 'portal_requested',
    'mode' => 'demo',
    'payload' => [], // Event::fromArray explicitly converts payload to an object.
    'private_context_ref' => null,
]);
// Persist these exact bytes/hash, head update, dedupe and outbox atomically.
$event->canonicalBytes;
$event->sha256;
```

`Event::fromCanonical($bytes)` validates stored bytes without replacing them.
`Event::data()` returns a fresh object. `ChainVerifier::verify($eventBytes,
$workspaceId, $deliveryId, $mode)` returns an immutable `ChainHead`. The iterable
must contain the complete chain from sequence 1 in commit order. Occurrence times
may go backwards when a delayed event arrives.

`CanonicalJson::encode()` accepts JSON primitives, safe integers, list arrays and
`stdClass` objects. Use objects deliberately: `{}` and `[]` are different.
`decode()` validates raw JSON before constructing objects; `requireCanonical()`
also requires byte-for-byte canonical form. `Schema::EVENTS` publishes the closed
source/type/payload map. See the [v2 profile](spec/evidence/README.md).

Payment payloads include `currency_exponent` (integer 0–9), preserving minor-unit
meaning without assuming cents. Preview reports accept only `png`, `jpeg`, `text`;
the application enforces safe preview bounds and offers PDF/ZIP as attachments.

CloudFront payloads preserve method, exact-version commitment, source/request IDs,
header-inclusive byte semantics, nullable response range/length fields and initial,
final and detailed result classes. Use `SourceEventId::cloudFront($distributionId,
$requestId, $logSourceId)` for their required dedupe ID. The stable logical source ID
must survive retries and new log batches. Set `occurred_at` to the provider timestamp,
not ingestion time. See the complete payload and commitment contract in the profile.
No combination of these fields is treated as proof of receipt.

```php
use MyProof\Evidence\{BundleVerifier, TrustedKey, SigningInput};

// $publicKey is 32 raw Ed25519 bytes from independently configured trust policy.
$key = new TrustedKey($approvedKeyId, $publicKey, 'live');
$result = (new BundleVerifier())->verify(
    $canonicalManifest,
    $raw64ByteSignature,
    $key,
    $canonicalEventBytes,
    fn (string $name, int $expectedSize): string => $storage->readBounded($name, $expectedSize),
);
$message = SigningInput::forManifest($canonicalManifest);
```

The read callback must enforce storage ownership and bound bytes **before** reading.
Artifact names are flat allowlisted filenames, never URLs or paths. Verification
checks each declared size/hash, canonical snapshot bytes and snapshot ownership/mode.
It does not render HTML/PDF or extract archives. The application owns snapshot field
redaction, report wording and the meaning of factual claims.

`SigningInput` is exactly UTF-8 `MyProof evidence v2\n` followed by the **raw**
32-byte SHA-256 of canonical manifest bytes. Use ordinary Ed25519, not Ed25519ph,
not a hexadecimal digest, and not a second prehash operation. `DemoSigner` only
accepts `demo`/`test`; it intentionally provides no production signing adapter.

CLI bundle layout: canonical `manifest.json` with no trailing newline,
`signature.ed25519` containing 64 raw bytes, `events.ndjson` containing one original
canonical event plus LF per line, and declared artifacts including `snapshot.json`.
Exit 0 means all implemented integrity checks passed; nonzero means failure.
Symlink artifacts, unbounded files and trust pins inside the bundle are rejected.

Integrity and a pinned signing key do not establish observation truth, file reading,
independent time, cardholder identity or dispute outcome. Revocation, rotation,
historical key policy and external time commitments belong to the trust policy.
No AWS KMS/staging acceptance has been run by this package.

Larger histories use the separate [collection v1 contract](spec/evidence/collections.md).
`CollectionVerifier::verify($canonicalIndex, $signature, $pinnedKey, $readPart, $readRootArtifact)`
reads one bounded numbered ZIP at a time through caller-provided bounded callbacks,
checks every original v2 event and all cross-part identities/ranges, and returns the
complete head only after every part and root artifact passes. Collection verification
requires `ext-zip`; it reads flat allowlisted entries into bounded memory and never
extracts arbitrary paths. `CollectionSigningInput::forIndex()` uses its new domain;
`SigningInput::forManifest()` and all original v2 bytes remain unchanged.

Use `--collection=DIR` instead of `--bundle=DIR`, keeping the extracted root index
and artifacts beside all numbered `segment-NNNN.zip` files. Missing, duplicate,
reordered or extra files fail. The independently pinned key must remain outside
that directory. The collection index and per-part structural schemas are provided
alongside the v2 schemas; structural validation alone does not verify integrity.
