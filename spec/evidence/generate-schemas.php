<?php
declare(strict_types=1);

// Schemas document structural validation; the byte profile additionally rejects
// duplicate keys, floating/exponent tokens, invalid UTF-8 and noncanonical bytes.
$root = dirname(__DIR__, 2);
$autoload = is_file($root.'/composer.json')
    && json_decode(file_get_contents($root.'/composer.json'), true)['name'] === 'myproof/evidence'
        ? $root.'/vendor/autoload.php'
        : $root.'/packages/evidence/vendor/autoload.php';
require $autoload;

use MyProof\Evidence\{CanonicalJson, CollectionSchema, Schema};

$definitions = [
    'ulid' => ['type' => 'string', 'minLength' => 26, 'maxLength' => 26, 'pattern' => '^[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25}$'],
    'hash' => ['type' => 'string', 'pattern' => '^[0-9a-f]{64}$'],
    'opaque' => ['type' => 'string', 'pattern' => '^[A-Za-z0-9._:-]{1,128}$'],
    'timestamp' => ['type' => 'string', 'format' => 'date-time', 'pattern' => '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}Z$'],
    'uint' => ['type' => 'integer', 'minimum' => 0, 'maximum' => CanonicalJson::MAX_INTEGER],
    'currency' => ['type' => 'string', 'pattern' => '^[A-Z]{3}$'],
    'currency_exponent' => ['type' => 'integer', 'minimum' => 0, 'maximum' => 9],
    'edge_request_id' => ['type' => 'string', 'pattern' => '^[A-Za-z0-9_+=/-]{1,128}$'],
    'nullable_uint' => ['type' => ['integer', 'null'], 'minimum' => 0, 'maximum' => CanonicalJson::MAX_INTEGER],
    'http_status' => ['type' => 'integer', 'minimum' => 100, 'maximum' => 599],
    'edge_status' => ['oneOf' => [['const' => 0], ['type' => 'integer', 'minimum' => 100, 'maximum' => 599]]],
    'bool' => ['type' => 'boolean'],
];
$reference = static fn (string $name): array => ['$ref' => '#/$defs/'.$name];
$object = static fn (array $properties): array => ['type' => 'object', 'additionalProperties' => false, 'required' => array_keys($properties), 'properties' => (object) $properties];
$base = ['$schema' => 'https://json-schema.org/draft/2020-12/schema', '$defs' => $definitions];
$event = $base + $object([
    'schema' => ['const' => Schema::VERSION], 'event_id' => $reference('ulid'), 'workspace_id' => $reference('ulid'), 'delivery_id' => $reference('ulid'),
    'sequence' => ['type' => 'integer', 'minimum' => 1, 'maximum' => CanonicalJson::MAX_INTEGER],
    'previous_hash' => ['oneOf' => [['type' => 'null'], $reference('hash')]], 'occurred_at' => $reference('timestamp'), 'recorded_at' => $reference('timestamp'),
    'source' => ['enum' => Schema::SOURCES], 'source_event_id' => $reference('opaque'), 'type' => ['enum' => array_keys(Schema::EVENTS)],
    'mode' => ['enum' => Schema::MODES], 'payload' => ['type' => 'object'], 'private_context_ref' => ['oneOf' => [['type' => 'null'], $reference('ulid')]],
]);
$event['title'] = 'MyProof evidence v2 event';
$event['oneOf'] = [];
foreach (Schema::EVENTS as $type => [$sources, $payload]) {
    $properties = [];
    foreach ($payload as $name => $constraint) {
        $properties[$name] = is_array($constraint) ? ['enum' => $constraint] : $reference($constraint);
    }
    $payloadSchema = $object($properties);
    $variant = ['properties' => ['type' => ['const' => $type], 'source' => ['enum' => $sources], 'payload' => $payloadSchema]];
    if ($type === 'edge_response_observed') {
        $variant['properties']['source_event_id'] = ['type' => 'string', 'pattern' => '^cf:[0-9a-f]{64}$'];
        $variant['properties']['payload']['allOf'] = [[
            'if' => ['properties' => ['response_range_start' => ['type' => 'null']]],
            'then' => ['properties' => ['response_range_end' => ['type' => 'null']]],
            'else' => ['properties' => ['response_range_end' => ['type' => 'integer']]],
        ]];
    }
    $event['oneOf'][] = $variant;
}
$event['allOf'] = [['if' => ['properties' => ['sequence' => ['const' => 1]]], 'then' => ['properties' => ['previous_hash' => ['type' => 'null']]], 'else' => ['properties' => ['previous_hash' => $reference('hash')]]]];
$manifest = $base + $object([
    'schema' => ['const' => Schema::VERSION], 'workspace_id' => $reference('ulid'), 'delivery_id' => $reference('ulid'), 'mode' => ['enum' => Schema::MODES],
    'generated_at' => $reference('timestamp'), 'key_id' => $reference('opaque'), 'signature_algorithm' => ['const' => 'Ed25519'], 'privacy_mode' => ['enum' => ['masked', 'full_private']],
    'snapshot_sha256' => $reference('hash'), 'chain_head' => $object(['sequence' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 10000], 'sha256' => $reference('hash')]),
    'artifacts' => ['type' => 'array', 'minItems' => 1, 'maxItems' => 16, 'items' => $object([
        'name' => ['type' => 'string', 'pattern' => '^[a-z0-9][a-z0-9_-]{0,63}\\.(json|html|pdf|txt)$'], 'sha256' => $reference('hash'), 'size' => ['type' => 'integer', 'minimum' => 0, 'maximum' => 16777216],
    ]), 'contains' => ['properties' => ['name' => ['const' => 'snapshot.json']]], 'minContains' => 1, 'maxContains' => 1],
    'coverage' => ['type' => 'array', 'minItems' => 1, 'maxItems' => 6, 'items' => $object([
        'source' => ['enum' => Schema::SOURCES], 'status' => ['enum' => ['observed', 'pending', 'unavailable']], 'limitation' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 512],
    ])],
]);
$manifest['title'] = 'MyProof evidence v2 manifest';
$positive = static fn (int $max): array => ['type' => 'integer', 'minimum' => 1, 'maximum' => $max];
$identity = ['export_id' => $reference('ulid'), 'workspace_id' => $reference('ulid'), 'delivery_id' => $reference('ulid'), 'mode' => ['enum' => Schema::MODES], 'privacy_mode' => ['enum' => ['masked', 'full_private']]];
$head = $object(['sequence' => $positive(CollectionSchema::MAX_EVENTS), 'sha256' => $reference('hash')]);
$artifacts = ['type' => 'array', 'minItems' => 1, 'maxItems' => 16, 'items' => $object([
    'name' => ['type' => 'string', 'pattern' => '^[a-z0-9][a-z0-9_-]{0,63}\\.(json|html|pdf|txt)$', 'not' => ['enum' => ['segment.json', 'collection.json']]],
    'sha256' => $reference('hash'), 'size' => ['type' => 'integer', 'minimum' => 0, 'maximum' => CollectionSchema::MAX_ARTIFACT_BYTES],
])];
$stream = ['events_sha256' => $reference('hash'), 'events_bytes' => $positive(CollectionSchema::MAX_SEGMENT_BYTES), 'event_count' => $positive(CollectionSchema::MAX_SEGMENT_EVENTS)];
$segment = $base + $object(['schema' => ['const' => CollectionSchema::SEGMENT_VERSION]] + $identity + [
    'index' => $positive(CollectionSchema::MAX_SEGMENTS), 'chain_start' => $object(['sequence' => $positive(CollectionSchema::MAX_EVENTS), 'previous_sha256' => ['oneOf' => [['type' => 'null'], $reference('hash')]]]), 'chain_head' => $head,
] + $stream + ['artifacts' => $artifacts]);
$segment['title'] = 'MyProof evidence segment v1';
$segment['allOf'] = [['if' => ['properties' => ['chain_start' => ['properties' => ['sequence' => ['const' => 1]]]]], 'then' => ['properties' => ['chain_start' => ['properties' => ['previous_sha256' => ['type' => 'null']]]]], 'else' => ['properties' => ['chain_start' => ['properties' => ['previous_sha256' => $reference('hash')]]]]]];
$collection = $base + $object(['schema' => ['const' => CollectionSchema::VERSION]] + $identity + [
    'created_at' => $reference('timestamp'), 'key_id' => $reference('opaque'), 'signature_algorithm' => ['const' => 'Ed25519'], 'full_head' => $head,
    'event_count' => $positive(CollectionSchema::MAX_EVENTS), 'snapshot_sha256' => $reference('hash'),
    'segments' => ['type' => 'array', 'minItems' => 1, 'maxItems' => CollectionSchema::MAX_SEGMENTS, 'items' => $object([
        'index' => $positive(CollectionSchema::MAX_SEGMENTS), 'path' => ['type' => 'string', 'pattern' => '^segment-(000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|10[01][0-9]|102[0-4])\\.zip$'],
        'segment_sha256' => $reference('hash'), 'archive_sha256' => $reference('hash'), 'archive_size' => $positive(CollectionSchema::MAX_ARCHIVE_BYTES),
    ] + $stream + ['first_sequence' => $positive(CollectionSchema::MAX_EVENTS), 'last_sequence' => $positive(CollectionSchema::MAX_EVENTS), 'previous_sha256' => ['oneOf' => [['type' => 'null'], $reference('hash')]], 'last_sha256' => $reference('hash')])],
    'artifacts' => $artifacts + ['contains' => ['properties' => ['name' => ['const' => 'snapshot.json']]], 'minContains' => 1, 'maxContains' => 1],
    'coverage' => ['type' => 'array', 'minItems' => count(Schema::SOURCES), 'maxItems' => count(Schema::SOURCES), 'items' => $object([
        'source' => ['enum' => Schema::SOURCES], 'status' => ['enum' => ['observed', 'pending', 'unavailable']], 'limitation' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 512],
    ])],
]);
$collection['title'] = 'MyProof complete evidence collection v1';
foreach (['segment' => &$segment, 'collection' => &$collection] as &$schema) {
    $schema['$comment'] = 'Structural schema only. Strict canonical byte/token profile, UTF-8 byte bounds, summed artifact bounds, unique names/sources, range arithmetic, ordered descriptors, path/index equality, original v2 chain checks, digest and signature verification are mandatory protocol checks.';
}
unset($schema);
foreach (['event' => $event, 'manifest' => $manifest, 'segment' => $segment, 'collection' => $collection] as $name => $schema) {
    file_put_contents(__DIR__.'/'.$name.'.schema.json', json_encode($schema, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
}
fwrite(STDOUT, "Generated structural schemas; protocol byte and cross-document checks remain mandatory.\n");
