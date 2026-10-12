<?php
declare(strict_types=1);

require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/FixturePaths.php';

use MyProof\Evidence\{BundleVerifier, CanonicalJson, ChainVerifier, DemoSigner, Event, EvidenceException, Schema, SigningInput, SourceEventId, TrustedKey};

$checks = 0;
function same(mixed $expected, mixed $actual, string $label): void
{
    global $checks;
    ++$checks;
    if ($expected !== $actual) {
        throw new RuntimeException('FAIL: '.$label);
    }
}
function rejected(callable $operation, string $label): void
{
    global $checks;
    ++$checks;
    try {
        $operation();
    } catch (EvidenceException) {
        return;
    }
    throw new RuntimeException('FAIL: accepted '.$label);
}

$json = new CanonicalJson();
$fixtures = evidenceFixtures();
$bundle = $fixtures.'/test-bundle';
$vectors = json_decode(file_get_contents($fixtures.'/canonical-vectors.json'), true, flags: JSON_THROW_ON_ERROR);
foreach ($vectors as $vector) {
    same($vector['canonical'], $json->canonicalize($vector['input']), $vector['name']);
    same($vector['sha256'], hash('sha256', $json->canonicalize($vector['input'])), $vector['name'].' hash');
}
$oldEncoding = mb_internal_encoding();
mb_internal_encoding('ISO-8859-1');
same($vectors[0]['canonical'], $json->canonicalize($vectors[0]['input']), 'UTF-16 sorting ignores process source encoding');
same('ISO-8859-1', mb_internal_encoding(), 'restore process encoding');
mb_internal_encoding($oldEncoding);
foreach ([
    'duplicate' => '{"a":1,"a":2}', 'escaped duplicate' => '{"a":1,"\\u0061":2}',
    'nested duplicate' => '{"a":{"x":1,"x":2}}', 'duplicate numeric key' => '{"0":1,"0":2}',
    'float' => '1.5', 'integral float' => '1.0', 'exponent' => '1e0', 'negative zero' => '-0',
    'unsafe positive' => '9007199254740992', 'unsafe negative' => '-9007199254740992',
    'huge integer' => '18446744073709551616', 'leading zero' => '01', 'NaN' => 'NaN',
    'bad UTF8' => "\"\xc3\x28\"", 'lone surrogate' => '"\\ud800"', 'reversed surrogate' => '"\\udc00\\ud800"',
    'control in string' => "\"hello\nworld\"", 'leading BOM' => "\xef\xbb\xbf{}", 'trailing input' => '{}true',
    'trailing comma' => '[1,]', 'missing comma' => '[1 2]', 'missing colon' => '{"x"1}',
    'invalid escape' => '"\\x"', 'unclosed string' => '"oops', 'nul leading property' => '{"\\u0000x":1}',
    'too deep' => str_repeat('[', 33).'0'.str_repeat(']', 33),
    'too many nodes' => '['.str_repeat('0,', 20000).'0]', 'too many bytes' => '"'.str_repeat('x', CanonicalJson::MAX_BYTES).'"',
] as $label => $input) {
    rejected(fn () => $json->canonicalize($input), $label);
}
same(str_repeat('[', 32).'0'.str_repeat(']', 32), $json->canonicalize(str_repeat('[', 32).'0'.str_repeat(']', 32)), 'maximum depth');
rejected(fn () => $json->encode(1.0), 'PHP float');
rejected(fn () => $json->encode(['name' => 'value']), 'ambiguous PHP associative array');
rejected(fn () => $json->encode(new DateTimeImmutable()), 'custom PHP object');
rejected(fn () => $json->requireCanonical('{ "a":1}'), 'noncanonical stored bytes');
same('{"0":"zero","10":"ten","2":"two"}', $json->canonicalize('{"2":"two","10":"ten","0":"zero"}'), 'numeric object keys remain lexicographic');
$cycle = new stdClass();
$cycle->self = $cycle;
rejected(fn () => $json->encode($cycle), 'cyclic PHP object');
$wideObject = new stdClass();
for ($i = 0; $i < 10000; ++$i) $wideObject->{'k'.$i} = 0;
rejected(fn () => $json->decode(json_encode($wideObject, JSON_THROW_ON_ERROR)), 'object keys count toward parser node budget');

$manifest = file_get_contents($bundle.'/manifest.json');
$signature = file_get_contents($bundle.'/signature.ed25519');
$events = explode("\n", rtrim(file_get_contents($bundle.'/events.ndjson'), "\n"));
$expected = json_decode(file_get_contents($fixtures.'/expected.json'), true, flags: JSON_THROW_ON_ERROR);
$publicKey = hex2bin(trim(file_get_contents($fixtures.'/test-only-public-key.hex')));
$key = new TrustedKey('test-vector-2026', $publicKey, 'test');
$read = static fn (string $name): string => file_get_contents($bundle.'/'.$name);
$verifier = new BundleVerifier();
$valid = $verifier->verify($manifest, $signature, $key, $events, $read);
same($expected['sequence'], $valid->head->sequence, 'independent signed bundle');
same($expected['head_sha256'], $valid->head->sha256, 'independent head');
same($expected['signing_input_hex'], bin2hex(SigningInput::forManifest($manifest)), 'exact domain and raw SHA-256');
same($expected['manifest_sha256'], hash('sha256', $manifest), 'independent manifest hash');
foreach ($events as $index => $bytes) {
    $event = Event::fromCanonical($bytes);
    same($expected['event_hashes'][$index], $event->sha256, 'independent event hash '.$index);
    same($bytes, Event::fromArray((array) $event->data())->canonicalBytes, 'array integration roundtrip '.$index);
}
$event = Event::fromCanonical($events[0]);
$data = $event->data();
$data->mode = 'live';
same('test', $event->data()->mode, 'event data cannot mutate canonical bytes');
$mutateEvent = static function (int $index, callable $change) use ($events, $json): array {
    $copy = $events;
    $data = $json->decode($copy[$index]);
    $change($data);
    $copy[$index] = $json->encode($data);
    return $copy;
};
foreach ([
    'wrong source' => fn ($e) => $e->source = 'client',
    'wrong mode' => fn ($e) => $e->mode = 'live',
    'unknown event' => fn ($e) => $e->type = 'receipt_proven',
    'unexpected PII payload' => fn ($e) => $e->payload->email = 'example@example.com',
    'invalid date' => fn ($e) => $e->recorded_at = '2026-02-31T00:00:00.000000Z',
    'v1 schema' => fn ($e) => $e->schema = 'myproof.evidence.v1',
    'invalid workspace' => fn ($e) => $e->workspace_id = 'arbitrary',
    'untrusted source event text' => fn ($e) => $e->source_event_id = 'someone@example.com',
] as $label => $change) {
    rejected(fn () => $verifier->verify($manifest, $signature, $key, $mutateEvent(0, $change), $read), $label);
}
foreach ([
    'wrong sequence' => fn ($e) => $e->sequence = 3,
    'wrong previous hash' => fn ($e) => $e->previous_hash = str_repeat('a', 64),
    'duplicate event ID' => fn ($e) => $e->event_id = $event->data()->event_id,
    'cross-delivery event' => fn ($e) => $e->delivery_id = '01K6R000000000000000000009',
] as $label => $change) {
    rejected(fn () => $verifier->verify($manifest, $signature, $key, $mutateEvent(1, $change), $read), $label);
}
rejected(fn () => $verifier->verify($manifest, $signature, $key, array_reverse($events), $read), 'reordered events');
rejected(fn () => $verifier->verify($manifest, $signature, $key, array_slice($events, 0, 3), $read), 'truncated chain');
rejected(fn () => $verifier->verify($manifest, $signature, $key, [], $read), 'empty export chain');
rejected(fn () => $verifier->verify($manifest, $signature, new TrustedKey('test-vector-2026', str_repeat("\0", 32), 'test'), $events, $read), 'wrong pinned public key');
rejected(fn () => $verifier->verify($manifest, $signature, new TrustedKey('different', $publicKey, 'test'), $events, $read), 'wrong pinned key ID');
rejected(fn () => $verifier->verify($manifest, $signature, new TrustedKey('test-vector-2026', $publicKey, 'live'), $events, $read), 'test key used in live mode');
rejected(fn () => $verifier->verify($manifest, str_repeat("\0", 64), $key, $events, $read), 'tampered signature');
rejected(fn () => $verifier->verify($manifest, substr($signature, 1), $key, $events, $read), 'truncated signature');
rejected(fn () => $verifier->verify(str_replace('masked', 'full_private', $manifest), $signature, $key, $events, $read), 'tampered manifest');
foreach (['snapshot.json', 'report.html'] as $tamper) {
    rejected(fn () => $verifier->verify($manifest, $signature, $key, $events, static fn (string $name): string => $name === $tamper ? $read($name).'x' : $read($name)), 'tampered '.$tamper);
}
$pair = sodium_crypto_sign_seed_keypair(hex2bin($expected['test_seed_hex']));
$secret = sodium_crypto_sign_secretkey($pair);
same($signature, (new DemoSigner())->sign($manifest, $secret), 'PHP sodium agrees with Node ordinary Ed25519');
same($publicKey, sodium_crypto_sign_publickey($pair), 'independent raw key representation');
rejected(fn () => (new DemoSigner())->sign(str_replace('"test"', '"live"', $manifest), $secret), 'local signer refuses live');
$manifestData = $json->decode($manifest);
$manifestData->included_public_key = bin2hex($publicKey);
rejected(fn () => SigningInput::forManifest($json->encode($manifestData)), 'included key is not a trust anchor');
$manifestData = $json->decode($manifest);
$manifestData->artifacts[1]->name = '../report.html';
rejected(fn () => SigningInput::forManifest($json->encode($manifestData)), 'artifact traversal');
$manifestData->artifacts[1]->name = 'snapshot.json';
rejected(fn () => SigningInput::forManifest($json->encode($manifestData)), 'duplicate artifact name');

// A signer cannot make a snapshot from a different delivery pass binding checks.
$manifestData = $json->decode($manifest);
$snapshot = $json->decode($read('snapshot.json'));
$snapshot->delivery_id = '01K6R000000000000000000009';
$snapshotBytes = $json->encode($snapshot);
$manifestData->snapshot_sha256 = hash('sha256', $snapshotBytes);
$manifestData->artifacts[0]->sha256 = $manifestData->snapshot_sha256;
$manifestData->artifacts[0]->size = strlen($snapshotBytes);
$changedManifest = $json->encode($manifestData);
$changedSignature = (new DemoSigner())->sign($changedManifest, $secret);
rejected(fn () => $verifier->verify($changedManifest, $changedSignature, $key, $events, static fn ($name) => $name === 'snapshot.json' ? $snapshotBytes : $read($name)), 'validly signed cross-delivery snapshot');

// Provider retry dedupe is a full-chain property, even with recomputed hashes.
$duplicate = $json->decode($events[2]);
$duplicate->sequence = 4;
$duplicate->event_id = '01K6R000000000000000000019';
$duplicate->previous_hash = hash('sha256', $events[2]);
$duplicateEvents = [...array_slice($events, 0, 3), $json->encode($duplicate)];
$owner = $event->data();
rejected(fn () => (new ChainVerifier())->verify($duplicateEvents, $owner->workspace_id, $owner->delivery_id, 'test'), 'duplicate source retry');
same(0, (new ChainVerifier())->verify([], $owner->workspace_id, $owner->delivery_id, 'test')->sequence, 'empty local chain head');

// Laravel stores lowercase ULIDs; validation must never rewrite signed identity.
$lowerFields = (array) $owner;
foreach (['event_id', 'workspace_id', 'delivery_id'] as $field) {
    $lowerFields[$field] = strtolower($lowerFields[$field]);
}
$lowerFields['payload'] = (object) [
    'snapshot_sha256' => $owner->payload->snapshot_sha256,
    'asset_version_id' => strtolower($owner->payload->asset_version_id),
    'order_id' => strtolower($owner->payload->order_id),
];
$lowerFields['private_context_ref'] = strtolower($owner->event_id);
$lowerEvent = Event::fromArray($lowerFields);
foreach (['event_id', 'workspace_id', 'delivery_id', 'private_context_ref'] as $field) {
    same($lowerFields[$field], $lowerEvent->data()->{$field}, 'preserve lowercase '.$field);
}
same($lowerFields['payload']->asset_version_id, $lowerEvent->data()->payload->asset_version_id, 'preserve lowercase payload asset identity');
$caseVariant = (array) $lowerEvent->data();
$caseVariant['event_id'] = strtoupper($caseVariant['event_id']);
$caseVariantEvent = Event::fromArray($caseVariant);
same(false, $lowerEvent->canonicalBytes === $caseVariantEvent->canonicalBytes, 'only identity casing changes canonical bytes');
same(false, $lowerEvent->sha256 === $caseVariantEvent->sha256, 'only identity casing changes hash');
same(1, (new ChainVerifier())->verify([$lowerEvent->canonicalBytes], $lowerFields['workspace_id'], $lowerFields['delivery_id'], 'test')->sequence, 'lowercase identities verify exactly');
rejected(fn () => (new ChainVerifier())->verify([$lowerEvent->canonicalBytes], strtoupper($lowerFields['workspace_id']), $lowerFields['delivery_id'], 'test'), 'workspace identity case substitution');
rejected(fn () => (new ChainVerifier())->verify([$lowerEvent->canonicalBytes], $lowerFields['workspace_id'], strtoupper($lowerFields['delivery_id']), 'test'), 'delivery identity case substitution');
foreach (['00000000000000000000000000', '7ZZZZZZZZZZZZZZZZZZZZZZZZZ', '7zzzzzzzzzzzzzzzzzzzzzzzzz', '01k6R000000000000000000001'] as $validId) {
    Schema::value($validId, 'ulid');
    same($validId, $json->decode($json->encode($validId)), 'valid ULID spelling is stable');
}
foreach (['', '01k6r00000000000000000000', '01k6r0000000000000000000000', '8zzzzzzzzzzzzzzzzzzzzzzzzz',
    '01i6r000000000000000000001', '01l6r000000000000000000001', '01o6r000000000000000000001', '01u6r000000000000000000001',
    '01I6R000000000000000000001', '01L6R000000000000000000001', '01O6R000000000000000000001', '01U6R000000000000000000001',
    "01k6r000000000000000000001\n", '０1k6r000000000000000000001', null, 123,
] as $invalidId) {
    rejected(fn () => Schema::value($invalidId, 'ulid'), 'malformed ULID '.var_export($invalidId, true));
}

// CDN observations retain partial and final-result semantics, never receipt claims.
$partial = Event::fromCanonical($events[6])->data();
$disconnect = Event::fromCanonical($events[7])->data();
$capturedSnapshot = $json->decode($read('snapshot.json'));
same(hash('sha256', $json->encode($capturedSnapshot->object_identity)), $partial->payload->object_identity_sha256, 'exact bucket/key/version commitment agrees with independent snapshot');
same($capturedSnapshot->asset_version_id, $partial->payload->asset_version_id, 'exact asset revision retained');
same(206, $partial->payload->status_code, 'partial response is preserved');
same([0, 9], [$partial->payload->response_range_start, $partial->payload->response_range_end], 'inclusive partial range is preserved');
same('response_including_headers', $partial->payload->bytes_semantics, 'header-inclusive byte semantics are explicit');
same(true, $partial->payload->bytes_sent > $partial->payload->response_content_length, 'logged bytes can exceed the response body length');
same([200, 'Hit', 'Error', 'ClientCommError'], [$disconnect->payload->status_code, $disconnect->payload->response_result_type, $disconnect->payload->final_result_type, $disconnect->payload->detailed_result_type], '200 response followed by disconnect remains adverse');
same($partial->source_event_id, SourceEventId::cloudFront($partial->payload->distribution_id, $partial->payload->request_id, $partial->payload->log_source_id), 'Node/PHP source dedupe identity agrees');
same(false, $partial->source_event_id === SourceEventId::cloudFront('other-distribution', $partial->payload->request_id, $partial->payload->log_source_id), 'dedupe includes distribution');
same(false, $partial->source_event_id === SourceEventId::cloudFront($partial->payload->distribution_id, 'other-request', $partial->payload->log_source_id), 'dedupe includes request');
same(false, $partial->source_event_id === SourceEventId::cloudFront($partial->payload->distribution_id, $partial->payload->request_id, 'other-log-source'), 'dedupe includes logical source');
$sourceTime = '2026-10-12T12:01:00.000000Z';
same($sourceTime, $partial->occurred_at, 'source occurrence time retained separately');
same('2026-10-12T12:03:00.000000Z', $partial->recorded_at, 'late ingestion time retained');
foreach ([
    'half-null range' => fn ($e) => $e->payload->response_range_start = null,
    'reversed range' => fn ($e) => $e->payload->response_range_start = 10,
    'negative range' => fn ($e) => $e->payload->response_range_start = -1,
    'float range' => fn ($e) => $e->payload->response_range_end = 9.0,
    'unsafe range' => fn ($e) => $e->payload->response_range_end = 9007199254740992,
    'body-only bytes claim' => fn ($e) => $e->payload->bytes_semantics = 'file_body',
    'invented receipt result' => fn ($e) => $e->payload->final_result_type = 'ReceiptConfirmed',
    'invented result detail' => fn ($e) => $e->payload->detailed_result_type = 'Downloaded',
    'raw signed query' => fn ($e) => $e->payload->signed_query = 'Signature=secret',
    'public network context' => fn ($e) => $e->payload->client_ip = '192.0.2.1',
    'raw object URL' => fn ($e) => $e->payload->object_identity_sha256 = 'https://example.com/file?Signature=secret',
    'arbitrary request payload' => fn ($e) => $e->payload->request_id = str_repeat('x', 129),
    'changed dedupe identity' => fn ($e) => $e->source_event_id = 'random-retry-id',
    'receipt assertion' => fn ($e) => $e->payload->receipt_completed = true,
] as $label => $change) {
    rejected(function () use ($json, $partial, $change): void {
        $copy = $json->decode($json->encode($partial));
        $change($copy);
        Event::fromArray((array) $copy);
    }, $label);
}
$headOnly = $json->decode($json->encode($disconnect));
$headOnly->payload->method = 'HEAD';
$headOnly->payload->response_content_length = 22;
same('HEAD', Event::fromArray((array) $headOnly)->data()->payload->method, 'HEAD observations cannot be converted to GET receipt');
$noResponse = $json->decode($json->encode($disconnect));
$noResponse->payload->status_code = 0;
$noResponse->payload->response_content_length = null;
$noResponse->payload->response_result_type = 'Unknown';
same(0, Event::fromArray((array) $noResponse)->data()->payload->status_code, 'CloudFront 000 becomes integer zero without inventing an HTTP response');
$unknownRange = $json->decode($json->encode($partial));
$unknownRange->payload->response_range_start = $unknownRange->payload->response_range_end = null;
same(null, Event::fromArray((array) $unknownRange)->data()->payload->response_range_start, 'missing range metadata remains unknown even for 206');

$jpy = Event::fromCanonical($events[4])->data();
$kwd = Event::fromCanonical($events[5])->data();
same(['JPY', 500, 0, 'merchant'], [$jpy->payload->currency, $jpy->payload->amount_minor, $jpy->payload->currency_exponent, $jpy->source], 'zero-exponent merchant amount is not cents');
same(['KWD', 1250, 3], [$kwd->payload->currency, $kwd->payload->amount_minor, $kwd->payload->currency_exponent], 'three-exponent amount preserves 1.250 without a float');
foreach ([-1, 10, 2.0, '2', null] as $exponent) {
    rejected(function () use ($json, $jpy, $exponent): void {
        $copy = $json->decode($json->encode($jpy));
        $copy->payload->currency_exponent = $exponent;
        Event::fromArray((array) $copy);
    }, 'invalid currency exponent '.var_export($exponent, true));
}
$preview = (array) $owner;
$preview['type'] = 'preview_reported';
$preview['source'] = 'client';
foreach (['png', 'jpeg', 'text', 'pdf', 'zip', 'image', 'svg', 'html'] as $previewType) {
    $preview['payload'] = ['attempt_id' => $owner->event_id, 'asset_version_id' => $owner->event_id, 'preview_type' => $previewType];
    if (in_array($previewType, ['png', 'jpeg', 'text'], true)) {
        same($previewType, Event::fromArray($preview)->data()->payload->preview_type, 'bounded '.$previewType.' preview type');
    } else {
        rejected(fn () => Event::fromArray($preview), 'unsupported '.$previewType.' preview');
    }
}

// Existing bundles remain unchanged; this additional vector was signed independently by Node.
$merchantLines = explode("\n", trim(file_get_contents($fixtures.'/merchant-test-bundle/events.ndjson')));
$merchant = Event::fromCanonical($merchantLines[count($merchantLines) - 1]);
same(trim(file_get_contents($fixtures.'/merchant-event.sha256')), $merchant->sha256, 'independent merchant event digest');
same('partially_refunded', $merchant->data()->payload->status, 'provider observation includes adverse state');
foreach (['merchant-source', 'wrong-account', 'excess-refund', 'wrong-time'] as $defect) {
    rejected(function () use ($merchant, $json, $defect): void {
        $data = $json->decode($merchant->canonicalBytes);
        match ($defect) {
            'merchant-source' => $data->source = 'merchant',
            'wrong-account' => $data->payload->account_id = 'pi_other',
            'excess-refund' => $data->payload->refunded_minor = 101,
            'wrong-time' => $data->payload->observed_at = $data->recorded_at,
        };
        Event::fromArray((array) $data);
    }, 'provider event rejects '.$defect);
}

// Every published event/type pair has a runnable schema-valid example.
foreach (Schema::EVENTS as $type => [$sources, $fields]) {
    foreach ($sources as $source) {
        $fieldsData = [];
        foreach ($fields as $name => $constraint) {
            $fieldsData[$name] = is_array($constraint) ? $constraint[0] : match ($constraint) {
                'ulid' => $owner->event_id, 'hash' => str_repeat('a', 64), 'timestamp' => $owner->recorded_at,
                'uint', 'currency_exponent' => 0, 'nullable_uint' => null,
                'opaque', 'edge_request_id' => 'fixture-identity',
                'currency' => 'USD', 'http_status', 'edge_status' => 200, 'bool' => true,
            };
        }
        $candidate = (array) $owner;
        $candidate['type'] = $type;
        $candidate['source'] = $source;
        $candidate['payload'] = $fieldsData;
        if ($type === 'edge_response_observed') {
            $candidate['source_event_id'] = SourceEventId::cloudFront($fieldsData['distribution_id'], $fieldsData['request_id'], $fieldsData['log_source_id']);
        }
        if ($type === 'payment_provider_observed') {
            $candidate['payload']['account_id'] = 'acct_fixture';
            $candidate['payload']['payment_intent_id'] = 'pi_fixture';
            $candidate['payload']['observed_at'] = $candidate['occurred_at'];
        }
        same($type, Event::fromArray($candidate)->data()->type, $type.' source '.$source);
    }
}
fwrite(STDOUT, 'PASS '.$checks." evidence checks; Node fixtures + PHP sodium, no live provider calls.\n");
