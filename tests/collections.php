<?php
declare(strict_types=1);

require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/FixturePaths.php';

use MyProof\Evidence\BoundedZip;
use MyProof\Evidence\CanonicalJson;
use MyProof\Evidence\CollectionSchema;
use MyProof\Evidence\CollectionSigningInput;
use MyProof\Evidence\CollectionVerifier;
use MyProof\Evidence\EvidenceException;
use MyProof\Evidence\TrustedKey;

$directory = evidenceFixtures().'/collection-test';
$indexBytes = file_get_contents($directory.'/collection.json');
$signature = file_get_contents($directory.'/signature.ed25519');
$key = new TrustedKey('collection-test-2026', hex2bin(trim(file_get_contents($directory.'-key.hex'))), 'test');
$read = static fn (string $name, int $size): string => file_get_contents($directory.'/'.$name);
$verifier = new CollectionVerifier();
$checks = 0;
$assert = static function (bool $truth) use (&$checks): void {
    $checks++;
    if (!$truth) { throw new RuntimeException('Collection check failed.'); }
};
$reject = static function (callable $call) use ($assert): void {
    try { $call(); } catch (EvidenceException) { $assert(true); return; }
    throw new RuntimeException('Invalid collection accepted.');
};
$assert($verifier->verify($indexBytes, $signature, $key, $read, $read)->head->sequence === 8);
$assert(CollectionSigningInput::forIndex($indexBytes) === "MyProof evidence collection v1\n".hash('sha256', $indexBytes, true));
$secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(str_repeat('C', 32)));
$sign = static fn (string $bytes): string => sodium_crypto_sign_detached("MyProof evidence collection v1\n".hash('sha256', $bytes, true), $secret);
$mutate = static function (callable $change) use ($indexBytes, $sign, $verifier, $key, $read): void {
    $data = json_decode($indexBytes);
    $change($data);
    $bytes = (new CanonicalJson())->encode($data);
    $verifier->verify($bytes, $sign($bytes), $key, $read, $read);
};
$reject(fn () => $verifier->verify($indexBytes, $signature, new TrustedKey($key->keyId, str_repeat('x', 32), 'test'), $read, $read));
$reject(fn () => $verifier->verify($indexBytes, $signature, new TrustedKey($key->keyId, $key->publicKey, 'live'), $read, $read));
$reject(fn () => $verifier->verify($indexBytes, sodium_crypto_sign_detached("MyProof evidence v2\n".hash('sha256', $indexBytes, true), $secret), $key, $read, $read));
$reject(fn () => $mutate(function ($d) { $d->segments = array_reverse($d->segments); }));
$reject(fn () => $mutate(function ($d) { $d->segments[1] = $d->segments[0]; }));
$reject(fn () => $mutate(function ($d) { array_pop($d->segments); }));
$reject(fn () => $mutate(function ($d) { $d->segments[1]->previous_sha256 = str_repeat('a', 64); }));
$reject(fn () => $mutate(function ($d) { $d->segments[1]->path = '../segment-0002.zip'; }));
$reject(fn () => $mutate(function ($d) { $d->segments[1]->first_sequence++; }));
$reject(fn () => $mutate(function ($d) { $d->full_head->sha256 = str_repeat('a', 64); }));
$reject(fn () => $mutate(function ($d) { $d->event_count--; }));
$reject(fn () => $mutate(function ($d) { $d->mode = 'live'; }));
$reject(fn () => $mutate(function ($d) { $d->segments[0]->archive_size = CollectionSchema::MAX_ARCHIVE_BYTES + 1; }));
$reject(fn () => $verifier->verify($indexBytes, $signature, $key, static fn ($name,$size): string => 'corrupt', $read));
$reject(fn () => $verifier->verify($indexBytes, $signature, $key, $read, static fn ($name,$size): string => 'corrupt'));
$reject(fn () => $verifier->verify(str_replace('"event_count":8', '"event_count":8.0', $indexBytes), $signature, $key, $read, $read));
$reject(fn () => $verifier->verify('{"mode":"test",'.substr($indexBytes,1), $signature, $key, $read, $read));
$bytes = '';
foreach (json_decode($indexBytes)->segments as $part) {
    $files = BoundedZip::read($read($part->path, $part->archive_size));
    $bytes .= $files['events.ndjson'];
    $assert(str_contains($files['context.json'], '😀'));
}
$assert($bytes === file_get_contents(dirname($directory).'/test-bundle/events.ndjson'));

// Rebuild every hash and signature so these failures exercise semantic checks,
// rather than stopping at an incidental archive digest mismatch.
$archive = static function (array $files, ?string $symlink = null): string {
    $path = tempnam(sys_get_temp_dir(), 'myproof-test-');
    $zip = new ZipArchive();
    $zip->open($path, ZipArchive::OVERWRITE);
    foreach ($files as $name => $data) {
        $zip->addFromString($name, $data);
        if ($name === $symlink) { $zip->setExternalAttributesName($name, 3, 0120777 << 16); }
    }
    $zip->close();
    try { return file_get_contents($path); } finally { unlink($path); }
};
$rebuild = static function (callable $changeEvent, ?callable $changeFiles = null) use ($indexBytes, $read, $archive, $sign, $verifier, $key): void {
    $json = new CanonicalJson();
    $index = json_decode($indexBytes);
    $archives = [];
    $previous = null;
    foreach ($index->segments as $descriptor) {
        $files = BoundedZip::read($read($descriptor->path, $descriptor->archive_size));
        $segment = json_decode($files['segment.json']);
        $segment->chain_start->previous_sha256 = $descriptor->previous_sha256 = $previous;
        $lines = [];
        foreach (explode("\n", rtrim($files['events.ndjson'], "\n")) as $line) {
            $event = json_decode($line);
            $changeEvent($event);
            $event->previous_hash = $previous;
            $lines[] = $canonical = $json->encode($event);
            $previous = hash('sha256', $canonical);
        }
        $files['events.ndjson'] = implode("\n", $lines)."\n";
        $segment->events_sha256 = $descriptor->events_sha256 = hash('sha256', $files['events.ndjson']);
        $segment->events_bytes = $descriptor->events_bytes = strlen($files['events.ndjson']);
        $segment->chain_head->sha256 = $descriptor->last_sha256 = $previous;
        $files['segment.json'] = $json->encode($segment);
        $descriptor->segment_sha256 = hash('sha256', $files['segment.json']);
        if ($changeFiles !== null) { $changeFiles($files); }
        $archives[$descriptor->path] = $archive($files);
        $descriptor->archive_sha256 = hash('sha256', $archives[$descriptor->path]);
        $descriptor->archive_size = strlen($archives[$descriptor->path]);
    }
    $index->full_head->sha256 = $previous;
    $snapshot = json_decode($read('snapshot.json', 1048576));
    $snapshot->head_hash = $previous;
    $snapshotBytes = $json->encode($snapshot);
    $index->snapshot_sha256 = $index->artifacts[0]->sha256 = hash('sha256', $snapshotBytes);
    $index->artifacts[0]->size = strlen($snapshotBytes);
    $canonical = $json->encode($index);
    $verifier->verify($canonical, $sign($canonical), $key, static fn ($name,$size): string => $archives[$name], static fn ($name,$size): string => $snapshotBytes);
};
$rebuild(static function ($event): void {}); // A fully rebuilt valid collection still passes.
$assert(true);
foreach (['event_id' => '01K6R000000000000000000012', 'source_event_id' => 'test-source-3'] as $field => $duplicate) {
    try {
        $rebuild(static function ($event) use ($field, $duplicate): void { if ($event->sequence === 4) { $event->{$field} = $duplicate; } });
        throw new RuntimeException('Cross-segment duplicate accepted.');
    } catch (EvidenceException $failure) {
        $assert($failure->getMessage() === 'Duplicate event or source identity across collection segments.');
    }
}
$reject(fn () => $rebuild(static function ($event): void {}, static function (&$files): void { $files['unbound.txt'] = 'unbound'; }));
$reject(fn () => BoundedZip::read($archive(['../escape.txt' => 'invalid'])));
$reject(fn () => BoundedZip::read($archive(['link.txt' => 'elsewhere'], 'link.txt')));
$reject(fn () => BoundedZip::read($archive(['large.txt' => str_repeat('x', CollectionSchema::MAX_ARTIFACT_BYTES + 1)])));
// Two equal-length different names become duplicate local and central directory names.
$reject(fn () => BoundedZip::read(str_replace('other.txt', 'first.txt', $archive(['first.txt' => 'one', 'other.txt' => 'two']))));
echo "Collection verification: {$checks} checks passed.\n";
