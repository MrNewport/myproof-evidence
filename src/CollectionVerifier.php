<?php
declare(strict_types=1);

namespace MyProof\Evidence;

final class CollectionVerifier
{
    /**
     * Segment archives are read one at a time, within their declared compressed limit.
     * @param callable(string,int):string $readSegmentArchive Bounded local reader, never remote fetch from index paths.
     * @param callable(string,int):string $readArtifact Bounded root artifact reader.
     */
    public function verify(string $canonicalIndex, string $signature, TrustedKey $pinnedKey, callable $readSegmentArchive, callable $readArtifact): VerificationResult
    {
        $json = new CanonicalJson();
        $index = CollectionSchema::index($json->requireCanonical($canonicalIndex, CollectionSchema::MAX_INDEX_BYTES));
        if ($index->key_id !== $pinnedKey->keyId || $index->mode !== $pinnedKey->mode || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached($signature, CollectionSigningInput::forIndex($canonicalIndex), $pinnedKey->publicKey)) {
            throw new EvidenceException('Collection signature, independent key or mode mismatch.');
        }
        $ids = [];
        $sources = [];
        $observe = static function (Event $event) use (&$ids, &$sources): void {
            $data = $event->data();
            $source = $data->source.':'.$data->source_event_id;
            if (isset($ids[$data->event_id]) || isset($sources[$source])) {
                throw new EvidenceException('Duplicate event or source identity across collection segments.');
            }
            $ids[$data->event_id] = true;
            $sources[$source] = true;
        };
        foreach ($index->segments as $descriptor) {
            $archive = $readSegmentArchive($descriptor->path, $descriptor->archive_size);
            if (!is_string($archive) || strlen($archive) !== $descriptor->archive_size || hash('sha256', $archive) !== $descriptor->archive_sha256) {
                throw new EvidenceException('Collection segment archive mismatch.');
            }
            $files = BoundedZip::read($archive);
            $envelope = $files['segment.json'] ?? '';
            if (hash('sha256', $envelope) !== $descriptor->segment_sha256) {
                throw new EvidenceException('Collection segment envelope mismatch.');
            }
            $segment = CollectionSchema::segment($json->requireCanonical($envelope, 65536));
            foreach (['export_id', 'workspace_id', 'delivery_id', 'mode', 'privacy_mode'] as $field) {
                if ($index->{$field} !== $segment->{$field}) {
                    throw new EvidenceException('Segment belongs to another collection identity or privacy scope.');
                }
            }
            foreach (['index', 'event_count', 'events_bytes', 'events_sha256'] as $field) {
                if ($descriptor->{$field} !== $segment->{$field}) {
                    throw new EvidenceException('Segment metadata differs from the signed index.');
                }
            }
            if ($segment->chain_start->sequence !== $descriptor->first_sequence || $segment->chain_start->previous_sha256 !== $descriptor->previous_sha256
                || $segment->chain_head->sequence !== $descriptor->last_sequence || $segment->chain_head->sha256 !== $descriptor->last_sha256) {
                throw new EvidenceException('Segment chain range differs from the signed index.');
            }
            BoundedZip::exactFiles($files, ['segment.json', 'events.ndjson', ...array_column($segment->artifacts, 'name')]);
            (new SegmentVerifier())->verify($envelope, $files['events.ndjson'], static fn (string $name, int $size): string => $files[$name], $observe);
            unset($archive, $files);
        }
        foreach ($index->artifacts as $artifact) {
            $bytes = $readArtifact($artifact->name, $artifact->size);
            if (!is_string($bytes) || strlen($bytes) !== $artifact->size || hash('sha256', $bytes) !== $artifact->sha256) {
                throw new EvidenceException('Collection root artifact mismatch.');
            }
            if ($artifact->name === 'snapshot.json') {
                $snapshot = $json->requireCanonical($bytes);
                if (!$snapshot instanceof \stdClass || ($snapshot->workspace_id ?? null) !== $index->workspace_id || ($snapshot->delivery_id ?? null) !== $index->delivery_id
                    || ($snapshot->mode ?? null) !== $index->mode || ($snapshot->privacy_mode ?? null) !== $index->privacy_mode
                    || ($snapshot->head_sequence ?? null) !== $index->full_head->sequence || ($snapshot->head_hash ?? null) !== $index->full_head->sha256) {
                    throw new EvidenceException('Collection snapshot identity or cutoff mismatch.');
                }
            }
        }
        return new VerificationResult($index->mode, $index->key_id, new ChainHead($index->full_head->sequence, $index->full_head->sha256), count($index->artifacts));
    }
}
