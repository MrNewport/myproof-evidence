<?php
declare(strict_types=1);

namespace MyProof\Evidence;

final class SegmentVerifier
{
    /** Observer lets the collection enforce identity uniqueness across segment boundaries. */
    public function verify(string $envelope, string $ndjson, callable $readArtifact, ?callable $observe = null): ChainHead
    {
        $segment = CollectionSchema::segment((new CanonicalJson())->requireCanonical($envelope, 65536));
        if (strlen($ndjson) !== $segment->events_bytes || hash('sha256', $ndjson) !== $segment->events_sha256 || !str_ends_with($ndjson, "\n")) {
            throw new EvidenceException('Segment stream size, digest or newline mismatch.');
        }
        $lines = explode("\n", substr($ndjson, 0, -1));
        if (count($lines) !== $segment->event_count) {
            throw new EvidenceException('Segment stream count mismatch.');
        }
        $previous = $segment->chain_start->previous_sha256;
        $sequence = $segment->chain_start->sequence;
        $ids = [];
        $sources = [];
        foreach ($lines as $bytes) {
            $event = Event::fromCanonical($bytes);
            $data = $event->data();
            $source = $data->source.':'.$data->source_event_id;
            if ($data->workspace_id !== $segment->workspace_id || $data->delivery_id !== $segment->delivery_id || $data->mode !== $segment->mode
                || $data->sequence !== $sequence || $data->previous_hash !== $previous || isset($ids[$data->event_id]) || isset($sources[$source])) {
                throw new EvidenceException('Segment chain identity or sequence mismatch.');
            }
            $ids[$data->event_id] = true;
            $sources[$source] = true;
            if ($observe !== null) {
                $observe($event);
            }
            $sequence++;
            $previous = $event->sha256;
        }
        if ($sequence - 1 !== $segment->chain_head->sequence || $previous !== $segment->chain_head->sha256) {
            throw new EvidenceException('Segment does not reach its declared head.');
        }
        foreach ($segment->artifacts as $artifact) {
            $bytes = $readArtifact($artifact->name, $artifact->size);
            if (!is_string($bytes) || strlen($bytes) !== $artifact->size || hash('sha256', $bytes) !== $artifact->sha256) {
                throw new EvidenceException('Segment artifact mismatch.');
            }
        }
        return new ChainHead($sequence - 1, $previous);
    }
}
