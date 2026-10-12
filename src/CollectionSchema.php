<?php
declare(strict_types=1);

namespace MyProof\Evidence;

/** New collection and segment envelopes; original evidence v2 event bytes never change. */
final class CollectionSchema
{
    public const VERSION = 'myproof.evidence.collection.v1';
    public const SEGMENT_VERSION = 'myproof.evidence.segment.v1';
    public const MAX_SEGMENTS = 1024;
    public const MAX_EVENTS = 512000;
    public const MAX_SEGMENT_EVENTS = 500;
    public const MAX_SEGMENT_BYTES = 4194304;
    public const MAX_ARCHIVE_BYTES = 16777216;
    public const MAX_ARTIFACT_BYTES = 8388608;
    public const MAX_INDEX_BYTES = 1048576;

    public static function index(mixed $index): \stdClass
    {
        Schema::fields($index, ['schema', 'export_id', 'workspace_id', 'delivery_id', 'mode', 'privacy_mode', 'created_at', 'key_id', 'signature_algorithm', 'full_head', 'event_count', 'snapshot_sha256', 'segments', 'artifacts', 'coverage']);
        Schema::oneOf($index->schema, [self::VERSION]);
        self::identity($index);
        Schema::value($index->created_at, 'timestamp');
        Schema::value($index->key_id, 'opaque');
        Schema::oneOf($index->signature_algorithm, ['Ed25519']);
        Schema::value($index->snapshot_sha256, 'hash');
        self::head($index->full_head);
        self::positive($index->event_count, self::MAX_EVENTS);
        if ($index->event_count !== $index->full_head->sequence || !is_array($index->segments) || !array_is_list($index->segments) || count($index->segments) < 1 || count($index->segments) > self::MAX_SEGMENTS) {
            throw new EvidenceException('Invalid complete collection range.');
        }
        $sequence = 0;
        $previous = null;
        foreach ($index->segments as $offset => $segment) {
            Schema::fields($segment, ['index', 'path', 'segment_sha256', 'archive_sha256', 'archive_size', 'events_sha256', 'events_bytes', 'event_count', 'first_sequence', 'last_sequence', 'previous_sha256', 'last_sha256']);
            self::positive($segment->index, self::MAX_SEGMENTS);
            self::positive($segment->archive_size, self::MAX_ARCHIVE_BYTES);
            self::positive($segment->events_bytes, self::MAX_SEGMENT_BYTES);
            self::positive($segment->event_count, self::MAX_SEGMENT_EVENTS);
            self::positive($segment->first_sequence, self::MAX_EVENTS);
            self::positive($segment->last_sequence, self::MAX_EVENTS);
            foreach (['segment_sha256', 'archive_sha256', 'events_sha256', 'last_sha256'] as $field) {
                Schema::value($segment->{$field}, 'hash');
            }
            if ($segment->index !== $offset + 1 || $segment->path !== sprintf('segment-%04d.zip', $segment->index)
                || $segment->first_sequence !== $sequence + 1 || $segment->last_sequence !== $sequence + $segment->event_count
                || $segment->previous_sha256 !== $previous) {
                throw new EvidenceException('Collection segments are not a unique contiguous chain from genesis.');
            }
            $sequence = $segment->last_sequence;
            $previous = $segment->last_sha256;
        }
        if ($sequence !== $index->event_count || $previous !== $index->full_head->sha256) {
            throw new EvidenceException('Collection omits part of the declared full history.');
        }
        self::artifacts($index->artifacts);
        $snapshot = array_values(array_filter($index->artifacts, static fn ($a): bool => $a->name === 'snapshot.json'));
        if (count($snapshot) !== 1 || $snapshot[0]->sha256 !== $index->snapshot_sha256) {
            throw new EvidenceException('Missing or inconsistent collection snapshot.');
        }
        if (!is_array($index->coverage) || !array_is_list($index->coverage) || count($index->coverage) !== count(Schema::SOURCES)) {
            throw new EvidenceException('Collection must describe every source.');
        }
        $sources = [];
        foreach ($index->coverage as $coverage) {
            Schema::fields($coverage, ['source', 'status', 'limitation']);
            Schema::oneOf($coverage->source, Schema::SOURCES);
            Schema::oneOf($coverage->status, ['observed', 'pending', 'unavailable']);
            if (isset($sources[$coverage->source]) || !is_string($coverage->limitation) || strlen($coverage->limitation) < 1 || strlen($coverage->limitation) > 512) {
                throw new EvidenceException('Invalid collection source coverage.');
            }
            $sources[$coverage->source] = true;
        }
        return $index;
    }

    public static function segment(mixed $segment): \stdClass
    {
        Schema::fields($segment, ['schema', 'export_id', 'workspace_id', 'delivery_id', 'mode', 'privacy_mode', 'index', 'chain_start', 'chain_head', 'events_sha256', 'events_bytes', 'event_count', 'artifacts']);
        Schema::oneOf($segment->schema, [self::SEGMENT_VERSION]);
        self::identity($segment);
        self::positive($segment->index, self::MAX_SEGMENTS);
        Schema::fields($segment->chain_start, ['sequence', 'previous_sha256']);
        self::positive($segment->chain_start->sequence, self::MAX_EVENTS);
        if ($segment->chain_start->sequence === 1) {
            if ($segment->chain_start->previous_sha256 !== null) {
                throw new EvidenceException('Genesis must have no predecessor.');
            }
        } else {
            Schema::value($segment->chain_start->previous_sha256, 'hash');
        }
        self::head($segment->chain_head);
        self::positive($segment->event_count, self::MAX_SEGMENT_EVENTS);
        self::positive($segment->events_bytes, self::MAX_SEGMENT_BYTES);
        Schema::value($segment->events_sha256, 'hash');
        if ($segment->chain_head->sequence !== $segment->chain_start->sequence + $segment->event_count - 1) {
            throw new EvidenceException('Segment range and count differ.');
        }
        self::artifacts($segment->artifacts);
        return $segment;
    }

    public static function artifacts(mixed $artifacts): void
    {
        if (!is_array($artifacts) || !array_is_list($artifacts) || count($artifacts) < 1 || count($artifacts) > 16) {
            throw new EvidenceException('Invalid collection artifact list.');
        }
        $names = [];
        $total = 0;
        foreach ($artifacts as $artifact) {
            Schema::fields($artifact, ['name', 'sha256', 'size']);
            if (!is_string($artifact->name) || !preg_match('/\A[a-z0-9][a-z0-9_-]{0,63}\.(json|html|pdf|txt)\z/', $artifact->name)
                || in_array($artifact->name, ['segment.json', 'collection.json'], true) || isset($names[$artifact->name])) {
                throw new EvidenceException('Invalid or duplicate collection artifact path.');
            }
            $names[$artifact->name] = true;
            Schema::value($artifact->sha256, 'hash');
            Schema::value($artifact->size, 'uint');
            if (($total += $artifact->size) > self::MAX_ARTIFACT_BYTES) {
                throw new EvidenceException('Collection artifact bytes exceed the bound.');
            }
        }
    }

    private static function identity(\stdClass $value): void
    {
        foreach (['export_id', 'workspace_id', 'delivery_id'] as $field) {
            Schema::value($value->{$field}, 'ulid');
        }
        Schema::oneOf($value->mode, Schema::MODES);
        Schema::oneOf($value->privacy_mode, ['masked', 'full_private']);
    }

    private static function head(mixed $head): void
    {
        Schema::fields($head, ['sequence', 'sha256']);
        self::positive($head->sequence, self::MAX_EVENTS);
        Schema::value($head->sha256, 'hash');
    }

    private static function positive(mixed $value, int $max): void
    {
        Schema::value($value, 'uint');
        if ($value < 1 || $value > $max) {
            throw new EvidenceException('Collection integer bound exceeded.');
        }
    }
}
