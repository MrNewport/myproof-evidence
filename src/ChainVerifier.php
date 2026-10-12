<?php
declare(strict_types=1);

namespace MyProof\Evidence;

final class ChainVerifier
{
    public const MAX_EVENTS = 10000;
    public const MAX_CHAIN_BYTES = 33554432;

    /** @param iterable<string> $canonicalEvents Original stored canonical bytes, in commit order. */
    public function verify(iterable $canonicalEvents, string $workspaceId, string $deliveryId, string $mode): ChainHead
    {
        Schema::value($workspaceId, 'ulid');
        Schema::value($deliveryId, 'ulid');
        Schema::oneOf($mode, Schema::MODES);
        $sequence = 0;
        $previous = null;
        $bytes = 0;
        $ids = [];
        $sources = [];
        foreach ($canonicalEvents as $canonical) {
            if (!is_string($canonical) || ++$sequence > self::MAX_EVENTS || ($bytes += strlen($canonical)) > self::MAX_CHAIN_BYTES) {
                throw new EvidenceException('Event chain limits exceeded.');
            }
            $event = Event::fromCanonical($canonical);
            $data = $event->data();
            if ($data->workspace_id !== $workspaceId || $data->delivery_id !== $deliveryId || $data->mode !== $mode || $data->sequence !== $sequence || $data->previous_hash !== $previous) {
                throw new EvidenceException('Chain ownership, mode, sequence or hash mismatch.');
            }
            $sourceKey = $data->source.':'.$data->source_event_id;
            if (isset($ids[$data->event_id]) || isset($sources[$sourceKey])) {
                throw new EvidenceException('Duplicate event identity or source event.');
            }
            $ids[$data->event_id] = true;
            $sources[$sourceKey] = true;
            $previous = $event->sha256;
        }
        return new ChainHead($sequence, $previous);
    }
}
