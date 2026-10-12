<?php
declare(strict_types=1);

namespace MyProof\Evidence;

/** Stable dedupe identities over normalized, nonsecret provider identifiers. */
final class SourceEventId
{
    public static function cloudFront(string $distributionId, string $requestId, string $logSourceId): string
    {
        Schema::value($distributionId, 'opaque');
        Schema::value($requestId, 'edge_request_id');
        Schema::value($logSourceId, 'opaque');
        $identity = (object) [
            'distribution_id' => $distributionId,
            'request_id' => $requestId,
            'log_source_id' => $logSourceId,
        ];
        return 'cf:'.hash('sha256', "MyProof CloudFront source event v2\n".(new CanonicalJson())->encode($identity));
    }
}
