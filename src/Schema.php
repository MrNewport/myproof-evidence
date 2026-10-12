<?php
declare(strict_types=1);

namespace MyProof\Evidence;

/** Closed v2 protocol fields. Application authorization remains outside this package. */
final class Schema
{
    public const VERSION = 'myproof.evidence.v2';
    public const MODES = ['demo', 'test', 'live'];
    public const SOURCES = ['app', 'merchant', 'stripe', 'ses', 'cloudfront', 'client'];
    public const EDGE_RESULTS = ['Hit', 'RefreshHit', 'Miss', 'LimitExceeded', 'CapacityExceeded', 'Error', 'Redirect', 'LambdaExecutionError', 'Unknown'];
    public const EDGE_DETAILS = [...self::EDGE_RESULTS, 'OriginShieldHit', 'MissGeneratedResponse', 'AbortedOrigin', 'ClientCommError', 'ClientGeoBlocked', 'ClientHungUpRequest', 'InternalError', 'InvalidRequest', 'InvalidRequestBlocked', 'InvalidRequestCertificate', 'InvalidRequestHeader', 'InvalidRequestMethod', 'LambdaLimitExceeded', 'OriginCommError', 'OriginConnectError', 'OriginContentRangeLengthError', 'OriginDnsError', 'OriginError', 'OriginHeaderTooBigError', 'OriginInvalidResponseError', 'OriginReadError', 'OriginWriteError', 'OriginZeroSizeObjectError', 'SlowReaderOriginError'];
    public const EVENTS = [
        'order_snapshot_recorded' => [['app', 'merchant'], ['snapshot_sha256' => 'hash', 'asset_version_id' => 'ulid', 'order_id' => 'ulid']],
        'payment_observed' => [['stripe', 'merchant'], ['status' => ['pending', 'paid', 'failed', 'refunded', 'partially_refunded', 'disputed', 'unknown'], 'amount_minor' => 'uint', 'currency' => 'currency', 'currency_exponent' => 'currency_exponent']],
        'payment_provider_observed' => [['stripe'], [
            'account_id' => 'opaque', 'payment_intent_id' => 'opaque', 'order_id' => 'ulid', 'order_snapshot_sha256' => 'hash',
            'status' => ['pending', 'paid', 'failed', 'refunded', 'partially_refunded', 'disputed'],
            'amount_minor' => 'uint', 'currency' => 'currency', 'currency_exponent' => 'currency_exponent',
            'refunded_minor' => 'uint', 'refund_pending' => 'bool', 'dispute_status' => ['none', 'open', 'won', 'lost'],
            'observed_at' => 'timestamp', 'trigger_created_at' => 'timestamp', 'mapping_source' => ['merchant'],
        ]],
        'portal_requested' => [['app'], []],
        'delivery_access_changed' => [['app'], ['change' => ['rotated', 'revoked'], 'generation' => 'uint', 'residual_url_seconds' => 'uint']],
        'code_message_accepted' => [['ses'], ['purpose' => ['delivery_access']]],
        'email_code_verified' => [['app'], ['method' => ['email_code']]],
        'download_authorized' => [['app'], ['attempt_id' => 'ulid', 'asset_version_id' => 'ulid', 'expires_at' => 'timestamp', 'receipt_mode' => ['native', 'browser_checksum']]],
        'edge_response_observed' => [['cloudfront'], [
            'attempt_id' => 'ulid', 'asset_version_id' => 'ulid', 'object_identity_sha256' => 'hash',
            'distribution_id' => 'opaque', 'request_id' => 'edge_request_id', 'log_source_id' => 'opaque',
            'method' => ['GET', 'HEAD', 'OPTIONS'], 'status_code' => 'edge_status', 'bytes_sent' => 'uint',
            'bytes_semantics' => ['response_including_headers'], 'response_content_length' => 'nullable_uint',
            'response_range_start' => 'nullable_uint', 'response_range_end' => 'nullable_uint',
            'response_result_type' => self::EDGE_RESULTS, 'final_result_type' => self::EDGE_RESULTS, 'detailed_result_type' => self::EDGE_DETAILS,
        ]],
        'browser_receipt_reported' => [['client'], ['attempt_id' => 'ulid', 'asset_version_id' => 'ulid', 'sha256' => 'hash', 'bytes_received' => 'uint', 'hash_matches' => 'bool']],
        'preview_reported' => [['client'], ['attempt_id' => 'ulid', 'asset_version_id' => 'ulid', 'preview_type' => ['png', 'jpeg', 'text']]],
        'access_acknowledged' => [['client'], ['voluntary' => [true]]],
        'help_requested' => [['client', 'app'], ['category' => ['access', 'file', 'payment', 'other']]],
        'transfer_problem_reported' => [['client'], ['attempt_id' => 'ulid', 'reason' => ['interrupted', 'hash_mismatch', 'browser_error', 'unknown']]],
    ];

    public static function event(mixed $event): \stdClass
    {
        self::fields($event, ['schema', 'event_id', 'workspace_id', 'delivery_id', 'sequence', 'previous_hash', 'occurred_at', 'recorded_at', 'source', 'source_event_id', 'type', 'mode', 'payload', 'private_context_ref']);
        self::oneOf($event->schema, [self::VERSION]);
        foreach (['event_id', 'workspace_id', 'delivery_id'] as $field) {
            self::value($event->{$field}, 'ulid');
        }
        self::value($event->sequence, 'uint');
        if ($event->sequence < 1 || ($event->sequence === 1 ? $event->previous_hash !== null : !self::matches($event->previous_hash, '/\A[0-9a-f]{64}\z/'))) {
            throw new EvidenceException('Invalid event sequence or previous hash.');
        }
        self::value($event->occurred_at, 'timestamp');
        self::value($event->recorded_at, 'timestamp');
        self::oneOf($event->mode, self::MODES);
        self::value($event->source_event_id, 'opaque');
        if ($event->private_context_ref !== null) {
            self::value($event->private_context_ref, 'ulid');
        }
        if (!is_string($event->type) || !isset(self::EVENTS[$event->type])) {
            throw new EvidenceException('Unsupported event type.');
        }
        [$sources, $payload] = self::EVENTS[$event->type];
        self::oneOf($event->source, $sources);
        self::fields($event->payload, array_keys($payload));
        foreach ($payload as $key => $type) {
            self::value($event->payload->{$key}, $type);
        }
        if ($event->type === 'edge_response_observed') {
            $start = $event->payload->response_range_start;
            $end = $event->payload->response_range_end;
            if (($start === null) !== ($end === null) || ($start !== null && $start > $end)) {
                throw new EvidenceException('Response range must be an ordered inclusive pair or two nulls.');
            }
            if ($event->source_event_id !== SourceEventId::cloudFront($event->payload->distribution_id, $event->payload->request_id, $event->payload->log_source_id)) {
                throw new EvidenceException('CloudFront source event identity does not match normalized provider identifiers.');
            }
        }
        if ($event->type === 'payment_provider_observed'
            && (!self::matches($event->payload->account_id, '/\Aacct_[A-Za-z0-9]{1,100}\z/')
                || !self::matches($event->payload->payment_intent_id, '/\Api_[A-Za-z0-9]{1,100}\z/')
                || $event->payload->refunded_minor > $event->payload->amount_minor
                || $event->occurred_at !== $event->payload->observed_at)) {
            throw new EvidenceException('Invalid provider payment identity, amount or observation time.');
        }
        return $event;
    }

    public static function manifest(mixed $manifest): \stdClass
    {
        self::fields($manifest, ['schema', 'workspace_id', 'delivery_id', 'mode', 'generated_at', 'key_id', 'signature_algorithm', 'privacy_mode', 'snapshot_sha256', 'chain_head', 'artifacts', 'coverage']);
        self::oneOf($manifest->schema, [self::VERSION]);
        self::value($manifest->workspace_id, 'ulid');
        self::value($manifest->delivery_id, 'ulid');
        self::oneOf($manifest->mode, self::MODES);
        self::value($manifest->generated_at, 'timestamp');
        self::value($manifest->key_id, 'opaque');
        self::oneOf($manifest->signature_algorithm, ['Ed25519']);
        self::oneOf($manifest->privacy_mode, ['masked', 'full_private']);
        self::value($manifest->snapshot_sha256, 'hash');
        self::fields($manifest->chain_head, ['sequence', 'sha256']);
        self::value($manifest->chain_head->sequence, 'uint');
        if ($manifest->chain_head->sequence < 1 || $manifest->chain_head->sequence > ChainVerifier::MAX_EVENTS) {
            throw new EvidenceException('Export must bind a nonempty, bounded chain.');
        }
        self::value($manifest->chain_head->sha256, 'hash');
        if (!is_array($manifest->artifacts) || !array_is_list($manifest->artifacts) || count($manifest->artifacts) < 1 || count($manifest->artifacts) > 16) {
            throw new EvidenceException('Invalid artifact list.');
        }
        $names = [];
        foreach ($manifest->artifacts as $artifact) {
            self::fields($artifact, ['name', 'sha256', 'size']);
            if (!self::matches($artifact->name, '/\A[a-z0-9][a-z0-9_-]{0,63}\.(json|html|pdf|txt)\z/') || isset($names[$artifact->name])) {
                throw new EvidenceException('Invalid or duplicate artifact filename.');
            }
            $names[$artifact->name] = true;
            self::value($artifact->sha256, 'hash');
            self::value($artifact->size, 'uint');
            if ($artifact->size > BundleVerifier::MAX_ARTIFACT_BYTES) {
                throw new EvidenceException('Artifact too large.');
            }
            if ($artifact->name === 'snapshot.json' && $artifact->sha256 !== $manifest->snapshot_sha256) {
                throw new EvidenceException('Snapshot binding mismatch.');
            }
        }
        if (!isset($names['snapshot.json'])) {
            throw new EvidenceException('Missing snapshot artifact.');
        }
        if (!is_array($manifest->coverage) || !array_is_list($manifest->coverage) || count($manifest->coverage) < 1 || count($manifest->coverage) > 6) {
            throw new EvidenceException('Missing or invalid source coverage.');
        }
        $sources = [];
        foreach ($manifest->coverage as $coverage) {
            self::fields($coverage, ['source', 'status', 'limitation']);
            self::oneOf($coverage->source, self::SOURCES);
            self::oneOf($coverage->status, ['observed', 'pending', 'unavailable']);
            if (isset($sources[$coverage->source]) || !is_string($coverage->limitation) || strlen($coverage->limitation) < 1 || strlen($coverage->limitation) > 512) {
                throw new EvidenceException('Invalid source coverage limitation.');
            }
            $sources[$coverage->source] = true;
        }
        return $manifest;
    }

    public static function fields(mixed $object, array $expected): void
    {
        if (!$object instanceof \stdClass) {
            throw new EvidenceException('Expected a JSON object.');
        }
        $actual = array_keys(get_object_vars($object));
        sort($actual);
        sort($expected);
        if ($actual !== $expected) {
            throw new EvidenceException('Object fields do not match the closed v2 schema.');
        }
    }

    public static function value(mixed $value, string|array $type): void
    {
        if (is_array($type)) {
            self::oneOf($value, $type);
            return;
        }
        $valid = match ($type) {
            'ulid' => self::matches($value, '/\A[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25}\z/'),
            'hash' => self::matches($value, '/\A[0-9a-f]{64}\z/'),
            'opaque' => self::matches($value, '/\A[A-Za-z0-9._:-]{1,128}\z/'),
            'currency' => self::matches($value, '/\A[A-Z]{3}\z/'),
            'currency_exponent' => is_int($value) && $value >= 0 && $value <= 9,
            'edge_request_id' => self::matches($value, '/\A[A-Za-z0-9_+=\/-]{1,128}\z/'),
            'uint' => is_int($value) && $value >= 0 && $value <= CanonicalJson::MAX_INTEGER,
            'nullable_uint' => $value === null || (is_int($value) && $value >= 0 && $value <= CanonicalJson::MAX_INTEGER),
            'http_status' => is_int($value) && $value >= 100 && $value <= 599,
            'edge_status' => is_int($value) && ($value === 0 || ($value >= 100 && $value <= 599)),
            'bool' => is_bool($value),
            'timestamp' => self::timestamp($value),
            default => false,
        };
        if (!$valid) {
            throw new EvidenceException('Invalid value for '.$type.'.');
        }
    }

    public static function oneOf(mixed $value, array $values): void
    {
        if (!in_array($value, $values, true)) {
            throw new EvidenceException('Value is not in the allowed protocol set.');
        }
    }

    private static function matches(mixed $value, string $pattern): bool
    {
        return is_string($value) && preg_match($pattern, $value) === 1;
    }

    private static function timestamp(mixed $value): bool
    {
        if (!self::matches($value, '/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\z/')) {
            return false;
        }
        $time = \DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s.u\Z', $value, new \DateTimeZone('UTC'));
        return $time !== false && $time->format('Y-m-d\TH:i:s.u\Z') === $value;
    }
}
