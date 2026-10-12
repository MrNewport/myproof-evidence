# `myproof.evidence.v2` protocol profile

Version frozen for the local implementation. Genuine v1 archives require a separate
legacy verifier; this package rejects v1 and does not relabel its contents.

## Canonical bytes

The serializer follows RFC 8785 key ordering and string serialization on a deliberately
restricted input domain. This is **not** a complete floating-point JCS implementation.

- UTF-8 must be valid, without a BOM. Unpaired Unicode surrogates are rejected.
- Objects and arrays are distinct; preserve them as `stdClass` and PHP list arrays.
- Decoded duplicate keys are rejected at every depth, including escaped spellings.
  No Unicode normalization occurs; composed and decomposed strings remain different.
- Object keys sort lexicographically by unsigned UTF-16 code units. Numeric-looking
  object keys remain strings. Empty keys are allowed. NUL-leading object keys are
  outside this profile because PHP `stdClass` cannot represent them; internal NUL
  characters and NUL string values are supported.
- Strings use JSON escapes for quote, backslash, controls U+0000–001F; backspace,
  tab, LF, form-feed and CR use short escapes. Other control escapes use lowercase
  hex. Slash, U+2028/U+2029 and other Unicode are literal UTF-8.
- Numbers are integer tokens in `[-9007199254740991, 9007199254740991]`. Reject
  fractions, exponent notation, `-0`, leading zeros, NaN and infinity, even when
  a floating representation could denote an exact integer. Require 64-bit PHP.
- Input and canonical output are at most 1,048,576 bytes, nesting at most 32 edges
  from root to value (root depth 0), at most 20,000 values **including object keys**.
  Event bytes are further bounded to 65,536; manifest bytes to 262,144. No leading,
  trailing or inter-token whitespace remains in canonical bytes.

`CanonicalJson` uses the MIT `mmccook/php-json-canonicalization-scheme` serializer,
with strict parsing and validation before invocation. The adapter explicitly sets
UTF-8 for upstream UTF-16 conversion and restores the process encoding, and corrects
upstream's U+2028/2029 escaping while preserving literal backslash-u text. Its float
formatter is never invoked. The package tests cover this adapter boundary; the application source review is outside this public protocol.

Structural [event](event.schema.json) and [manifest](manifest.schema.json) JSON
schemas accompany the byte contract. A JSON Schema validator alone is insufficient:
it cannot detect duplicate raw keys or enforce original number spellings, canonical
bytes, byte-oriented limits, duplicate artifact names/source coverage, or cross-file
hash/ownership constraints. The PHP runtime adds those mandatory checks. Generated
schemas can be refreshed with `php spec/evidence/generate-schemas.php`.

## Events and chain

Every event has the exact required keys in `event.schema.json`. Event, workspace,
delivery and private context identifiers use the valid ASCII ULID alphabet in either
case, including Laravel's lowercase ULIDs. Original spelling is preserved byte for
byte: no uppercasing, lowercasing or other normalization is performed. Identity
comparisons and duplicate checks are case-sensitive, so differently cased identifiers
cannot substitute for the exact stored workspace/delivery/event identity. The first
character remains 0–7 and the alphabet excludes I/L/O/U in either case. Source event IDs are
1–128 ASCII characters `[A-Za-z0-9._:-]`. Private context is a nullable opaque ULID,
never private content. Timestamps use valid UTC calendar times with exactly six
fractional digits, such as `2026-10-12T12:00:00.000000Z`.

| Type | Allowed source | Exact required payload fields |
| --- | --- | --- |
| `order_snapshot_recorded` | `app`, `merchant` | `snapshot_sha256`, `asset_version_id`, `order_id` |
| `payment_observed` | `stripe`, `merchant` | `status`, `amount_minor`, `currency`, `currency_exponent` |
| `payment_provider_observed` | `stripe` only | Account/payment identity, frozen order commitment, current observed payment/refund/dispute state and read time, triggering event time; product mapping remains `merchant` |
| `portal_requested` | `app` | Empty object |
| `code_message_accepted` | `ses` | `purpose: delivery_access` |
| `email_code_verified` | `app` | `method: email_code` |
| `download_authorized` | `app` | `attempt_id`, `asset_version_id`, `expires_at`, `receipt_mode` |
| `edge_response_observed` | `cloudfront` | Exact-version, source/request, method, response/range and final-result fields below |
| `browser_receipt_reported` | `client` | `attempt_id`, `asset_version_id`, `sha256`, `bytes_received`, `hash_matches` |
| `preview_reported` | `client` | `attempt_id`, `asset_version_id`, `preview_type` |
| `access_acknowledged` | `client` | `voluntary: true` |
| `help_requested` | `client`, `app` | `category` |
| `transfer_problem_reported` | `client` | `attempt_id`, `reason` |

All ID payload fields are ULIDs and SHA-256 fields are 64 lowercase hex characters.
Amounts/byte counts are nonnegative safe integers; currency is three uppercase ASCII
letters (a syntactic code, not a supported-currency policy). Payment states:
`pending`, `paid`, `failed`, `refunded`, `partially_refunded`, `disputed`, `unknown`.
The currency exponent is an integer from 0 through 9: the recorded value denotes
`amount_minor × 10^(-currency_exponent)` units of that currency. There is no universal
cents assumption and no floating-point conversion. The application validates the
currency/exponent against its authoritative provider or recorded merchant assertion;
the package does not supply a currency catalog. Examples: JPY 500/exponent 0 denotes
500 JPY; KWD 1250/exponent 3 denotes 1.250 KWD. `source` still distinguishes `stripe`
provider reads from `merchant` assertions.

Receipt modes: `native`, `browser_checksum`. Preview types: `png`, `jpeg`, `text`.
The application must enforce bounded PNG/JPEG/TXT preview generation and access;
this event only records the client's report. PDF and ZIP are download attachments,
never accepted preview types. SVG/HTML and a generic unverified `image` type are
also rejected.
Help categories: `access`, `file`, `payment`, `other`. Transfer reasons:
`interrupted`, `hash_mismatch`, `browser_error`, `unknown`.
No additional payload keys or arbitrary free text are allowed. Source validation is
not permission to let a browser choose trusted server/provider event types.

### CloudFront observation payload

Every listed field is required; nullable fields must explicitly contain null when
unavailable. These are factual source fields, without an inferred receipt boolean.

| Field | Contract |
| --- | --- |
| `attempt_id`, `asset_version_id` | ULIDs bound by the application's authorized exact-version transfer mapping |
| `object_identity_sha256` | Lowercase SHA-256 of canonical `{bucket, key, version_id}` for the exact storage version; raw tuple is retained in authorized snapshot/private context |
| `distribution_id`, `log_source_id` | Bounded opaque IDs; log source identifies a stable logical source registry entry |
| `request_id` | Exact decoded provider request ID, 1–128 characters `[A-Za-z0-9_+=/-]` |
| `method` | `GET`, `HEAD` or `OPTIONS`; other methods remain in the raw inbox for explicit handling |
| `status_code` | Integer 100–599, or 0 for the provider's `000` no-response value |
| `bytes_sent` | Nonnegative safe integer, preserving `sc-bytes` |
| `bytes_semantics` | Constant `response_including_headers` |
| `response_content_length` | Nullable nonnegative safe integer from `sc-content-len` |
| `response_range_start`, `response_range_end` | Inclusive response range endpoints; both null or nonnegative safe integers with start ≤ end |
| `response_result_type` | Initial classification from `x-edge-response-result-type` |
| `final_result_type` | Final classification from `x-edge-result-type` |
| `detailed_result_type` | Detailed classification from `x-edge-detailed-result-type` |

The first two result fields allow the closed `Schema::EDGE_RESULTS` set (`Hit`,
`RefreshHit`, `Miss`, `LimitExceeded`, `CapacityExceeded`, `Error`, `Redirect`,
`LambdaExecutionError`, `Unknown`). Detailed values additionally allow the documented
class names in `Schema::EDGE_DETAILS`. Missing or newly unrecognized provider classes
map to `Unknown`; retain original data in the encrypted, bounded raw inbox for review.
Never map an unfamiliar class to success. The adapter preserves the provider's UTC
timestamp in the event's `occurred_at`, and ingestion time in `recorded_at`.

CloudFront byte totals include response headers. Initial status/classification may
precede a disconnect; final fields preserve that distinction. Range endpoints
describe response metadata, not verified local storage. Null ranges mean unavailable
metadata, not proof of a full request. The verifier neither sums overlapping ranges
nor derives receipt from status, byte totals, Content-Length, HEAD responses or final
classifications. Missing logs remain unknown. These mappings were checked against the
[AWS log reference](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logs-reference.html)
on 12 October 2026; live ingestion remains unverified.

`SourceEventId::cloudFront($distributionId, $requestId, $logSourceId)` returns `cf:`
followed by lowercase SHA-256 of `UTF8("MyProof CloudFront source event v2\n") ||
canonical({distribution_id, request_id, log_source_id})`. The event's `source_event_id`
must match that value. A retry from another batch/log filename uses the same stable
logical source ID; it must not invent a new source identity to bypass dedupe. The
application performs trusted source selection and one-time provider decoding before
calling this helper. The identity is not derived from timestamps or signed query
strings. Raw URL/query, cookies, IP, user-agent and storage paths are not payload fields.
The application must verify the object commitment against its authorized exact tuple;
the hash alone cannot prove the tuple or its provenance.

Mode is explicitly `demo`, `test` or `live` throughout a chain and manifest. Sequence
starts at 1 with `previous_hash: null`; later events contain SHA-256 of the **original
canonical bytes** of their immediately preceding event. Verify complete contiguous
sequence and matching workspace/delivery/mode, unique event IDs and unique
`(source, source_event_id)`. No timestamp reordering is performed. The limit is
10,000 events and 33,554,432 bytes per verification; larger exports need an explicitly
designed protocol extension, not silent truncation.

The application appends under a locked delivery head, stores immutable canonical
bytes/hash, writes unique sequence/source constraints and an outbox in the same
transaction. The pure package verifies results; it cannot supply database locks,
tenant authorization, update/delete restrictions or privacy deletion workflows.

## Manifest and verification

The closed manifest binds workspace, delivery, mode, generation time, key ID,
`signature_algorithm: Ed25519`, `privacy_mode: masked|full_private`, snapshot hash,
the terminal sequence/hash, 1–16 artifact descriptors and 1–6 unique source coverage
entries. Coverage status is `observed`, `pending` or `unavailable`, with a nonempty
limitation of at most 512 UTF-8 bytes. Generation time is a signer assertion, not an
independent timestamp. Apps should include every relevant source, including sources
with missing or pending telemetry; an omitted source cannot be inferred as complete.

The snapshot is canonical `snapshot.json`, containing matching `workspace_id`,
`delivery_id` and `mode`. Its remaining fields are application-owned captured data;
the application must minimize/redact them according to privacy mode. The manifest
snapshot hash must equal its artifact descriptor. The snapshot represents export
cutoff state and need not be byte-identical to the original order snapshot event.

Artifact names match `[a-z0-9][a-z0-9_-]{0,63}\.(json|html|pdf|txt)`, are unique,
and have exact byte size/SHA-256. Maximum each: 16,777,216 bytes; total: 33,554,432.
V2 bundle verification never downloads a URL, follows artifact symlinks, executes reports,
extracts a ZIP or invents a missing file. It verifies every declared artifact;
undeclared extra files have no authenticated standing and must not be presented as
verified contents. Snapshot JSON additionally obeys the 1 MiB canonical limit.

Signature input is `UTF8("MyProof evidence v2\n") || raw_SHA256(canonical_manifest)`.
Signature format is 64 raw ordinary Ed25519 bytes; pin format is 32 raw Ed25519 bytes.
The key policy supplies the expected key ID and expected mode independently. The
manifest cannot introduce or override its own trust anchor. `DemoSigner` rejects
`live`. No KMS adapter, SPKI decoder, v1 adapter or independent timestamp service is
implemented here. A staging KMS signature must later verify with this standalone
tool before KMS interoperability can be marked passed.

## Independent fixtures

`node spec/evidence/generate-fixtures.mjs` generates deterministic fixtures with an
independent JavaScript restricted serializer, Node SHA-256 and Node ordinary Ed25519.
It never calls PHP. The golden vectors cover UTF-16 supplementary key order,
control/line-separator escaping, literal escape text, integer bounds, non-normalized
Unicode and empty/numeric objects versus arrays. The public seed and pin are labeled
test-only. PHP tests compare exact canonical bytes, hashes, signing input and
signature, then attack parser/chain/manifest/artifact/ownership/key/mode handling.
The eight-event bundle also preserves merchant amounts with exponents 0 and 3,
a partial edge response, and a `200` response ending in `ClientCommError`. These are
synthetic fixtures: no provider was called. Schema tests reject unsupported preview
types, extra receipt/PII/query fields, malformed ranges and inconsistent source IDs.

`tests/Contract/EvidenceContractTest.php` runs the same fixture through the root
Composer consumer. Package tests require no Laravel. Framework integration and
database concurrency tests remain separate acceptance work.

Histories beyond the v2 bound use the independently domain-separated
[collection and segment v1 protocol](collections.md). Its new envelopes preserve
all original v2 event bytes and hashes. Do not relax this v2 profile or reuse its
signing domain to represent a partial chain.
