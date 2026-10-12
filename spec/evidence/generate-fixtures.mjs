// Independent JavaScript reference for the restricted v2 profile. No PHP is called.
// The public deterministic seed below is TEST MATERIAL, never a production secret.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const directory = fileURLToPath(new URL('./fixtures/', import.meta.url));
const bundle = join(directory, 'test-bundle');
mkdirSync(bundle, { recursive: true });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0)) return String(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  throw Error('Outside restricted profile');
}

const vectors = [
  { name: 'utf16-key-order', value: { '\ufb33': 'Hebrew', '😀': 'supplementary', '€': 'Euro', '\r': 'CR', '1': 'one', '\u0080': 'control', 'ö': 'Latin' } },
  { name: 'line-separators-and-literal-escapes', value: { text: 'x\u2028y\u2029z', literal: '\\u2028\\u2029', escaped: '\\\u2028', controls: '\u0000\b\f\n\r\t"\\/' } },
  { name: 'object-array-distinction', value: { object: {}, list: [], numericObject: { '2': 'two', '10': 'ten', '0': 'zero' }, nested: [{}, []] } },
  { name: 'integer-limits', value: [-9007199254740991, 9007199254740991, 0, 42] },
  { name: 'unicode-not-normalized', value: { composed: 'é', decomposed: 'e\u0301', supplementary: '𐀀' } },
  { name: 'empty-key-and-internal-nul', value: { '': 'empty', 'x\u0000': 'internal NUL is permitted' } },
].map(({ name, value }) => {
  const bytes = canonical(value);
  return { name, input: JSON.stringify(value, null, 2), canonical: bytes, sha256: hash(bytes) };
});
writeFileSync(join(directory, 'canonical-vectors.json'), JSON.stringify(vectors, null, 2) + '\n');

const workspace = '01K6R000000000000000000001';
const delivery = '01K6R000000000000000000002';
const asset = '01K6R000000000000000000003';
const order = '01K6R000000000000000000004';
const attempt = '01K6R000000000000000000005';
const objectIdentity = { bucket: 'myproof-test-only', key: 'test/asset.bin', version_id: 'test-exact-version-1' };
const snapshot = canonical({ workspace_id: workspace, delivery_id: delivery, mode: 'test', order_id: order, asset_version_id: asset, asset_sha256: hash('Harmless test fixture.\n'), asset_size: 22, object_identity: objectIdentity, order_source: 'merchant_assertion' });
const report = '<!doctype html><html lang="en"><meta charset="utf-8"><title>TEST evidence</title><body><h1>TEST DATA</h1><p>Interrupted transfer followed by a browser report. Browser claims are not independently verified receipt.</p></body></html>\n';
writeFileSync(join(bundle, 'snapshot.json'), snapshot);
writeFileSync(join(bundle, 'report.html'), report);
let previous = null;
const events = [];
const addEvent = (type, source, payload, occurred, recorded) => {
  const event = {
    schema: 'myproof.evidence.v2', event_id: '01K6R0000000000000000000' + (events.length + 10),
    workspace_id: workspace, delivery_id: delivery, sequence: events.length + 1,
    previous_hash: previous, occurred_at: occurred, recorded_at: recorded, source,
    source_event_id: 'test-source-' + (events.length + 1), type, mode: 'test', payload, private_context_ref: null,
  };
  if (source === 'cloudfront') {
    event.source_event_id = 'cf:' + hash('MyProof CloudFront source event v2\n' + canonical({ distribution_id: payload.distribution_id, request_id: payload.request_id, log_source_id: payload.log_source_id }));
  }
  const bytes = canonical(event);
  previous = hash(bytes);
  events.push(bytes);
};
const time = minute => '2026-10-12T12:' + minute + ':00.000000Z';
addEvent('order_snapshot_recorded', 'merchant', { snapshot_sha256: hash(snapshot), asset_version_id: asset, order_id: order }, time('00'), time('00'));
addEvent('download_authorized', 'app', { attempt_id: attempt, asset_version_id: asset, expires_at: time('05'), receipt_mode: 'browser_checksum' }, time('01'), time('01'));
addEvent('transfer_problem_reported', 'client', { attempt_id: attempt, reason: 'interrupted' }, time('02'), time('02'));
// A late occurrence is intentionally appended at the end, never sorted into history.
addEvent('browser_receipt_reported', 'client', { attempt_id: attempt, asset_version_id: asset, sha256: hash('Harmless test fixture.\n'), bytes_received: 22, hash_matches: true }, time('01'), time('03'));
addEvent('payment_observed', 'merchant', { status: 'paid', amount_minor: 500, currency: 'JPY', currency_exponent: 0 }, time('00'), time('03'));
addEvent('payment_observed', 'merchant', { status: 'refunded', amount_minor: 1250, currency: 'KWD', currency_exponent: 3 }, time('02'), time('03'));
const edge = {
  attempt_id: attempt, asset_version_id: asset,
  object_identity_sha256: hash(canonical(objectIdentity)),
  distribution_id: 'test-distribution', request_id: 'test-request/partial==', log_source_id: 'test-log-source',
  method: 'GET', status_code: 206, bytes_sent: 410, bytes_semantics: 'response_including_headers',
  response_content_length: 10, response_range_start: 0, response_range_end: 9,
  response_result_type: 'Hit', final_result_type: 'Hit', detailed_result_type: 'Hit',
};
addEvent('edge_response_observed', 'cloudfront', edge, time('01'), time('03'));
addEvent('edge_response_observed', 'cloudfront', { ...edge, request_id: 'test-request/disconnected==', status_code: 200, bytes_sent: 412,
  response_content_length: 22, response_range_start: null, response_range_end: null,
  final_result_type: 'Error', detailed_result_type: 'ClientCommError' }, time('02'), time('03'));
writeFileSync(join(bundle, 'events.ndjson'), events.join('\n') + '\n');

const manifest = canonical({
  schema: 'myproof.evidence.v2', workspace_id: workspace, delivery_id: delivery, mode: 'test',
  generated_at: time('04'), key_id: 'test-vector-2026', signature_algorithm: 'Ed25519', privacy_mode: 'masked',
  snapshot_sha256: hash(snapshot), chain_head: { sequence: events.length, sha256: previous },
  artifacts: [
    { name: 'snapshot.json', sha256: hash(snapshot), size: Buffer.byteLength(snapshot) },
    { name: 'report.html', sha256: hash(report), size: Buffer.byteLength(report) },
  ],
  coverage: [
    { source: 'app', status: 'observed', limitation: 'Test authorization only; URL issuance does not prove receipt.' },
    { source: 'client', status: 'observed', limitation: 'Simulated browser claims are not device attestation.' },
    { source: 'cloudfront', status: 'observed', limitation: 'Synthetic partial/disconnected responses only; header-inclusive bytes do not establish receipt. No provider was called.' },
    { source: 'ses', status: 'unavailable', limitation: 'No messages were sent.' },
    { source: 'stripe', status: 'unavailable', limitation: 'No payment provider was called.' },
    { source: 'merchant', status: 'observed', limitation: 'Synthetic merchant assertion.' },
  ],
});
const seed = createHash('sha256').update('MyProof publicly known TEST ONLY seed 2026').digest();
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), type: 'pkcs8', format: 'der' });
const publicKey = createPublicKey(privateKey);
const rawPublic = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
const signingInput = Buffer.concat([Buffer.from('MyProof evidence v2\n'), createHash('sha256').update(manifest).digest()]);
const signature = sign(null, signingInput, privateKey);
if (!verify(null, signingInput, publicKey, signature)) throw Error('Independent signature check failed');
writeFileSync(join(bundle, 'manifest.json'), manifest);
writeFileSync(join(bundle, 'signature.ed25519'), signature);
writeFileSync(join(directory, 'test-only-public-key.hex'), rawPublic.toString('hex') + '\n');
writeFileSync(join(directory, 'expected.json'), JSON.stringify({ sequence: events.length, manifest_sha256: hash(manifest), signing_input_hex: signingInput.toString('hex'), signature_hex: signature.toString('hex'), head_sha256: previous, event_hashes: events.map(hash), test_seed_hex: seed.toString('hex') }, null, 2) + '\n');
// Never load trusted keys from test-bundle: this reference pin is an explicit fixture input.
if (!verify(null, signingInput, publicKey, readFileSync(join(bundle, 'signature.ed25519')))) throw Error('Written fixture failed');
console.log('Generated six independent canonical vectors and ordinary Ed25519 test bundle. TEST KEY IS PUBLIC.');
