// Offline synthetic provider-observation vector. No provider credentials or API calls.
// Reuses the independent JavaScript canonicalizer and PUBLIC TEST ONLY signing seed.
import { canonical } from './generate-fixtures.mjs';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const directory = fileURLToPath(new URL('./fixtures/', import.meta.url));
const original = join(directory, 'test-bundle');
const target = join(directory, 'merchant-test-bundle');
mkdirSync(target, { recursive: true });
const hash = value => createHash('sha256').update(value).digest('hex');
for (const file of ['snapshot.json', 'report.html']) copyFileSync(join(original, file), join(target, file));
const manifest = JSON.parse(readFileSync(join(original, 'manifest.json'), 'utf8'));
const prior = readFileSync(join(original, 'events.ndjson'), 'utf8');
const event = {
  schema: 'myproof.evidence.v2', event_id: '01K6R000000000000000000099',
  workspace_id: manifest.workspace_id, delivery_id: manifest.delivery_id,
  sequence: manifest.chain_head.sequence + 1, previous_hash: manifest.chain_head.sha256,
  occurred_at: '2026-10-12T12:03:00.000000Z', recorded_at: '2026-10-12T12:03:01.000000Z',
  source: 'stripe', source_event_id: 'stripe:synthetic-offline-fixture', type: 'payment_provider_observed', mode: 'test', private_context_ref: null,
  payload: {
    account_id: 'acct_synthetic', payment_intent_id: 'pi_synthetic', order_id: '01K6R000000000000000000004',
    order_snapshot_sha256: manifest.snapshot_sha256, status: 'partially_refunded', amount_minor: 100, currency: 'USD', currency_exponent: 2,
    refunded_minor: 25, refund_pending: true, dispute_status: 'won', observed_at: '2026-10-12T12:03:00.000000Z',
    trigger_created_at: '2026-10-12T11:00:00.000000Z', mapping_source: 'merchant',
  },
};
const eventBytes = canonical(event);
writeFileSync(join(target, 'events.ndjson'), prior + eventBytes + '\n');
manifest.chain_head = { sequence: event.sequence, sha256: hash(eventBytes) };
manifest.coverage.find(x => x.source === 'stripe').status = 'observed';
manifest.coverage.find(x => x.source === 'stripe').limitation = 'Synthetic offline provider adapter fixture only. No Stripe API was called. Mapping remains merchant supplied and payment can change.';
const bytes = canonical(manifest);
const seed = createHash('sha256').update('MyProof publicly known TEST ONLY seed 2026').digest();
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), type: 'pkcs8', format: 'der' });
writeFileSync(join(target, 'manifest.json'), bytes);
writeFileSync(join(target, 'signature.ed25519'), sign(null, Buffer.concat([Buffer.from('MyProof evidence v2\n'), createHash('sha256').update(bytes).digest()]), key));
writeFileSync(join(directory, 'merchant-event.sha256'), hash(eventBytes) + '\n');
