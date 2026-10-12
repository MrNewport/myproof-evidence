// Independent Node crypto/canonicalizer and deterministic ZIP: never calls PHP.
// Uses the original v2 fixture event bytes, unchanged, split into three parts.
import { canonical } from './generate-fixtures.mjs';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

// ZIP's DOS timestamp is local time, and system zip/deflate output varies by
// host. These tiny test archives use stored entries and fixed headers instead.
// The collection verifier accepts method 0; no production archive is changed.
const zipDate = ((2000 - 1980) << 9) | (1 << 5) | 1;
const crcTable = Array.from({length: 256}, (_, value) => {
  for (let bit = 0; bit < 8; bit++) value = (value & 1) ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
  return value >>> 0;
});
const crc32 = bytes => {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff];
  return (crc ^ 0xffffffff) >>> 0;
};
function fixedZip(entries) {
  const local = [], directory = [];
  let offset = 0;
  for (const [name, content] of Object.entries(entries)) {
    const filename = Buffer.from(name, 'utf8'), bytes = Buffer.from(content, 'utf8');
    if (filename.length > 0xffff || bytes.length > 0xffffffff) throw new Error('Fixture ZIP entry exceeds format bounds.');
    const checksum = crc32(bytes);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4); // ZIP 2.0, stored entry
    header.writeUInt16LE(zipDate, 12);
    header.writeUInt32LE(checksum, 14);
    header.writeUInt32LE(bytes.length, 18);
    header.writeUInt32LE(bytes.length, 22);
    header.writeUInt16LE(filename.length, 26);
    local.push(header, filename, bytes);

    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE((3 << 8) | 20, 4); // Unix origin, ZIP 2.0
    record.writeUInt16LE(20, 6);
    record.writeUInt16LE(zipDate, 14);
    record.writeUInt32LE(checksum, 16);
    record.writeUInt32LE(bytes.length, 20);
    record.writeUInt32LE(bytes.length, 24);
    record.writeUInt16LE(filename.length, 28);
    record.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    record.writeUInt32LE(offset, 42);
    directory.push(record, filename);
    offset += header.length + filename.length + bytes.length;
  }
  const central = Buffer.concat(directory);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(entries).length, 8);
  end.writeUInt16LE(Object.keys(entries).length, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, central, end]);
}
const dir = fileURLToPath(new URL('./fixtures/collection-test/', import.meta.url));
mkdirSync(dir,{recursive:true});
const hash = v => createHash('sha256').update(v).digest('hex');
const original = readFileSync(new URL('./fixtures/test-bundle/events.ndjson', import.meta.url),'utf8').trimEnd().split('\n');
const first = JSON.parse(original[0]), last = JSON.parse(original.at(-1));
const identity = {export_id:'01K6R000000000000000000099',workspace_id:first.workspace_id,delivery_id:first.delivery_id,mode:'test',privacy_mode:'masked'};
const descriptors=[];
for (let offset=0;offset<original.length;offset+=3) {
  const lines=original.slice(offset,offset+3), start=JSON.parse(lines[0]), end=JSON.parse(lines.at(-1)), index=descriptors.length+1;
  const ndjson=lines.join('\n')+'\n';
  const context=canonical({...identity,context_frozen_at:'2026-10-12T12:05:00.000000Z',private_context:{},unicode:'é / e\u0301 / 😀'});
  const html='<html><body><p>All segment observations, including adverse facts:</p><pre>'+lines.join('\n').replaceAll('&','&amp;').replaceAll('<','&lt;')+'</pre></body></html>';
  const artifacts=[{name:'context.json',sha256:hash(context),size:Buffer.byteLength(context)},{name:'report.html',sha256:hash(html),size:Buffer.byteLength(html)}];
  const envelope=canonical({schema:'myproof.evidence.segment.v1',...identity,index,chain_start:{sequence:start.sequence,previous_sha256:start.previous_hash},chain_head:{sequence:end.sequence,sha256:hash(lines.at(-1))},events_sha256:hash(ndjson),events_bytes:Buffer.byteLength(ndjson),event_count:lines.length,artifacts});
  const path='segment-'+String(index).padStart(4,'0')+'.zip';
  const archive=fixedZip({'segment.json':envelope,'events.ndjson':ndjson,'context.json':context,'report.html':html});
  writeFileSync(join(dir,path),archive);
  descriptors.push({index,path,segment_sha256:hash(envelope),archive_sha256:hash(archive),archive_size:archive.length,events_sha256:hash(ndjson),events_bytes:Buffer.byteLength(ndjson),event_count:lines.length,first_sequence:start.sequence,last_sequence:end.sequence,previous_sha256:start.previous_hash,last_sha256:hash(lines.at(-1))});
}
const snapshot=canonical({...identity,head_sequence:last.sequence,head_hash:hash(original.at(-1)),requested_at:'2026-10-12T12:04:00.000000Z'});
writeFileSync(join(dir,'snapshot.json'),snapshot);
const index=canonical({schema:'myproof.evidence.collection.v1',...identity,created_at:'2026-10-12T12:06:00.000000Z',key_id:'collection-test-2026',signature_algorithm:'Ed25519',full_head:{sequence:last.sequence,sha256:hash(original.at(-1))},event_count:last.sequence,snapshot_sha256:hash(snapshot),segments:descriptors,artifacts:[{name:'snapshot.json',sha256:hash(snapshot),size:Buffer.byteLength(snapshot)}],coverage:['app','merchant','stripe','ses','cloudfront','client'].map(source=>({source,status:original.some(v=>JSON.parse(v).source===source)?'observed':'unavailable',limitation:'Fixture observations only; missing and late events remain unknown.'}))});
const key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,0x43)]),format:'der',type:'pkcs8'});
const pub=createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32);
writeFileSync(join(dir,'collection.json'),index);
writeFileSync(join(dir,'signature.ed25519'),sign(null,Buffer.concat([Buffer.from('MyProof evidence collection v1\n'),Buffer.from(hash(index),'hex')]),key));
writeFileSync(fileURLToPath(new URL('./fixtures/collection-test-key.hex',import.meta.url)),pub.toString('hex')+'\n');
console.log('Generated independent collection fixture: '+original.length+' original v2 events, '+descriptors.length+' segments. TEST KEY ONLY.');
