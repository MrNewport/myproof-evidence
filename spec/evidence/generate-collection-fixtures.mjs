// Independent Node crypto/canonicalizer and system ZIP: never calls PHP.
// Uses the original v2 fixture event bytes, unchanged, split into three parts.
import { canonical } from './generate-fixtures.mjs';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, utimesSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
  const scratch=mkdtempSync(join(tmpdir(),'myproof-node-fixture-'));
  try {
    for(const [name,bytes] of Object.entries({'segment.json':envelope,'events.ndjson':ndjson,'context.json':context,'report.html':html})) {
      writeFileSync(join(scratch,name),bytes);utimesSync(join(scratch,name),946684800,946684800);
    }
    const path='segment-'+String(index).padStart(4,'0')+'.zip';
    const archivePath=join(scratch,path);
    execFileSync('/usr/bin/zip',['-X','-q',archivePath,'segment.json','events.ndjson','context.json','report.html'],{cwd:scratch});
    const archive=readFileSync(archivePath);writeFileSync(join(dir,path),archive);
    descriptors.push({index,path,segment_sha256:hash(envelope),archive_sha256:hash(archive),archive_size:archive.length,events_sha256:hash(ndjson),events_bytes:Buffer.byteLength(ndjson),event_count:lines.length,first_sequence:start.sequence,last_sequence:end.sequence,previous_sha256:start.previous_hash,last_sha256:hash(lines.at(-1))});
  } finally {rmSync(scratch,{recursive:true,force:true});}
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
