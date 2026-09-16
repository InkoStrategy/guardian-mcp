'use strict';
/**
 * Write the Duration element into a MediaRecorder WebM (Chromium leaves it out, so players cannot seek).
 * Usage: node webm-duration.cjs in.webm out.webm <durationSeconds>
 * Only the Segment > Info element is rewritten; the Segment has unknown size, so growing Info is safe.
 */
const fs = require('node:fs');

function readVint(buf, pos) {
  const first = buf[pos];
  let len = 1;
  while (len <= 8 && !(first & (0x80 >> (len - 1)))) len++;
  if (len > 8) throw new Error('bad vint at ' + pos);
  let value = first & (0xff >> len);
  for (let i = 1; i < len; i++) value = value * 256 + buf[pos + i];
  const allOnes = value === Math.pow(2, 7 * len) - 1;
  return { len, value, unknown: allOnes };
}

function readId(buf, pos) {
  const first = buf[pos];
  let len = 1;
  while (len <= 4 && !(first & (0x80 >> (len - 1)))) len++;
  let id = 0;
  for (let i = 0; i < len; i++) id = id * 256 + buf[pos + i];
  return { id, len };
}

function encodeSize(n) {
  // 8-byte vint so the size field width never matters
  const out = Buffer.alloc(8);
  out[0] = 0x01;
  let v = n;
  for (let i = 7; i >= 1; i--) { out[i] = v % 256; v = Math.floor(v / 256); }
  return out;
}

function fix(buf, durationSeconds) {
  let pos = 0;
  // EBML header
  const ebml = readId(buf, pos); if (ebml.id !== 0x1a45dfa3) throw new Error('not EBML');
  pos += ebml.len; const ebmlSize = readVint(buf, pos); pos += ebmlSize.len + ebmlSize.value;
  const seg = readId(buf, pos); if (seg.id !== 0x18538067) throw new Error('no Segment');
  pos += seg.len; const segSize = readVint(buf, pos); pos += segSize.len;
  const segDataStart = pos;
  while (pos < buf.length) {
    const el = readId(buf, pos);
    const size = readVint(buf, pos + el.len);
    const headerLen = el.len + size.len;
    if (el.id === 0x1549a966) { // Info
      const infoStart = pos;
      const dataStart = pos + headerLen;
      const dataEnd = dataStart + size.value;
      let timecodeScale = 1000000;
      let p = dataStart;
      const kept = [];
      while (p < dataEnd) {
        const child = readId(buf, p);
        const cs = readVint(buf, p + child.len);
        const total = child.len + cs.len + cs.value;
        if (child.id === 0x2ad7b1) { // TimecodeScale
          let v = 0; for (let i = 0; i < cs.value; i++) v = v * 256 + buf[p + child.len + cs.len + i];
          timecodeScale = v;
        }
        if (child.id !== 0x4489) kept.push(buf.subarray(p, p + total)); // drop any existing Duration
        p += total;
      }
      const dur = Buffer.alloc(8);
      dur.writeDoubleBE((durationSeconds * 1e9) / timecodeScale, 0);
      const durationEl = Buffer.concat([Buffer.from([0x44, 0x89, 0x88]), dur]);
      const body = Buffer.concat(kept.concat(durationEl));
      const info = Buffer.concat([Buffer.from([0x15, 0x49, 0xa9, 0x66]), encodeSize(body.length), body]);
      return Buffer.concat([buf.subarray(0, infoStart), info, buf.subarray(dataEnd)]);
    }
    if (size.unknown) break;
    pos += headerLen + size.value;
    if (pos - segDataStart > 1e6) break;
  }
  throw new Error('Info element not found');
}

if (require.main === module) {
  const [input, output, seconds] = process.argv.slice(2);
  const fixed = fix(fs.readFileSync(input), Number(seconds));
  fs.writeFileSync(output, fixed);
  console.log('wrote', output, fixed.length, 'bytes, duration', seconds, 's');
}

module.exports = { fix };
