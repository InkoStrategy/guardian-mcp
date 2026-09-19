'use strict';

/**
 * Builds the ~40s short cut: the cold open plus the unedited live-agent scene, nothing else.
 * Reuses the already-synthesised voice-over (--skip-tts), so it never re-runs TTS.
 * It swaps narration.json for the duration of the render and always puts the original back.
 *
 *   node demo-video/build-short.cjs
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = __dirname;
const OUT = path.join(ROOT, 'out');
const NARR = path.join(ROOT, 'narration.json');
const KEEP_NARR = path.join(ROOT, 'build', 'narration.full.json');
const RENDER_OUT = path.join(OUT, 'guardian-pay-safe-demo.webm');
const KEEP_WEBM = path.join(OUT, 'guardian-pay-safe-demo-v6.2.webm');
const SHORT = path.join(OUT, 'guardian-pay-safe-short.webm');

const SCENES = ['S0', 'S9B'];

const full = JSON.parse(fs.readFileSync(NARR, 'utf8'));
fs.writeFileSync(KEEP_NARR, JSON.stringify(full, null, 1));

const picked = SCENES.map((id) => {
  const sc = full.scenes.find((s) => s.id === id);
  if (!sc) throw new Error('scene ' + id + ' not in narration.json');
  return sc;
});

if (!fs.existsSync(KEEP_WEBM)) throw new Error('refusing to run: the v6.2 master is missing, ' + KEEP_WEBM);

let failed = null;
try {
  fs.writeFileSync(NARR, JSON.stringify(Object.assign({}, full, { scenes: picked }), null, 1));
  console.log('rendering the short cut from ' + SCENES.join(' + ') + ' (voice-over reused)…');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'render.cjs'), '--skip-tts'],
    { cwd: path.dirname(ROOT), encoding: 'utf8', stdio: 'inherit' });
  if (r.status !== 0) throw new Error('render.cjs exited ' + r.status);
  if (!fs.existsSync(RENDER_OUT)) throw new Error('render produced no webm');
  fs.renameSync(RENDER_OUT, SHORT);
  console.log('wrote ' + path.relative(process.cwd(), SHORT) +
    '  (' + (fs.statSync(SHORT).size / 1048576).toFixed(1) + ' MB)');
} catch (e) {
  failed = e;
} finally {
  fs.writeFileSync(NARR, JSON.stringify(full, null, 1));
  console.log('narration.json restored (' + full.scenes.length + ' scenes)');
  // render.cjs writes the full cut to this name; put the master back so nothing looks truncated.
  if (!fs.existsSync(RENDER_OUT)) fs.copyFileSync(KEEP_WEBM, RENDER_OUT);
}
if (failed) { console.error(failed.message); process.exit(1); }
