# Demo video pipeline

Builds the 2–4 minute Dev Day demo video from the live product, with no screen recorder and no manual editing.

1. `node capture.cjs` renders the slides and captures real states of https://guardian-mcp-rho.vercel.app/pay-safe
   (hover, loading and result for each demo seller, plus the marketplace scan) at 1920x1080.
2. `node render.cjs` synthesizes `narration.json` sentence by sentence with the Windows voice Microsoft Zira
   (`tts.ps1`), then plays `compose.html` in headless Chromium: page scroll, cursor, terminal replay of
   `captures/*.txt`, subtitles and voice are recorded with MediaRecorder into VP9/Opus WebM, and
   `webm-duration.cjs` writes the duration header. Output: `out/guardian-pay-safe-demo.webm`.
3. `node timeline.cjs` exports sentence timings and `out/guardian-pay-safe-demo.en.srt`.
4. `node verify.cjs out/guardian-pay-safe-demo.webm 5,30,60` extracts frames and per-second audio loudness.

The terminal scene replays real output of `scripts/safe-pay.js` captured on 16 Sep 2026 (`captures/`).
