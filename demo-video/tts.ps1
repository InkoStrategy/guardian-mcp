param(
  [string]$Narration = "$PSScriptRoot\narration.json",
  [string]$OutDir = "$PSScriptRoot\build\audio",
  [int]$Rate = 0
)
# Synthesize every sentence of narration.json with Microsoft Zira and write build/audio/durations.json.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Speech
New-Item -ItemType Directory -Force $OutDir | Out-Null
$json = Get-Content $Narration -Raw -Encoding UTF8 | ConvertFrom-Json
$result = @()
foreach ($scene in $json.scenes) {
  $i = 0
  foreach ($sentence in $scene.sentences) {
    $name = "$($scene.id)-$i.wav"
    $path = Join-Path $OutDir $name
    $synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
    $synth.SelectVoice('Microsoft Zira Desktop')
    $synth.Rate = $Rate
    $fmt = New-Object System.Speech.AudioFormat.SpeechAudioFormatInfo(24000, [System.Speech.AudioFormat.AudioBitsPerSample]::Sixteen, [System.Speech.AudioFormat.AudioChannel]::Mono)
    $synth.SetOutputToWaveFile($path, $fmt)
    $synth.Speak([string]$sentence.speech)
    $synth.Dispose()
    $bytes = (Get-Item $path).Length
    $seconds = [math]::Round(($bytes - 44) / 48000.0, 3)
    $result += [pscustomobject]@{ scene = $scene.id; index = $i; file = $name; seconds = $seconds }
    $i++
  }
}
$result | ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutDir 'durations.json') -Encoding utf8
"sentences: $($result.Count), total seconds: $([math]::Round(($result | Measure-Object seconds -Sum).Sum, 1))"
