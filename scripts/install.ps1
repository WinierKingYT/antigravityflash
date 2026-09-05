# Strict Engineering Kernel Installer for Antigravity
param(
    [string]$GeminiDir = "$env:USERPROFILE\.gemini",
    [string]$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Installing Antigravity Strict Engineering Kernel V5.0" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not $PythonExe) {
    $PythonExe = "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe"
    if (-not (Test-Path $PythonExe)) {
        $PythonExe = "$env:LOCALAPPDATA\Python\bin\python.exe"
    }
}

Write-Host "Using Python executable: $PythonExe" -ForegroundColor Yellow

$TargetConfigDir = Join-Path $GeminiDir "config\strict-engineering"
New-Item -ItemType Directory -Force -Path $TargetConfigDir | Out-Null

$SourceDir = Join-Path $PSScriptRoot "..\src\strict_engineering"
if (-not (Test-Path $SourceDir)) {
    $SourceDir = Join-Path $PSScriptRoot "..\strict_engineering"
}

Copy-Item -Path "$SourceDir\*" -Destination $TargetConfigDir -Recurse -Force
Write-Host "[OK] Modules copied to $TargetConfigDir" -ForegroundColor Green

# Update hooks.json
$HooksPath = Join-Path $GeminiDir "config\hooks.json"
$HooksDir = Split-Path $HooksPath
New-Item -ItemType Directory -Force -Path $HooksDir | Out-Null

$EscapedPython = $PythonExe -replace '\', '\\'
$EscapedScript = (Join-Path $TargetConfigDir "hooks_handler.py") -replace '\', '\\'

$HooksJson = @"
{
  "strict-engineering": {
    "PreToolUse": [
      {
        "matcher": "write_to_file|replace_file_content|multi_replace_file_content|run_command",
        "hooks": [
          {
            "type": "command",
            "command": "$EscapedPython $EscapedScript pre-tool",
            "timeout": 15
          }
        ]
      }
    ],
    "PreInvocation": [
      {
        "type": "command",
        "command": "$EscapedPython $EscapedScript pre-invocation",
        "timeout": 10
      }
    ],
    "Stop": [
      {
        "type": "command",
        "command": "$EscapedPython $EscapedScript stop",
        "timeout": 30
      }
    ]
  }
}
"@

Set-Content -Path $HooksPath -Value $HooksJson -Encoding UTF8
Write-Host "[OK] Hooks configured at $HooksPath" -ForegroundColor Green

# Update GEMINI.md
$GeminiMdPath = Join-Path $GeminiDir "GEMINI.md"
$SourceGeminiMd = Join-Path $PSScriptRoot "..\GEMINI.md"
if (Test-Path $SourceGeminiMd) {
    Copy-Item -Path $SourceGeminiMd -Destination $GeminiMdPath -Force
    Write-Host "[OK] System prompt configured at $GeminiMdPath" -ForegroundColor Green
}

Write-Host "`nRunning validation tests..." -ForegroundColor Cyan
& $PythonExe (Join-Path $PSScriptRoot "run_all_tests.py")

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[SUCCESS] Antigravity Strict Engineering Kernel successfully installed and verified!" -ForegroundColor Green
} else {
    Write-Host "`n[ERROR] Verification tests failed. Please inspect logs." -ForegroundColor Red
}
