# Strict Engineering Kernel Installer for Antigravity
param(
    [string]$GeminiDir = "$env:USERPROFILE\.gemini",
    [string]$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
)

if (-not $PythonExe) {
    $PythonExe = "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe"
    if (-not (Test-Path $PythonExe)) {
        $PythonExe = "$env:LOCALAPPDATA\Python\bin\python.exe"
    }
}

& $PythonExe (Join-Path $PSScriptRoot "install.py")
