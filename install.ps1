# Copy both skills into the user's agent skills directory.
$ErrorActionPreference = "Stop"
$dest = Join-Path $env:USERPROFILE ".agents\skills"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
foreach ($skill in @("model-heist", "autoreg-pools")) {
    $src = Join-Path $PSScriptRoot "skills\$skill"
    $target = Join-Path $dest $skill
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    Copy-Item -Recurse -Force $src $target
    Write-Output "installed $skill -> $target"
}
Write-Output "`nVerify:"
Write-Output "  python `"$dest\model-heist\scripts\doctor.py`""
