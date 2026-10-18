[CmdletBinding()]
param(
    [string]$Version = '0.5.0',
    [switch]$SkipBuild,
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$DistDir = Join-Path $RepoRoot 'dist'
$ExePath = Join-Path $DistDir 'mapip.exe'
$RootExe = Join-Path $RepoRoot 'mapip.exe'
$SumsPath = Join-Path $RepoRoot 'SHA256SUMS.txt'
$IssPath = Join-Path $PSScriptRoot 'mapip.iss'

$IsccFallbacks = @()
if (${env:ProgramFiles(x86)}) {
    $IsccFallbacks += (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe')
}
if ($env:ProgramFiles) {
    $IsccFallbacks += (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
}
$IsccFallbacks += (Join-Path $env:USERPROFILE 'scoop\apps\inno-setup\current\ISCC.exe')

function Write-Step {
    param([string]$Message)
    Write-Host ''
    Write-Host "==> $Message"
}

function Find-Tool {
    param(
        [string]$Name,
        [string[]]$Fallbacks = @()
    )
    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        return $command.Source
    }
    foreach ($candidate in $Fallbacks) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    return $null
}

$mainGo = Join-Path $RepoRoot 'cmd\mapip\main.go'
if (Test-Path -LiteralPath $mainGo) {
    $match = Select-String -Path $mainGo -Pattern 'const version = "([^"]+)"' | Select-Object -First 1
    if ($match) {
        $sourceVersion = $match.Matches[0].Groups[1].Value
        if ($sourceVersion -ne $Version) {
            Write-Warning "cmd\mapip\main.go declares version $sourceVersion but this script was given $Version"
        }
    }
}

Set-Location -Path $RepoRoot

$go = Find-Tool -Name 'go'
if (-not $SkipBuild) {
    if (-not $go) {
        throw 'go executable not found on PATH; install Go 1.24+ or build mapip.exe manually'
    }
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    Write-Step "Building mapip.exe (version $Version)"
    & $go build -trimpath -ldflags '-s -w' -o $ExePath ./cmd/mapip
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE"
    }
    Copy-Item -LiteralPath $ExePath -Destination $RootExe -Force
    Write-Host "  $ExePath"
    Write-Host "  $RootExe"
}
elseif (-not (Test-Path -LiteralPath $ExePath)) {
    throw "no binary at $ExePath (drop -SkipBuild to build it)"
}

if (-not $SkipInstaller) {
    $iscc = Find-Tool -Name 'iscc' -Fallbacks $IsccFallbacks
    if (-not $iscc) {
        throw 'Inno Setup compiler (ISCC.exe) not found; install Inno Setup 6 or pass -SkipInstaller'
    }
    Write-Step 'Compiling the Inno Setup installer'
    & $iscc $IssPath
    if ($LASTEXITCODE -ne 0) {
        throw "iscc failed with exit code $LASTEXITCODE"
    }
}

$hash = (Get-FileHash -LiteralPath $RootExe -Algorithm SHA256).Hash
Set-Content -LiteralPath $SumsPath -Value ("{0}  mapip.exe" -f $hash) -Encoding ASCII
Write-Host ''
Write-Host "Refreshed $SumsPath"

Write-Step 'Artifacts'
$artifacts = @()
foreach ($pattern in @('mapip.exe', 'MapIp-Setup-*.exe')) {
    $artifacts += Get-ChildItem -Path $DistDir -Filter $pattern -File -ErrorAction SilentlyContinue
}
if ($artifacts.Count -eq 0) {
    Write-Host '  (none)'
}
foreach ($artifact in $artifacts) {
    $sha = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash
    Write-Host ("  {0}" -f $artifact.FullName)
    Write-Host ("    {0,12:N0} bytes  sha256 {1}" -f $artifact.Length, $sha)
}
Write-Host ''
