[CmdletBinding()]
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\MapIp'),
    [string]$Source = '',
    [switch]$Build,
    [switch]$NoPath,
    [switch]$NoShortcuts,
    [switch]$Uninstall,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Prefix = [System.IO.Path]::GetFullPath($Prefix)
$ExePath = Join-Path $Prefix 'mapip.exe'

function Write-Info {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Host $Message
    }
}

function Find-Tool {
    param([string]$Name)
    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        return $command.Source
    }
    return $null
}

function Add-UserPath {
    param([string]$Directory)
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $current) {
        $current = ''
    }
    $target = $Directory.TrimEnd('\')
    $present = $false
    foreach ($entry in $current.Split(';')) {
        if ($entry -and $entry.TrimEnd('\') -ieq $target) {
            $present = $true
        }
    }
    if (-not $present) {
        $updated = $current.TrimEnd(';')
        if ($updated -ne '') {
            $updated = $updated + ';'
        }
        $updated = $updated + $Directory
        [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
        Write-Info "Added $Directory to the user PATH."
    }
    else {
        Write-Info "The user PATH already contains $Directory."
    }
    $inSession = $false
    foreach ($entry in $env:PATH.Split(';')) {
        if ($entry -and $entry.TrimEnd('\') -ieq $target) {
            $inSession = $true
        }
    }
    if (-not $inSession) {
        $env:PATH = $env:PATH + ';' + $Directory
    }
}

function New-Shortcut {
    param(
        [string]$Path,
        [string]$Target,
        [string]$WorkingDirectory,
        [string]$Description
    )
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $Target
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Description = $Description
    $shortcut.Save()
}

$UninstallContent = @'
param()

$ErrorActionPreference = 'Continue'

$prefix = $PSScriptRoot

$startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'MapIp.lnk'
if (Test-Path -LiteralPath $startMenu) {
    Remove-Item -LiteralPath $startMenu -Force -ErrorAction SilentlyContinue
}

$desktop = Join-Path ([Environment]::GetFolderPath('Desktop')) 'MapIp.lnk'
if (Test-Path -LiteralPath $desktop) {
    Remove-Item -LiteralPath $desktop -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath) {
    $target = $prefix.TrimEnd('\')
    $kept = @()
    foreach ($entry in $userPath.Split(';')) {
        if ($entry -eq '') {
            continue
        }
        if ($entry.TrimEnd('\') -ieq $target) {
            continue
        }
        $kept += $entry
    }
    $updated = [string]::Join(';', $kept)
    if ($updated -ne $userPath) {
        [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
        Write-Host 'Removed MapIp from the user PATH.'
    }
}

Set-Location -Path $env:TEMP
Remove-Item -LiteralPath $prefix -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'MapIp has been removed.'
'@

if ($Uninstall) {
    $uninstaller = Join-Path $Prefix 'uninstall.ps1'
    if (Test-Path -LiteralPath $uninstaller) {
        Write-Info "Uninstalling MapIp from $Prefix"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uninstaller
        if ($LASTEXITCODE -ne 0) {
            throw "the uninstaller reported exit code $LASTEXITCODE"
        }
    }
    else {
        Write-Warning "No uninstaller found at $uninstaller"
    }
    exit 0
}

$candidates = @()
if ($Source -ne '') {
    $candidates += $Source
}
$candidates += (Join-Path $RepoRoot 'dist\mapip.exe')
$candidates += (Join-Path $RepoRoot 'mapip.exe')

$resolved = $null
foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        $resolved = $candidate
        break
    }
}

$go = $null
if ($Build -or -not $resolved) {
    $go = Find-Tool -Name 'go'
}

New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

if ($Build -or -not $resolved) {
    if (-not $go) {
        Write-Host ''
        Write-Host 'ERROR: no mapip.exe was found and the Go toolchain is not on PATH.' -ForegroundColor Red
        Write-Host "Looked in: $($candidates -join ', ')"
        Write-Host 'Install Go 1.24+ from https://go.dev/dl/ and re-run with -Build,'
        Write-Host 'or download a release binary and pass -Source <path-to-mapip.exe>.'
        exit 2
    }
    Write-Info 'Building mapip.exe from source'
    & $go build -trimpath -ldflags '-s -w' -o $ExePath ./cmd/mapip
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE"
    }
}
else {
    Write-Info "Installing $resolved"
    Copy-Item -LiteralPath $resolved -Destination $ExePath -Force
}

if (-not $NoShortcuts) {
    $programs = [Environment]::GetFolderPath('Programs')
    New-Item -ItemType Directory -Force -Path $programs | Out-Null
    New-Shortcut -Path (Join-Path $programs 'MapIp.lnk') -Target $ExePath -WorkingDirectory $env:USERPROFILE -Description 'MapIp terminal UI'
    New-Shortcut -Path (Join-Path ([Environment]::GetFolderPath('Desktop')) 'MapIp.lnk') -Target $ExePath -WorkingDirectory $env:USERPROFILE -Description 'MapIp terminal UI'
    Write-Info 'Created Start Menu and desktop shortcuts.'
}
else {
    Write-Info 'Skipping shortcuts (NoShortcuts).'
}

if (-not $NoPath) {
    Add-UserPath -Directory $Prefix
}
else {
    Write-Info 'Leaving PATH unchanged (NoPath).'
}

Set-Content -LiteralPath (Join-Path $Prefix 'uninstall.ps1') -Value $UninstallContent -Encoding UTF8

Write-Host ''
Write-Host 'MapIp installation complete.'
Write-Host ("  Location:  {0}" -f $Prefix)
Write-Host ("  Binary:    {0}" -f $ExePath)
Write-Host '  Launch:    type "mapip" in any new terminal, or Start Menu -> MapIp'
if ($NoPath) {
    Write-Host '  PATH:      not modified (NoPath)'
}
else {
    Write-Host ("  PATH:      {0} added to the user PATH" -f $Prefix)
    Write-Host '             (open a new terminal for it to take effect)'
}
Write-Host ("  Uninstall: powershell -NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f (Join-Path $Prefix 'uninstall.ps1'))
Write-Host ''
