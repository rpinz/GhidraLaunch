# download.ps1 : download the Temurin OpenJDK MSI and the Ghidra release zip
#                used by the installer and verify their SHA-256 checksums

$ErrorActionPreference = 'Stop'

$ghidraApi = 'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest'
$versionsFile = Join-Path $PSScriptRoot 'GhidraLaunchSetup/Versions.wxi'

function Download-Verified {
    param($Name, $Url, $Checksum, $Output)

    Write-Host -NoNewline $Name
    if (-not $Url -or $Checksum -notmatch '^[0-9a-f]{64}$') {
        Write-Host '  [❌] release URL or checksum not found'
        return $false
    }

    $part = "$Output.part"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $part -UseBasicParsing -ErrorAction Stop | Out-Null
    } catch {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        Write-Host '  [❌] download failed'
        return $false
    }

    try {
        if ((Get-FileHash -LiteralPath $part -Algorithm SHA256).Hash -ne $Checksum) {
            Write-Host '  [❌] checksum mismatch'
            return $false
        }
        Move-Item -LiteralPath $part -Destination $Output -Force
        Write-Host '  [✔️]'
        return $true
    } finally {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path -LiteralPath $versionsFile) {
    Remove-Item -LiteralPath $versionsFile -Force
}
Remove-Item -LiteralPath (Join-Path $PSScriptRoot 'GhidraLaunchInstaller/Ghidra') -Recurse -Force -ErrorAction SilentlyContinue

$status = 0
$javaVersion = $null
$ghidraZip = Join-Path $PSScriptRoot 'Ghidra.zip'

try {
    $ghidra = Invoke-RestMethod -Uri $ghidraApi -Headers @{ Accept = 'application/vnd.github+json' }
} catch {
    $ghidra = $null
}

$asset = $ghidra.assets | Where-Object { $_.name -cmatch '^ghidra_.*_PUBLIC_[0-9]+\.zip$' } | Select-Object -First 1
$checksumMatch = [regex]::Match([string]$ghidra.body, 'SHA-256:[^0-9a-f]*([0-9a-f]{64})', 'IgnoreCase')
$ghidraChecksum = if ($checksumMatch.Success) { $checksumMatch.Groups[1].Value } else { $null }

if (Download-Verified 'Latest Ghidra' $asset.browser_download_url $ghidraChecksum $ghidraZip) {
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($ghidraZip)
        try {
            $entry = $archive.Entries | Where-Object { $_.FullName -cmatch '(^|/)Ghidra/application\.properties$' } | Select-Object -First 1
            if (-not $entry) {
                throw 'Ghidra Java requirement not found in release archive'
            }
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try {
                $properties = $reader.ReadToEnd()
            } finally {
                $reader.Dispose()
            }
        } finally {
            $archive.Dispose()
        }

        $versionMatch = [regex]::Match($properties, '(?m)^application\.java\.min=([^=\r\n]*)')
        $javaVersion = $versionMatch.Groups[1].Value -replace '\s', ''
        if (-not $versionMatch.Success -or $javaVersion -notmatch '^[0-9]+$') {
            throw 'Ghidra Java requirement is missing or invalid'
        }

        $jdkApi = "https://api.adoptium.net/v3/assets/latest/$javaVersion/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse"
        try {
            $jdkAssets = @(Invoke-RestMethod -Uri $jdkApi)
        } catch {
            $jdkAssets = @()
        }
        $jdk = $jdkAssets | Select-Object -First 1
        $jdkMsi = Join-Path $PSScriptRoot "OpenJDK${javaVersion}U-jdk_x64.msi"
        if (-not (Download-Verified "Latest Temurin OpenJDK $javaVersion" $jdk.binary.installer.link $jdk.binary.installer.checksum $jdkMsi)) {
            $status = 1
        }
    } catch {
        Write-Host $_.Exception.Message
        $status = 1
    }
} else {
    $status = 1
}

if ($status -eq 0) {
    $staging = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    try {
        Expand-Archive -LiteralPath $ghidraZip -DestinationPath $staging
        $root = Get-ChildItem -LiteralPath $staging -Directory | Where-Object {
            Test-Path -LiteralPath (Join-Path $_.FullName 'ghidraRun.bat') -PathType Leaf
        } | Select-Object -First 1
        if (-not $root) { throw 'Ghidra archive does not contain a usable ghidraRun.bat' }
        $destination = Join-Path $PSScriptRoot 'GhidraLaunchInstaller/Ghidra'
        Move-Item -LiteralPath $root.FullName -Destination $destination
        [System.IO.File]::WriteAllText($versionsFile, ('<?define JavaVersion = "{0}" ?>' -f $javaVersion) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    } finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit $status
