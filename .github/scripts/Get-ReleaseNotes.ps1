<#
.SYNOPSIS
    Writes one version's section of CHANGELOG.md to a file for the release notes.

.DESCRIPTION
    Copies the lines under "## [<Version>]" up to the next "## [" heading
    (or the link references at the end), without the heading itself, which
    the release title already carries. With -Repository and -Ref, relative
    links become links to that ref on GitHub, since release pages do not
    resolve them. Exits with code 1 and writes nothing
    when CHANGELOG.md has no section for the version, so the caller can fall
    back to GitHub's generated notes alone.
#>
param(
    [Parameter(Mandatory)] [string]$Version,
    [Parameter(Mandatory)] [string]$OutFile,
    [string]$Changelog = 'CHANGELOG.md',
    [string]$Repository,
    [string]$Ref
)

$ErrorActionPreference = 'Stop'
$heading = "## [$Version]"
$section = $null
foreach ($line in Get-Content -LiteralPath $Changelog) {
    if ($null -eq $section) {
        if ($line -eq $heading -or $line.StartsWith("$heading ")) { $section = [Collections.Generic.List[string]]::new() }
        continue
    }
    if ($line.StartsWith('## [') -or $line -match '^\[[^\]]+\]:\s') { break }
    $section.Add($line)
}

if ($null -eq $section) {
    Write-Host "$Changelog has no '$heading' section."
    exit 1
}

$text = ($section -join "`n").Trim()
if (-not $text) {
    Write-Host "$Changelog's '$heading' section is empty."
    exit 1
}
if ($Repository -and $Ref) {
    $text = $text -replace '\]\((?!https?://|#|mailto:)([^)\s]+)\)', "](https://github.com/$Repository/blob/$Ref/`$1)"
}
Set-Content -Encoding utf8 -LiteralPath $OutFile -Value $text
Write-Host "Wrote the '$heading' section of $Changelog to $OutFile."
exit 0
