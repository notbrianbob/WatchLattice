# Supply chain

How a WatchLattice release is built, what goes into it, and how to check
that the copy you downloaded is the one CI built. For threats to an
installed copy, see the [threat model](threat-model.md).

## What a release is built from

- **Source.** A tag `vX.Y.Z` on `main` starts the
  [release workflow](../.github/workflows/release.yml) on a fresh
  GitHub-hosted Windows runner. Nothing is built on a personal machine.
- **Dependencies.** NuGet packages are pinned to exact versions in the
  project files and come only from nuget.org. The release is self-contained,
  so it bundles the .NET runtime installed by `actions/setup-dotnet` at the
  version in [global.json](../global.json).
- **Build steps.** Every GitHub Action in every workflow is pinned to a full
  commit SHA, with the version in a comment (for example
  `actions/checkout@3d3c42e… # v7.0.1`). A tag that someone moves can't
  change what a build runs. Dependabot opens a pull request when an action
  or package has a new version; majors of the .NET 10 packages are skipped
  on purpose ([dependabot.yml](../.github/dependabot.yml)).
- **Permissions.** Workflows start from `contents: read`. Only the release
  job may write, and only what it needs: creating the release and signing
  its attestation.

## What a release contains

| Asset | What it is |
|---|---|
| `WatchLattice-<version>-win-x64.zip` | Hub and tray, self-contained, with per-file hashes for the [install integrity check](install-integrity.md). The updater installs this. |
| `WatchLattice-<version>-win-x64.msi` | The same files as a Windows Installer package. |
| `SHA256SUMS.txt` | SHA-256 of the zip and the MSI. The updater checks the zip's line before installing. |
| `WatchLattice-<version>-sbom.cdx.json` | The software bill of materials, described below. |
| `WatchLattice-<version>-winget.zip` | winget manifests for the MSI. |
| Build provenance attestation | Signed by GitHub, for the zip, the MSI and the SBOM. |

## Software bill of materials

The SBOM is a [CycloneDX](https://cyclonedx.org/) 1.7 JSON file. It lists
every third-party component in the release:

- each NuGet package the hub and tray ship, direct or transitive, with its
  version, package URL (`pkg:nuget/...`), license and SHA-512 hash, from
  [packaging/sbom/release.slnf](../packaging/sbom/release.slnf) for
  `win-x64`;
- the .NET runtime the self-contained release bundles (for example
  `Microsoft.NETCore.App.Runtime.win-x64`), read from the published
  runtimeconfig files. Project-level tools can't see this dependency, so
  [Write-Sbom.ps1](../.github/scripts/Write-Sbom.ps1) adds it.

Test projects, demos and build-only tools are not in it, because they are
not shipped. CI writes the same SBOM on every pull request, so a change that
breaks it fails before release.

To check a release against known vulnerabilities, feed the SBOM to any
CycloneDX-aware scanner, for example
`osv-scanner scan --sbom WatchLattice-<version>-sbom.cdx.json` or
`grype sbom:WatchLattice-<version>-sbom.cdx.json`.

## Checking a download

```powershell
# 1. The file is the one GitHub Actions built from this repository's tag:
gh attestation verify WatchLattice-<version>-win-x64.zip --repo notbrianbob/WatchLattice

# 2. It wasn't corrupted on the way (the updater does this itself):
(Get-FileHash WatchLattice-<version>-win-x64.zip -Algorithm SHA256).Hash
# Compare with the zip's line in SHA256SUMS.txt.
```

The attestation also works for the MSI and the SBOM. It shows which workflow
run, commit and tag produced the file.

## Scorecard

The [OpenSSF Scorecard](https://github.com/ossf/scorecard) workflow scores the
repository's practices every week and on every push to `main`. The score is
public on [scorecard.dev](https://scorecard.dev/viewer/?uri=github.com/notbrianbob/WatchLattice),
it shows as a badge in the README, and each finding is listed under the
repository's code scanning alerts. Checks that are expected to score low for
now, and why:

- **Signed-Releases.** The binaries are not Authenticode-signed until
  [code signing](code-signing.md) is set up. Scorecard also looks for
  signature files among the release assets, and doesn't count GitHub's
  attestation.
- **Code-Review** and **Contributors.** WatchLattice has one maintainer, so
  most changes are merged without a second person's review. Every change
  still goes through a pull request with CI.
- **Branch-Protection.** Scorecard can't read branch protection settings
  with the default token. The result depends on the repository's settings.

**Fuzzing.** For C#, Scorecard's fuzzing check looks for property-based
tests written with FsCheck. The [fuzz tests](fuzzing.md) include a set driven
by FsCheck, beside a larger set with its own input generator that Scorecard
does not recognize. Neither is coverage-guided fuzzing of the kind OSS-Fuzz
runs, and the fuzzing page says so. FsCheck is a test-only dependency: it is
pinned like the other packages and is not in the release or its SBOM.

The [OpenSSF Best Practices](https://www.bestpractices.dev/) badge is a
separate, self-assessed questionnaire. Draft answers, with what is not met
yet, are in [openssf-best-practices.md](openssf-best-practices.md).

## Honest limits

- The SBOM describes what was packaged, not what is installed on your PC
  now. The install integrity check covers that.
- Pinning protects against a moved tag, not against a compromised action at
  the commit that was pinned. Dependabot updates are reviewed like any
  other change.
- None of this proves the source code is free of bugs. That is what CI's
  tests, the [fuzz tests](fuzzing.md), CodeQL, the
  [detection checks](../demos/detection-checks.md) and the
  [threat model](threat-model.md) are for.
