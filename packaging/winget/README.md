# winget manifests

Templates for publishing WatchLattice's MSI to the
[Windows Package Manager](https://learn.microsoft.com/windows/package-manager/)
community repository as `notbrianbob.WatchLattice`, in the multi-file
manifest format (schema 1.10.0):

| File | Holds |
|---|---|
| `notbrianbob.WatchLattice.yaml` | the version manifest |
| `notbrianbob.WatchLattice.installer.yaml` | the MSI: URL, SHA-256, ProductCode, the MSI's fixed UpgradeCode, and the .NET 8 Desktop Runtime dependency |
| `notbrianbob.WatchLattice.locale.en-US.yaml` | name, publisher, description, license and links |

[`.github/scripts/Write-WingetManifest.ps1`](../../.github/scripts/Write-WingetManifest.ps1)
fills in the `{{...}}` values for a release (the ProductCode comes from the
built MSI, since each build gets a new one) and drops the `##` template
notes. The release workflow renders them for every tag, checks them with
`winget validate`, and attaches them to the GitHub release as
`WatchLattice-<version>-winget.zip`. CI renders and validates them for a
test MSI on every pull request.

Nothing is submitted to winget automatically. See
[publishing to winget](../../docs/releasing.md#publishing-to-winget).

The `UpgradeCode` here must match [`Package.wxs`](../msi/Package.wxs); a
test checks it.
