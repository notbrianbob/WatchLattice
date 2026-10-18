# Code signing

Release binaries and the MSI are Authenticode-signed through
[SignPath](https://signpath.io), using the free
[SignPath Foundation](https://signpath.org) program for open-source projects.
A signature tells Windows (and SmartScreen) who published a file and that it
has not changed since, and lets the in-hub updater refuse a release that is
not from the same publisher as the copy you installed.

Until the steps below are done, releases are built **unsigned**, exactly as
v0.1.0 was. The release workflow logs a notice saying so and carries on.

## What gets signed

The release workflow ([`.github/workflows/release.yml`](../.github/workflows/release.yml))
publishes the hub and tray, then, when signing is configured:

1. uploads the staged release folder (`Hub/`, `Tray/`, `LICENSE`, `README.md`)
   as a short-lived GitHub Actions artifact;
2. submits it to SignPath, which signs the files listed in
   [`.signpath/artifact-configuration.xml`](../.signpath/artifact-configuration.xml):
   `ScanAlways.Protection.Service.exe`/`.dll`, `ScanAlways.Tray.exe`/`.dll` and
   every `WatchLattice.*.dll`. Microsoft's DLLs are already signed by Microsoft
   and pass through unchanged;
3. checks with `Get-AuthenticodeSignature` that every `.exe` and `.dll` has a
   valid signature and that all of ours share one publisher, and fails the
   release otherwise;
4. zips the signed files and builds the MSI from them;
5. submits the MSI in a second request, which signs the MSI file itself
   using [`.signpath/msi-artifact-configuration.xml`](../.signpath/msi-artifact-configuration.xml),
   and checks it is validly signed by the same publisher as the hub;
6. writes `SHA256SUMS.txt` from the zip and the signed MSI, so the checksums
   and the provenance attestation cover the signed files.

Once the signing secrets exist, a release that cannot be signed **fails**
rather than shipping unsigned.

## How the updater uses signatures

Before swapping any file, `--apply-update` checks every `.exe` and `.dll` in
the downloaded package with `WinVerifyTrust` (including certificate
revocation), using the installed `ScanAlways.Protection.Service.exe` as the
reference:

| Installed copy | Package | Result |
|---|---|---|
| unsigned (v0.1.0 and any release before signing) | unsigned | installed, as before |
| unsigned | signed | installed; later updates must stay signed by that publisher |
| signed by publisher P | every file validly signed, ours by P | installed |
| signed by P | any unsigned file, or ours signed by someone else | refused, nothing changed |
| either | any file with a broken or revoked signature | refused, nothing changed |

So upgrading from unsigned v0.1.0 to the first signed release works, and from
then on an update cannot quietly drop or change the signature. The check is a
guard on top of the SHA-256 check, which still runs first.

Honest limits:

- Under the SignPath Foundation program the certificate is issued to
  *SignPath Foundation*, which signs many open-source projects. Matching the
  publisher therefore proves the files went through SignPath's reviewed
  signing process, not that they came from this repository specifically.
  The build provenance attestation is what ties a zip to this repository's
  workflow (`gh attestation verify`); the updater does not check it.
- Only `.exe` and `.dll` files carry signatures. Configuration and `.json`
  files in the package are covered by the SHA-256 check only.
- Certificate revocation is checked online. If Windows cannot reach the
  revocation servers, the signature counts as invalid and the update is
  refused; retry when the connection is back.

## Setting it up (maintainer, one time)

1. **Apply to the SignPath Foundation open-source program** at
   <https://signpath.org/apply> for `github.com/notbrianbob/WatchLattice`.
   The program needs a public repository with an OSI license (MIT), releases
   built on GitHub-hosted runners (they are), and a page that names the
   signing setup; this file and the README cover that.
2. **After approval, set up the SignPath project** in the SignPath web app:
   - Project slug `WatchLattice` (or set the repository variable
     `SIGNPATH_PROJECT_SLUG` to whatever you chose).
   - Add the GitHub.com trusted build system to the project.
   - Create the default artifact configuration from
     [`.signpath/artifact-configuration.xml`](../.signpath/artifact-configuration.xml).
   - Create a second artifact configuration with the slug `msi` from
     [`.signpath/msi-artifact-configuration.xml`](../.signpath/msi-artifact-configuration.xml)
     (or set the repository variable `SIGNPATH_MSI_ARTIFACT_CONFIGURATION_SLUG`
     to the slug you chose). The MSI goes through the same signing policy, so
     each release makes two signing requests to approve.
   - Signing policy slug `release-signing` (or set the repository variable
     `SIGNPATH_SIGNING_POLICY_SLUG`). The Foundation's policy may require you
     to approve each signing request in SignPath; the workflow waits for it
     (up to 10 minutes).
   - Create an API token for a CI user that may submit requests to that
     policy.
3. **Add two repository secrets** under *Settings → Secrets and variables →
   Actions*:

   | Secret | Value |
   |---|---|
   | `SIGNPATH_API_TOKEN` | the CI user's API token |
   | `SIGNPATH_ORGANIZATION_ID` | your SignPath organization ID (shown in the SignPath web app) |

4. Push the next release tag as usual ([releasing.md](releasing.md)). The
   *Verify signatures* step of the release run lists each binary and its
   signer.

## Checking a release by hand

```powershell
Get-AuthenticodeSignature 'C:\Program Files\WatchLattice\Hub\ScanAlways.Protection.Service.exe' | Format-List Status, SignerCertificate
```

`Status` should be `Valid`. SmartScreen reputation builds per certificate
over time, so the first signed releases may still show a warning for a while.
