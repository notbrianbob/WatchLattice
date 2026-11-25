# OpenSSF Best Practices badge: draft answers

The [OpenSSF Best Practices badge](https://www.bestpractices.dev/) is a
self-assessment: the maintainer answers each criterion with *Met*, *Unmet* or
*N/A* and gives a link or a sentence as evidence. This page holds draft
answers for the **passing** level, written against the criteria list as it
stood on 2026-11-25. The form itself is the authority; if a question there
isn't on this page, it was added later.

The maintainer submits the form at <https://www.bestpractices.dev/en/projects/new>
(sign in with GitHub, pick the repository). Each answer below is the text to
paste into that criterion's justification box. Answers marked **Check
first** depend on something only the maintainer can confirm.

Nothing here is submitted yet, and the project does not hold the badge.

## Summary

- 67 criteria at the passing level: 43 MUST, 10 SHOULD, 14 SUGGESTED.
- Drafted as Met or N/A: every MUST, provided the **Check first** items hold.
- Drafted as Unmet: three SUGGESTED criteria (`test_most`, `warnings_strict`,
  `dynamic_analysis_enable_assertions`). SUGGESTED criteria don't block the badge.

Things the badge does not ask at this level, but which a reader should know:
releases are not Authenticode-signed yet ([code signing](code-signing.md)),
the project has one maintainer, so changes are not reviewed by a second
person, and the repository is young. The silver level asks about some of
these; this page does not claim it.

## Check first

| Criterion | What to confirm |
|---|---|
| `vulnerability_report_private` | That **Private vulnerability reporting** is switched on under Settings > Advanced Security (called *Code security* on some accounts), so the link in SECURITY.md works. |
| `report_responses`, `enhancement_responses` | That issues opened by other people in the last 2 to 12 months were answered. With none opened, both are met. |
| `vulnerability_report_response` | That no vulnerability report in the last 6 months waited more than 14 days for a first reply. With none received, answer N/A. |
| `static_analysis_fixed` | That the Security tab shows no open CodeQL alert of medium or higher severity. |
| `know_secure_design`, `know_common_errors` | These are statements about what the primary developer knows. Only answer Met if the draft text is true for you. |

## Project details

| Field | Answer |
|---|---|
| Name | WatchLattice |
| Description | An experimental, open-source Windows security toolkit that complements Microsoft Defender with deception-based defenses, ransomware tripwires and continuous security-health monitoring. A supplement to a real anti-malware product, not a replacement. |
| Project URL | <https://github.com/notbrianbob/WatchLattice> |
| Repository URL | <https://github.com/notbrianbob/WatchLattice> |
| Programming languages | C#, PowerShell |
| License | MIT |
| CPE | Leave empty (none assigned). |

## Basics

| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| `description_good` | MUST | Met | The README opens with what the software does and what it is not (a supplement to Microsoft Defender, not a replacement): <https://github.com/notbrianbob/WatchLattice#readme> |
| `interact` | MUST | Met | The README covers installing and updating; CONTRIBUTING.md covers feedback and contributions; issues use templates for bugs, features and new tools: <https://github.com/notbrianbob/WatchLattice/blob/main/CONTRIBUTING.md> |
| `contribution` | MUST | Met | Issue first for larger changes, branch from main, pull request with tests, CI on Windows and Linux: <https://github.com/notbrianbob/WatchLattice/blob/main/CONTRIBUTING.md#making-a-change> |
| `contribution_requirements` | SHOULD | Met | Ground rules (user mode only, never weaken Defender, harmless by default, honest documentation) and code style: <https://github.com/notbrianbob/WatchLattice/blob/main/CONTRIBUTING.md#ground-rules> |
| `floss_license` | MUST | Met | MIT. |
| `floss_license_osi` | SUGGESTED | Met | MIT is OSI-approved. |
| `license_location` | MUST | Met | <https://github.com/notbrianbob/WatchLattice/blob/main/LICENSE> |
| `documentation_basics` | MUST | Met | README (install, run, configure), a README per module, and the docs folder: <https://github.com/notbrianbob/WatchLattice/tree/main/docs> |
| `documentation_interface` | MUST | Met | Every setting is documented in a table in its module's README; the hub's command-line options, the alert format and the Event Log IDs are documented: <https://github.com/notbrianbob/WatchLattice/blob/main/docs/event-log.md> |
| `sites_https` | MUST | Met | The repository, releases and documentation are on github.com, HTTPS only. |
| `discussion` | MUST | Met | GitHub Issues: searchable, each with its own URL, open to anyone with a GitHub account, no proprietary client needed. |
| `english` | SHOULD | Met | Documentation is in English and issues are accepted in English. |
| `maintained` | MUST | Met | Regular commits and releases; see the commit history and CHANGELOG.md. |

## Change control

| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| `repo_public` | MUST | Met | <https://github.com/notbrianbob/WatchLattice> |
| `repo_track` | MUST | Met | Git, on GitHub. |
| `repo_interim` | MUST | Met | Every change lands on main through a pull request between releases; releases are tags on main. |
| `repo_distributed` | SUGGESTED | Met | Git. |
| `version_unique` | MUST | Met | Each release has its own version, set from its tag by the release workflow. |
| `version_semver` | SUGGESTED | Met | Semantic Versioning; stated at the top of CHANGELOG.md. |
| `version_tags` | SUGGESTED | Met | Each release is a git tag `vX.Y.Z`. |
| `release_notes` | MUST | Met | CHANGELOG.md has a human-written section per release, which the release workflow publishes as the GitHub release's notes: <https://github.com/notbrianbob/WatchLattice/blob/main/CHANGELOG.md> |
| `release_notes_vulns` | MUST | N/A | No release has fixed a vulnerability that had a CVE or similar public identifier. Security fixes found by the project itself are listed under a **Security** heading in the release's notes. |

## Reporting

| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| `report_process` | MUST | Met | GitHub Issues with a bug report template: <https://github.com/notbrianbob/WatchLattice/issues/new/choose> |
| `report_tracker` | SHOULD | Met | GitHub Issues. |
| `report_responses` | MUST | Met (**check first**) | Issues are answered by the maintainer. |
| `enhancement_responses` | SHOULD | Met (**check first**) | Feature requests and new tool proposals have their own templates and are answered by the maintainer. |
| `report_archive` | MUST | Met | <https://github.com/notbrianbob/WatchLattice/issues?q=is%3Aissue> |
| `vulnerability_report_process` | MUST | Met | <https://github.com/notbrianbob/WatchLattice/blob/main/SECURITY.md> |
| `vulnerability_report_private` | MUST | Met (**check first**) | GitHub private vulnerability reporting, linked from SECURITY.md and from the issue chooser: <https://github.com/notbrianbob/WatchLattice/security/advisories/new> |
| `vulnerability_report_response` | MUST | N/A (**check first**) | No vulnerability reports were received in the last 6 months. SECURITY.md commits to an acknowledgement within 7 days. |

## Quality

| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| `build` | MUST | Met | `dotnet build -c Release` builds everything from source. |
| `build_common_tools` | SUGGESTED | Met | The .NET SDK (MSBuild, NuGet). |
| `build_floss_tools` | SHOULD | Met | The .NET SDK is open source (MIT). The MSI is built with the WiX Toolset, also open source. |
| `test` | MUST | Met | xUnit test projects under `tests/`, over 1,100 tests, MIT-licensed tooling; documented in CONTRIBUTING.md. |
| `test_invocation` | SHOULD | Met | `dotnet test -c Release`, the standard command for .NET. |
| `test_most` | SUGGESTED | Unmet | Statement coverage is not measured, so no figure can be claimed. Every module has its own test project, and the readers of untrusted input also have fuzz tests. |
| `test_continuous_integration` | SUGGESTED | Met | GitHub Actions builds and tests every pull request and every push to main on Windows and Linux, and installs, upgrades and uninstalls the packaged release on Windows: <https://github.com/notbrianbob/WatchLattice/actions/workflows/ci.yml> |
| `test_policy` | MUST | Met | CONTRIBUTING.md, *Making a change*, step 3: add or update tests; code that reads untrusted input also gets a fuzz test. |
| `tests_are_added` | MUST | Met | Recent pull requests add tests with the change. For example, each defect the fuzz tests found has its own regression test. |
| `tests_documented_added` | SUGGESTED | Met | The pull request template has a checkbox *New behavior has tests*: <https://github.com/notbrianbob/WatchLattice/blob/main/.github/pull_request_template.md> |
| `warnings` | MUST | Met | The C# compiler's warnings, nullable reference type analysis (enabled in every project) and the .NET SDK's built-in analyzers run on every build. CodeQL runs the `security-and-quality` query suite. |
| `warnings_fixed` | MUST | Met | The Release build has no warnings; CodeQL findings are fixed or dismissed with a reason. |
| `warnings_strict` | SUGGESTED | Unmet | Warnings are not treated as errors, and the analyzers run at their default level, not the strictest. |

## Security

| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| `know_secure_design` | MUST | Met (**check first**) | The project documents its own threat model with STRIDE at each trust boundary (least privilege for the tray, no code loaded from outside the release, protected install folder, input from lower trust treated as data): <https://github.com/notbrianbob/WatchLattice/blob/main/docs/threat-model.md> |
| `know_common_errors` | MUST | Met (**check first**) | The threat model and the fuzz test findings cover the error classes that apply to this kind of software (link following by a privileged service, path traversal in archives, untrusted input parsing, secrets in logs, injection into exported text) and how each is mitigated: <https://github.com/notbrianbob/WatchLattice/blob/main/docs/fuzzing.md> |
| `crypto_published` | MUST | Met | Only SHA-256 (file and download hashes) and TLS (downloads), both through the .NET runtime and Windows. No home-made cryptography. |
| `crypto_call` | SHOULD | Met | The software calls `System.Security.Cryptography` and the platform's TLS; it implements no cryptography itself. |
| `crypto_floss` | MUST | Met | .NET's cryptography API is open source (MIT). |
| `crypto_keylength` | MUST | N/A | The software creates and stores no keys. TLS parameters are the operating system's. |
| `crypto_working` | MUST | Met | No MD5, SHA-1, DES, RC4 or other broken algorithm is used; hashes are SHA-256. |
| `crypto_weaknesses` | SHOULD | Met | As above. |
| `crypto_pfs` | SHOULD | N/A | The software implements no key agreement; TLS is negotiated by Windows. |
| `crypto_password_storage` | MUST | N/A | The software stores no passwords and authenticates no users. |
| `crypto_random` | MUST | Met | The only security-relevant random values (canary file contents) come from `System.Security.Cryptography.RandomNumberGenerator`. No keys or nonces are generated. |
| `delivery_mitm` | MUST | Met | Releases are downloaded over HTTPS from GitHub Releases; the updater accepts only HTTPS addresses on GitHub hosts and checks the SHA-256 in `SHA256SUMS.txt`; each release has a signed build provenance attestation: <https://github.com/notbrianbob/WatchLattice/blob/main/docs/supply-chain.md> |
| `delivery_unsigned` | MUST | Met | Checksums are only ever fetched over HTTPS, never HTTP. |
| `vulnerabilities_fixed_60_days` | MUST | Met | There are no publicly known unpatched vulnerabilities. Dependabot reports vulnerable dependencies. |
| `vulnerabilities_critical_fixed` | SHOULD | Met | SECURITY.md commits to fixing confirmed high-severity issues quickly, normally within 30 days. |
| `no_leaked_credentials` | MUST | Met | The repository holds no credentials. Signing credentials, once set up, will be GitHub Actions secrets. |

## Analysis

| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| `static_analysis` | MUST | Met | CodeQL (C#, `security-and-quality`) on every pull request, every push to main and weekly: <https://github.com/notbrianbob/WatchLattice/actions/workflows/codeql.yml> |
| `static_analysis_common_vulnerabilities` | SUGGESTED | Met | CodeQL's security queries look for common vulnerability classes in C#. |
| `static_analysis_fixed` | MUST | Met (**check first**) | There are no open CodeQL alerts of medium or higher severity. |
| `static_analysis_often` | SUGGESTED | Met | On every pull request and push, and weekly. |
| `dynamic_analysis` | SUGGESTED | Met | Fuzz and property-based tests (a seeded generator of the project's own, and FsCheck) give every reader of untrusted input generated inputs on each pull request, and at a larger scale with a random seed every night. They are not coverage-guided: <https://github.com/notbrianbob/WatchLattice/blob/main/docs/fuzzing.md> |
| `dynamic_analysis_unsafe` | SUGGESTED | N/A | C# is memory-safe, and the project uses no `unsafe` code of its own. |
| `dynamic_analysis_enable_assertions` | SUGGESTED | Unmet | Tests and fuzz tests run against Release builds. The code reports broken invariants with exceptions, which are active in every build, and does not use debug-only assertions. |
| `dynamic_analysis_fixed` | MUST | Met | Every defect the fuzz tests found was fixed in the pull request that added them, each with a regression test: <https://github.com/notbrianbob/WatchLattice/blob/main/docs/fuzzing.md#what-it-has-found> |

## After submitting

- Add the badge to the README beside the Scorecard badge. The form gives the
  Markdown once the project has an ID.
- Scorecard's *CII-Best-Practices* check reads the badge from that ID on its
  next weekly run.
- Come back to the Unmet rows: measuring coverage (`coverlet`) and building
  with warnings as errors would turn two of them.
