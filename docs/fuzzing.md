# Fuzz tests

WatchLattice's hub runs as LocalSystem and reads files, registry values and
command lines that a standard user, another program or a web server wrote.
The fuzz tests in [tests/WatchLattice.Fuzz.Tests](../tests/WatchLattice.Fuzz.Tests)
feed those readers many thousands of generated inputs and check that each
one either reads the input or refuses it in the way its callers expect.

They are ordinary xUnit tests. `dotnet test` runs them with everything else,
on Windows and Linux, on every pull request. A [scheduled workflow](../.github/workflows/fuzz.yml)
runs them every night with a new random seed and many more inputs.

For how WatchLattice itself could be attacked, see the
[threat model](threat-model.md).

## What is fuzzed

| Input | Who can write it | Test file |
|---|---|---|
| The hosts file, and the proxy settings stored in the registry | Administrators (hosts); any program running as the user (proxy) | `HostsProxyFuzzTests.cs` |
| Browser profiles: Chromium `Preferences`, `Secure Preferences`, `Local State`, extension manifests and locale files; Firefox `profiles.ini` and `extensions.json`; extension policy values | Any program running as the user; extension authors | `BrowserExtensionFuzzTests.cs` |
| Process command lines and process-creation events from the Security log | Any program (it chooses its own command line) | `ScriptHostFuzzTests.cs` |
| Autostart entries: paths and commands in services, scheduled tasks (XML and the logged form), COM class IDs, Run keys, and the stored inventory | Any program running as the user, for per-user entries; administrators for the rest | `PersistenceFuzzTests.cs` |
| Update metadata: release JSON from GitHub, `SHA256SUMS.txt`, the install manifest, the package's zip entry names, `runtimeconfig.json`, version text | Whoever controls the release, or the network path to it | `UpdaterFuzzTests.cs` |
| Settings (`appsettings.json`), approvals and approval tokens, the alert feed and other state files, exports (CSV and *Export all data*), name and secret hiding, Defender and firewall status output | Administrators (settings); the tray user (tokens, review file); every source above, for text that ends up in an alert or an export | `CommonFuzzTests.cs` |
| All of the above again, with inputs from FsCheck | | `ArbitraryInputTests.cs` |

`FoundByFuzzingTests.cs` holds one plain test for each defect the fuzz tests
found, with the smallest input that showed it. Those keep each defect fixed
whatever inputs later runs happen to generate.

## How it works

There are two sources of inputs, written apart so that one can find what the
other's habits miss.

- **The harness** ([Harness/Fuzzer.cs](../tests/WatchLattice.Fuzz.Tests/Harness/Fuzzer.cs)
  and `FuzzRandom.cs`). Each test starts from a real sample of its format
  (an actual `Preferences` file, task definition or release) and changes it:
  it cuts, repeats and swaps pieces, inserts the format's own keywords, and
  mixes in text that parsers often get wrong, such as half of a surrogate
  pair, digits from other scripts, right-to-left marks, very long runs and
  deep nesting. It also builds inputs from nothing but those pieces.
- **[FsCheck](https://fscheck.github.io/FsCheck/)**, a property-based testing
  library ([Harness/Arbitrary.cs](../tests/WatchLattice.Fuzz.Tests/Harness/Arbitrary.cs)).
  It knows nothing about the formats beyond a list of words, grows its
  inputs from small to large, and reduces a failing input by itself.

Neither is guided by code coverage. See [honest limits](#honest-limits).

Each test states a property that must hold for every input. The usual ones:

- **Reads or refuses.** The reader returns, or throws only the exception its
  callers handle (`JsonException`, `InvalidDataException`, `XmlException`).
  Any other exception would stop a module, or the settings editor, in the hub.
- **Reads back the same.** What a writer produces, the reader returns
  unchanged: CSV exports, settings, approvals, checksums, versions.
- **Stays inside.** A path taken from a manifest or a zip stays in the
  install or staging folder. A path from a profile is never opened on another
  computer. Text from the PC can't add a heading, a table column or the end
  of a code block to an export.
- **Fails closed.** When hiding a secret or a name can't finish, the whole
  text is hidden. A name that must be hidden is never left standing as a word.

A test fails with the seed, the command to run it again, and the input
reduced to the smallest one that still fails, written as a C# string.

## Running them

```bash
# With everything else, the same inputs every time (seed 0):
dotnet test -c Release

# Only the fuzz tests, 20 times as many inputs, another seed:
WATCHLATTICE_FUZZ_SEED=12345 WATCHLATTICE_FUZZ_SCALE=20 dotnet test tests/WatchLattice.Fuzz.Tests -c Release
```

```powershell
$env:WATCHLATTICE_FUZZ_SEED = 12345; $env:WATCHLATTICE_FUZZ_SCALE = 20
dotnet test tests/WatchLattice.Fuzz.Tests -c Release
```

| Variable | Default | Meaning |
|---|---|---|
| `WATCHLATTICE_FUZZ_SEED` | `0` | Which inputs are generated. The same seed gives the same inputs on every machine. |
| `WATCHLATTICE_FUZZ_SCALE` | `1` | Multiplies the number of inputs of every test, up to 1000. |

At the default scale the 68 fuzz tests try about 200,000 inputs and take
about ten seconds, so pull requests stay quick and a failure there is always
reproducible. The nightly workflow picks a random seed, prints it, and runs
at scale 50 on Windows and Linux. To run a failed night again, start the
**Fuzz** workflow by hand with that seed, or set the two variables locally.

No test waits on a timer or asserts how long something took. The readers
that can take long on hostile input have their own limits instead (a nesting
limit for task XML, a one-second limit and bounded patterns for the command
line redactor), and the tests check that the limit is what stops them.

## What it has found

The first run, in November 2026, found the defects below. All were fixed in
the same pull request, and each has a test in `FoundByFuzzingTests.cs` that
fails on the old code. None was seen being used, and none let anyone run
code or gain rights. Most would stop one module from reporting until the
input changed, which for a monitoring tool means missed alerts.

**A module could be stopped by something a standard user's program can write**

- Browser extension watchdog: an extension named `__MSG__`, or a profile file
  holding a broken `\u` escape or bytes that are not UTF-8, raised an
  exception that ended the scan of every browser for every user. The module
  said it could not read the profiles, and compared nothing until the file
  changed.
- Persistence auditor: a service or task whose program was a single character
  (`a`, `.`, `%`) crashed path resolution, which the auditor uses to grade
  every change. The hub restarted the module and raised *Module failed*, and
  the same entry stopped it again. Two autostart entries whose names differ only by case (a
  Startup folder can be made case-sensitive) made the stored inventory look
  damaged.
- Persistence verification: task and service definitions with half of a
  surrogate pair, a repeated name or a broken escape threw exceptions the
  callers did not expect. Task XML nested thousands of levels deep kept a
  CPU core busy for minutes; it is now refused beyond 64 levels.
- Script host audit: one pattern of the command line redactor took time that
  grew with the square of a URL's length. It is now bounded, has a one-second
  limit, and hides the whole command line if the limit is reached.

**The hub could be sent to another computer**

- A Chromium extension's `path` in `Preferences`, or a Firefox profile path
  in `profiles.ini`, could be a network path (`\\server\share\…`). The hub,
  as LocalSystem, would have opened it, which contacts that server and can
  offer it the computer's own sign-in. Such paths are now reported and never
  opened.

**Something was graded or matched wrongly**

- A service in a folder users can write to was graded as an ordinary change
  when its path was written as `x.exe. -k …` or as a quoted `\SystemRoot\…`.
  Names containing `:` away from the drive letter were looked up as files.
- A hosts entry written with another kind of dot (`windowsupdate.com．`) or
  with an invisible character did not match the watched domain.
- An approval for an entry whose name ends in a space, or holds half of a
  surrogate pair, never matched its entry, so the alert came back.
- An approval token or extension ID with a line break after it was accepted,
  and so was an *Open file location* path with a trailing line break or a C1
  control character.

**Something that should be hidden was not**

- The command line redactor left part of a secret visible when only part of
  the value was quoted (`password=""secret`, `-Password "abc"secret`) or a
  quote was never closed.
- *Export all data* left the first half of a user name when a long activity
  line was clipped in the middle of it, and a whole name when it followed an
  escape such as `\t` in a setting.

**The updater or the editor failed with the wrong error**

- Version text with digits from other scripts, a checksum of the right length
  that is not hexadecimal, release metadata or a `runtimeconfig.json` of the
  wrong shape, and an install manifest path containing a control character
  each raised an exception the update check did not handle, instead of
  "this release can't be read". Addresses are now only parsed when they
  start with `https://`.
- A settings file with one setting written twice (also when differing only by
  case, or written both as `"A:B"` and as `B` inside `A`) failed part of the
  way through the editor's checks. It is now refused when read, with the
  setting's name. The hub itself already refused to start with such a file.
- The Defender and firewall status readers threw on text that is not valid
  Unicode and on dates outside the calendar.

## Honest limits

- **Passing proves little.** The tests find defects; they can't show there
  are none left. Inputs are short (mostly under a few kilobytes), and neither
  source is guided by code coverage the way libFuzzer, AFL or OSS-Fuzz are.
  A coverage-guided fuzzer for .NET would be a worthwhile addition.
- **Only the reading is fuzzed, not Windows.** The registry, the Event Log,
  the Task Scheduler and WMI are not called. The tests give the readers the
  text those sources return. A defect in how a module calls Windows needs the
  [hand checks](windows-checks.md) and the [detection checks](../demos/detection-checks.md).
- **The tray's window code is not covered**, because it only builds on
  Windows. Everything it reads goes through the shared readers that are.
- **A property is only as good as its statement.** "Never throws" says
  nothing about whether the answer is right. Where a second, independent
  reading exists (a round trip, or a simple reference parser), the tests use
  it; elsewhere the ordinary unit tests carry that weight.

## Adding a reader

When a module starts reading a new kind of input that someone else can
write:

1. Give it a test in the matching `*FuzzTests.cs` file: a real sample, the
   format's keywords, and a property from the list above. Use
   `Fuzzer.RunText`, `Fuzzer.RunBytes` or `Fuzzer.Run`.
2. Add it to the matching test in `ArbitraryInputTests.cs`, with its
   keywords in the word list.
3. Run a few seeds at a higher scale before opening the pull request.
4. If it finds something, fix it and add the reduced input to
   `FoundByFuzzingTests.cs`.
