# Contributing to WatchLattice

Thanks for helping. WatchLattice is a suite of small tools that run **alongside**
Microsoft Defender, so the most important rule is that nothing here may make a
machine less safe than it was before.

## Ground rules

Every change must keep these guardrails:

- **User mode only.** No kernel drivers, and nothing that only works as SYSTEM.
- **Never weaken Defender.** Do not disable, hook, impersonate, or reconfigure
  Microsoft Defender or its components.
- **Harmless by default.** Do not modify, quarantine, or delete user files
  unless that is a module's explicitly stated job and its README says so
  loudly.
- **Modest, configurable overhead** for CPU, disk, and memory.
- **Honest documentation.** Each module's README states what it does and,
  just as clearly, what it does not protect against.

Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Getting set up

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).
Windows 11 is the target platform, but the solution builds and tests on Linux
and macOS too.

```bash
git clone https://github.com/notbrianbob/WatchLattice.git
cd WatchLattice
dotnet build -c Release
dotnet test  -c Release
```

Run the hub locally (Ctrl+C to stop):

```bash
dotnet run -c Release --project src/WatchLattice.Hub
```

## Making a change

1. Open an issue first for anything larger than a small fix, so we can agree
   on the approach. New tools use the **New tool proposal** template.
2. Branch from `main` and keep each pull request focused on one thing.
3. Add or update tests. Shared code is tested in `tests/WatchLattice.Common.Tests`,
   each tool in `tests/WatchLattice.<Tool>.Tests`.
4. Update the relevant README(s), including the Tools table in the top-level
   README when you add or change a tool.
5. Make sure `dotnet build` and `dotnet test` pass. CI runs both on Windows and
   Linux, and CodeQL scans every pull request.

## Adding a new tool

Tools are modules that the hub runs. Follow
[docs/adding-a-tool.md](docs/adding-a-tool.md); it explains the module
contract, configuration, and testing.

## Code style

- Match the surrounding code: nullable enabled, file-scoped namespaces,
  `sealed` classes by default, XML doc comments on public types.
- Prefer clarity over cleverness. This code is read by people deciding whether
  to trust it.
- Shared code goes in `WatchLattice.Common` only once a second tool needs it.

## Commit messages

Use a short imperative subject line ("Add canary watcher module"), a blank
line, then a body explaining why the change is needed.

## Code of conduct

Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
