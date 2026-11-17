# Security policy

WatchLattice is security software, so we hold it to a higher bar than most
projects: a bug here can weaken the machine it is meant to protect.

## Supported versions

WatchLattice is pre-1.0. Only the latest commit on `main` receives security
fixes. Please reproduce on `main` before reporting.

| Version | Supported |
|---------|-----------|
| `main`  | Yes       |
| Anything older | No |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/notbrianbob/WatchLattice/security/advisories/new)
(the repository's **Security** tab → **Report a vulnerability**). Include:

- the affected module (or the hub) and the commit you tested,
- what an attacker can do, and what access they need first,
- steps or a proof of concept to reproduce it, and
- any suggested fix.

## What to expect

WatchLattice is maintained by a small team, so these are targets, not guarantees:

- **Acknowledgement** within 7 days.
- **Assessment** (confirmed or not, and a severity) within 14 days.
- **A fix or mitigation** for confirmed high-severity issues as quickly as we
  can, normally within 30 days, followed by a published advisory that credits
  you unless you prefer otherwise.

Please give us a reasonable chance to ship a fix before disclosing publicly.
We will not pursue legal action against good-faith research that follows this
policy, avoids harming other people's data or systems, and does not degrade
service for others.

## What counts as a vulnerability

[docs/threat-model.md](docs/threat-model.md) lists the threats already
considered, how each is handled, and the limits we accept. Something it
marks as mitigated that turns out not to be is exactly the kind of report we
want.

In scope:

- Anything that lets WatchLattice be used to **weaken** a machine: for example,
  causing it to disable, interfere with, or mislead Microsoft Defender, or to
  modify or delete user files.
- Privilege escalation through the hub when it runs as a Windows service (for
  example, through its configuration, log paths, or file handling).
- Loading or executing code that was not compiled into the hub.
- Resource exhaustion that defeats the documented throttling.

Out of scope:

- The documented limits in each module's README. For example, the decoy
  module detecting nothing is by design, not a vulnerability.
- Malware that does not react to a module's signals. That is a limit of
  deception, not a bug.
- Issues that require an attacker who already has administrator rights on the
  machine.
