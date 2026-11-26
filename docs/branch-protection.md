# Protecting `main`

`main` is what releases are tagged from, so nothing should reach it without
a pull request and green CI, and its history should never be rewritten.
GitHub enforces that with a **ruleset**. The settings are kept in this
repository as [.github/rulesets/protect-main.json](../.github/rulesets/protect-main.json)
so they can be reviewed and re-applied. The file is a record: GitHub does
not read it by itself, and a repository administrator has to import it.

## What the ruleset does

| Rule | Effect |
|---|---|
| Restrict deletions | `main` can't be deleted. |
| Block force pushes | Commits on `main` can't be rewritten or dropped. |
| Require a pull request | Nothing is pushed straight to `main`, by anyone. Open review threads must be resolved before merging. |
| Require status checks | A pull request merges only after CI's five jobs pass: build and test on Windows and Linux, the installer, the MSI, and the changelog check. |
| No bypass list | The rules apply to administrators too. |

What it leaves alone:

- **Tags.** The ruleset targets the default branch only, so pushing a
  release tag `vX.Y.Z` works as before ([cutting a release](releasing.md)).
- **Approvals.** The required number of approving reviews is 0. WatchLattice
  has one maintainer, and GitHub does not let an author approve their own
  pull request, so requiring one would block every merge. Raise it to 1 when
  there is a second maintainer.
- **CodeQL, the demos and the nightly fuzz run.** They still run and still
  show on each pull request where they apply. They are not required,
  because the demos only run when modules change and a required check that
  never starts would block the merge.

## Applying it

1. Open the repository's **Settings**, then **Rules**, then **Rulesets**.
2. Choose **New ruleset**, then **Import a ruleset**, and pick
   `.github/rulesets/protect-main.json` from a checkout.
3. Check that **Enforcement status** is **Active** and that the target is
   the default branch, then **Create**.
4. Open any pull request and confirm the five checks are listed as
   required. If GitHub shows one as "Expected" and it never starts, its
   name in the ruleset no longer matches the job name in
   [ci.yml](../.github/workflows/ci.yml); fix the name in both places.

To change a rule later, change it in Settings and update the JSON file in
the same pull request (the ruleset page has an **Export** option).

## What this does for the Scorecard

The [Scorecard](supply-chain.md#scorecard)'s Branch-Protection check gives
its first points for blocking force pushes and deletion, and more for
required status checks and pull requests. Its higher tiers ask for at least
one approving review from someone other than the author, which a
one-maintainer project can't meet honestly, so expect a partial score. The
Code-Review check stays low for the same reason.

## Honest limits

- A ruleset protects the branch on GitHub. It does not protect a
  maintainer's account; that is what two-factor authentication is for.
- A repository administrator can still edit or disable the ruleset.
  GitHub records that in the repository's audit trail, but nothing here
  prevents it.
