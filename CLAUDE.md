# Notes for Claude

## Language
- Everything on GitHub is English: code, comments, commit messages, issues, pull requests, workflows.
- Only user documentation (README, guides) exists additionally in German (`README.de.md`); keep both in sync.

## Building and testing
- `dotnet build NetworkOverview.slnx -c Release` (the WinForms app only builds on Windows / in CI).
- `dotnet run --project tests/NetworkOverview.Tests -c Release` — runs on Linux too, no NuGet needed.
- The Windows build is verified in GitHub Actions (`build.yml`); check it with `gh run list` / `gh run view`.

## Releases (the owner asked Claude to trigger releases)
1. Make sure `main` is green in the Build workflow.
2. Choose the next version (semantic versioning `MAJOR.MINOR.PATCH`). Versions below 1.0 are published as pre-releases.
3. Start the `Release` workflow on `main` with the version; it runs the tests, creates the tag `vX.Y.Z`
   and the release. (Pushing tags and creating refs is blocked for Claude sessions, dispatching works.)
   ```
   gh api -X POST repos/Schimmelreiter/network-overview/actions/workflows/release.yml/dispatches -f ref=main -f 'inputs[version]=X.Y.Z'
   ```
   The owner can alternatively push a tag `vX.Y.Z` or use Actions -> Release -> Run workflow.
4. Watch the run (`gh run list --workflow release.yml`) until the release has all assets:
   self-contained and framework-dependent executables for win-x64 and win-arm64 plus `SHA256SUMS.txt`.
5. Running the workflow again for an existing version rebuilds and replaces its assets.
6. Changes reach `main` only through pull requests (create and merge them via the REST API, `gh pr create` needs GraphQL).
