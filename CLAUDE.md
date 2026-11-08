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
2. Choose the next version (semantic versioning, `vMAJOR.MINOR.PATCH`). Versions below 1.0 are published as pre-releases.
3. Tag `main` and push the tag:
   ```
   git fetch origin main
   git tag vX.Y.Z origin/main
   git push origin vX.Y.Z
   ```
4. Watch the `Release` workflow (`gh run list --workflow release.yml`) until the release has all assets:
   self-contained and framework-dependent executables for win-x64 and win-arm64 plus `SHA256SUMS.txt`.
5. To rebuild an existing tag, run the `Release` workflow manually with input `tag`.
