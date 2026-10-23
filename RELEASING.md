# Releasing sweetcookie

Sweetcookie ships a Go module and GitHub source releases, not a CLI binary,
npm package, macOS app, or Homebrew formula.

`.github/workflows/release.yml` calls the shared source archetype at `@v1`.
It checks `VERSION`, the dated changelog section, protected-main ancestry and
green push CI on the exact commit. It runs the library tests with Go 1.27.3,
then two independent runners verify commit-bound source tar/zip archives, exact
release notes, the asset inventory and `SHA256SUMS` before GitHub publication.

Update `VERSION` and finalize the matching section of `CHANGELOG.md` for a
future release; retain a new Unreleased section. Merge to main, wait for push
CI, and run the no-publish rehearsal:

```sh
gh workflow run release.yml --ref main -f version=0.0.2 -F dry_run=true
```

Use the version being prepared for a future release. Main dry runs validate that
exact commit even if the selected version already has a tag; no tag or release
is changed, and the Go proxy is not warmed.

An explicitly authorized publication starts by pushing an SSH-signed annotated
`vX.Y.Z` tag at the tested commit, signed by the release key in
`.github/release-allowed-signers`. A dispatch with `dry_run=false` can resume the
same signed tag. Never move a version tag or replace public artifacts.
After the GitHub Release is verified, the workflow warms `proxy.golang.org` and
uses a fresh module cache with `sum.golang.org` to check the exact version,
module checksum and source commit. A successful GitHub publication alone does
not imply the proxy check passed; inspect the Go proxy job too.

No release secrets or local publication fallback are needed. Verify consumers
with `go get github.com/steipete/sweetcookie@vX.Y.Z` after publication. Major
versions 2 and later require the matching `/vN` module path.
