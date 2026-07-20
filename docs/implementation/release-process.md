# Release notes policy (pre-alpha)

## Purpose

Keep release publication deterministic and auditable by requiring one repository-owned release notes template for each pre-alpha tag.

## First pre-alpha tag policy

- First public pre-alpha tag: `v0.1.0-alpha.1`.
- Canonical template path: `.github/release-notes/v0.1.0-alpha.1.md`.
- Release workflow source of truth: `.github/workflows/release.yml` sets `RELEASE_NOTES_TEMPLATE` and passes it to GoReleaser via `--release-notes`.
- Release publication must fail if the configured template file is missing.

## Authoring requirements

Before publishing `v0.1.0-alpha.1`, update the template with final values:

1. Pin the exact catalog snapshot/digest in the `Catalog Version` section.
2. Copy schema artifact digest values from `checksums.txt` into `Schema Digest Set`.
3. Keep `Known Limitations` and `Support Boundary` aligned with current handoff and roadmap constraints.
4. Do not add unsupported product claims or production support language.

## Future tag convention

- Add one new release notes template file per new public tag.
- Update `RELEASE_NOTES_TEMPLATE` in `.github/workflows/release.yml` to the new file path in the same change that introduces the tag/release.
- Preserve prior tag templates unchanged as immutable historical publication records.
