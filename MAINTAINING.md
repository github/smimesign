# Maintaining smimesign

## Releases

The building/packaging of assets for release is handled by CI jobs. When you are ready to create a release for a new version, simply [create a new release](https://github.com/github/smimesign/releases/new) in the GitHub UI. Name the release `v<MAJOR>.<MINOR>.<PATCH>` and the tag `<MAJOR>.<MINOR>.<PATCH>`. Don't add any description of the release at this point.

Once the release is created, AppVeyor and TravisCI will kick off builds of packages for Windows and macOS respsectively. These are automatically added as assets to your new release. Once these have all been added, update the description of the release to include a list of changes included in the release, including markdown links to the relevant PRs.
