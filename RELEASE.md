# Release Process

This document describes the process for `cosmos-bsn-contracts` releases.

## Major / Minor Releases

* A release is initiated by creating a release branch `release-a.b` marking the major/minor release.
* Before beginning a release branch, check that dependencies have been pulled up to date:
  * Protobuf references and generation
    * `cd packages/proto/; cd babylon; git fetch; git pull --rebase; cd ../..; git add babylon; git commit -m "pull in latest babylon"`
    * `cd ../..; cargo run-script gen-proto; git add packages/proto; git commit -m "update gen proto"`
    * Then build and run tests to ensure the new proto is working.
    * `cargo build; cargo test`
    * Adjust `packages/apis` after the proto changes, if needed, and adapt / fix tests until they pass.
  * Go code (optional)
    * `cd datagen; go list -u -m -mod=readonly -json all | go-mod-outdated -update -direct -style=markdown`
    * Also, make sure the replaced babylon tag / commit in `go.mod` is up-to-date / correct.
* Update the version in `Cargo.toml` and `Cargo.lock` to the new version.
  * `./scripts/set_version.sh a.b.c`
* Generate the changelog for the upcoming new release version:
  * `./scripts/update_changelog.sh -u va.b.c`
* Push changes to the release branch.
  * `git push --set-upstream origin release-a.b`
* Create a PR for the release branch.
* Once the PR passes CI and is approved, merge it.
* After updating the `main` branch with the new merged release branch, create a tag for the release.
  * `git tag va.b.c -m "Release va.b.c"`
  * `git push --tags`
* Monitor CI for the proper release creation after pushing the release tag. Adjust / repeat as needed.
