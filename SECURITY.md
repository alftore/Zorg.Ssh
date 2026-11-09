# Security policy

## Supported versions

Only the latest release on nuget.org gets security fixes. Today that's `0.1.0-preview.3`. A fix ships as a new version, not as a patch to an old one.

Zorg.Ssh has had internal reviews and tests, not an external security audit or a penetration test. [docs/security.md](docs/security.md) says what has and hasn't been checked.

**The server isn't meant for the public internet, or for users you don't trust.** A report that depends on exposing it that way is still welcome, but the advice in [docs/server.md](docs/server.md#where-to-run-it) stays.

## Reporting a vulnerability

Report it privately through the repository's **Security** tab, using **Report a vulnerability**, or go straight to [the form](https://github.com/alftore/Zorg.Ssh/security/advisories/new). Don't open a public issue.

Please include the affected version, a way to reproduce it, and the impact you expect. A packet capture or a small hostile peer helps most. Remove passwords, private keys and host names you don't want to share.

Expect a first answer within 7 days. Confirmed problems are fixed in a new release and published as a GitHub Security Advisory, with a CVE when one is warranted. You'll be credited unless you'd rather not be.

## How releases are protected

From 0.1.0, releases go through `.github/workflows/release.yml`:

- Nobody pushes to `main` directly, administrators included. Every change arrives through a pull request with signed commits and passing checks on Windows, Linux, Native AOT and the interop suite.
- A release runs only from a `v*` tag on a commit that's on `main`, and it waits for approval in the `nuget` environment.
- Packages are published with NuGet trusted publishing. There's no long-lived API key: each release gets a key that lasts one hour.
- The job that publishes doesn't run repository code. The job that builds has no access to publishing credentials.
- Every GitHub Action is pinned to a full commit SHA. Dependabot proposes updates after a 7-day cooldown.

`0.1.0-preview.3` was uploaded by hand, before this workflow existed, so it has no attestation.

## Verifying a package

Each release from the workflow has a build provenance attestation for the packages it built. To check one, download the `packages` artifact from the release's workflow run and run:

```
gh attestation verify Zorg.Ssh.<version>.nupkg --repo alftore/Zorg.Ssh
```

This doesn't work on a `.nupkg` downloaded from nuget.org. nuget.org adds a repository signature to every package, so the file's digest no longer matches the attestation. Check those with `dotnet nuget verify` instead.
