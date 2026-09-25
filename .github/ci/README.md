# Test CI configuration

The `.github/workflows/test.yml` workflow is intentionally self-contained.

## Required repository settings

No repository secrets, variables, or environments are required.

The workflow uses the automatically-created `GITHUB_TOKEN` with:

```yaml
permissions:
  contents: read
```

It runs on `push`, `pull_request`, and `workflow_dispatch`.

## Optional secrets

The following repository Actions secrets are optional. A fork with none of
them configured still runs unit tests, race tests, Linux NAT/NAT66 host-network
tests, Windows Wintun/WFP host-network tests, and build tests. The public
awl-tester e2e is supplemental and is skipped unless that platform has a
stable CI identity configured.

| Secret | Purpose |
| --- | --- |
| `CONFIG_AWL_LINUX` | Complete `config_awl.json` for a stable Linux CI peer identity |
| `CONFIG_AWL_MACOS` | Complete `config_awl.json` for a stable macOS CI peer identity |
| `CONFIG_AWL_WINDOWS` | Complete `config_awl.json` for a stable Windows CI peer identity |
| `CONFIG_LIBRESPEED` | Optional complete LibreSpeed `--local-json` server list override |

If a platform `CONFIG_AWL_*` secret is absent, the public awl-tester e2e for
that platform is skipped with a GitHub Actions notice. Core deterministic
coverage still runs.

If `CONFIG_LIBRESPEED` is absent and external e2e is enabled, CI uses
`.github/ci/librespeed.json`, which contains the public direct endpoint and
the AWL overlay endpoint.

## Public tester

The self-contained e2e helper connects to the public AWL test peer:

```text
name:    awl-tester
peer ID: 12D3KooWJMUjt9b5T1umzgzjLv5yG2ViuuF4qjmN65tsRXZGS1p8
mesh IP: 10.66.0.2
```

The public tester only knows pre-authorized stable CI peers. Therefore public
mesh, overlay speed-test, and external full-tunnel checks require the relevant
platform `CONFIG_AWL_*` secret.

To enable the public e2e for a platform, provide its stable `CONFIG_AWL_*`
secret and ensure that peer has been added on `awl-tester`. To enable the
full-tunnel subsection as well, grant that peer `Allow as exit node` on
`awl-tester`.

This optional external test is supplemental. Deterministic gateway coverage is
provided by the repository's Linux NAT66 and Windows Wintun/WFP host-network
tests and the family-neutral gateway data-plane tests.
