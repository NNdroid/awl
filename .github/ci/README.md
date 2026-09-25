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
tests, Windows Wintun/WFP host-network tests, build tests, and public mesh /
LibreSpeed e2e coverage.

| Secret | Purpose |
| --- | --- |
| `CONFIG_AWL_LINUX` | Complete `config_awl.json` for a stable Linux CI peer identity |
| `CONFIG_AWL_MACOS` | Complete `config_awl.json` for a stable macOS CI peer identity |
| `CONFIG_AWL_WINDOWS` | Complete `config_awl.json` for a stable Windows CI peer identity |
| `CONFIG_LIBRESPEED` | Optional complete LibreSpeed `--local-json` server list override |

If a platform `CONFIG_AWL_*` secret is absent, CI writes `{}` and AWL
creates an ephemeral identity for that run.

If `CONFIG_LIBRESPEED` is absent, CI uses
`.github/ci/librespeed.json`, which contains the public direct endpoint and
the AWL overlay endpoint.

## Public tester

The self-contained e2e helper connects to the public AWL test peer:

```text
name:    awl-tester
peer ID: 12D3KooWJMUjt9b5T1umzgzjLv5yG2ViuuF4qjmN65tsRXZGS1p8
mesh IP: 10.66.0.2
```

Ordinary mesh connectivity and the overlay speed test do not require a stable
CI identity.

The external full-tunnel exit-node subsection additionally requires
`awl-tester` to grant that CI peer exit-node permission. Ephemeral identities
normally do not have that grant, so this subsection is skipped with a GitHub
Actions notice instead of failing the workflow.

To enable the external exit-node subsection, provide the relevant stable
`CONFIG_AWL_*` secret and grant its peer ID `Allow as exit node` on
`awl-tester`.

This optional external test is supplemental. Deterministic gateway coverage is
provided by the repository's Linux NAT66 and Windows Wintun/WFP host-network
tests and the family-neutral gateway data-plane tests.
